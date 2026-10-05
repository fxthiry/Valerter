# Design

## Context

Voir proposal.md (Why) pour la motivation. État actuel du code (v2.0.3) :

- `run_rule` (`src/engine.rs`) construit un `Arc<Throttler>` à chaque démarrage de tâche (règle, source), y compris lors d'une relance après panic. Chaque `Throttler` possède son propre `moka::sync::Cache<String, Arc<AtomicU32>>` (`src/throttle.rs`), créé avec `time_to_live(window)` (fenêtre fixe ancrée sur l'insertion) et `max_capacity(10_000)`.
- La clé par défaut est déjà `<rule>-<source>:global` ; `rule_name` et `vl_source` sont injectés dans le contexte de rendu de `throttle.key`.
- `ThrottleResetCallback::on_reconnect(rule_name, vl_source)` appelle `Throttler::reset()` (`invalidate_all`). Le trait `ReconnectCallback` (`src/tail.rs`) transmet déjà `vl_source`, prévu « for future use (e.g. selective reset across shared throttle stores) ».
- `RuleSpawnContext` est cloné et conservé dans `handle_to_context` pour la relance après panic.
- Le throttle effectif d'une règle (`rule.throttle` ou `defaults.throttle`) est identique pour toutes ses sources.

## Goals / Non-Goals

**Goals:**
- Un état de throttle par règle partagé par ses tâches, sans verrou global sur le chemin chaud.
- Une remise à zéro après reconnexion qui reste limitée à la source qui se reconnecte.
- Aucun changement de format de configuration ni de métriques.

**Non-Goals:**
- Partage d'état entre règles différentes (une clé identique dans deux règles reste deux compteurs).
- Fenêtre glissante ou configuration de la borne du cache.
- Validation de `defaults.throttle` ou rendu d'essai de `throttle.key` (change `harden-config-validation`).
- Modification de la politique de relance après panic (change `nonblocking-panic-supervision`).

## Decisions

### D1 — Un magasin `ThrottleStore` par règle, une vue `Throttler` par tâche

`src/throttle.rs` est scindé en deux types :
- `ThrottleStore` : enveloppe `Arc` autour du cache moka (TTL = `window`, capacité, `support_invalidation_closures()`), créé une fois par règle activée dans `RuleEngine::spawn_rule_tasks`, avant la boucle sur les sources résolues.
- `Throttler` : vue par tâche contenant `Arc<ThrottleStore>`, `rule_name`, `vl_source`, le template de clé, `max_count` et l'environnement minijinja. `check()` et `render_key()` gardent leur logique actuelle ; seule la provenance du cache change.

Le `ThrottleStore` est ajouté à `RuleSpawnContext` (champ `Arc<ThrottleStore>`), donc cloné avec lui et réutilisé par `run_rule`, y compris à la relance après panic (requirement « Persistance du cache à la relance d'une tâche »). `Throttler::new(config, rule, source)` est conservé (il crée un magasin privé) pour les tests unitaires existants ; un constructeur `Throttler::with_store(store, config, rule, source)` est utilisé par le moteur.

Alternatives écartées :
- *Un cache global unique avec clés préfixées par la règle* : le TTL moka est par cache, or chaque règle a sa propre `window` ; il faudrait une politique `Expiry` par entrée, plus complexe sans bénéfice.
- *Un `HashMap<rule, Arc<Throttler>>` partagé tel quel* : le `Throttler` porte `vl_source` (labels de métriques, clé par défaut, contexte de rendu), qui doit rester propre à chaque tâche.

### D2 — Entrée de cache avec source propriétaire et marqueur de partage

La valeur du cache devient `Arc<ThrottleEntry>` avec `count: AtomicU32`, `owner: Arc<str>` (source qui a créé l'entrée) et `shared: AtomicBool`. Dans `check()`, après `get_with`, si `owner != self.vl_source` et que `shared` est faux, on le passe à vrai (opération atomique sans verrou, une seule écriture par entrée en pratique). `get_with` de moka sérialise déjà l'initialisation concurrente d'une même clé : deux sources ne peuvent pas créer deux compteurs pour la même clé.

`Throttler::reset()` devient sélectif : `invalidate_entries_if(|_, e| e.owner == vl_source && !e.shared)`. Moka garantit qu'une entrée correspondant au prédicat et insérée avant l'appel n'est plus renvoyée par `get` après le retour de l'appel. Une entrée touchée par une seule source est donc supprimée, une entrée partagée est conservée (requirement « Remise à zéro après reconnexion »). Avec la clé par défaut, chaque entrée n'a qu'un seul propriétaire : le comportement actuel est strictement préservé. Le log DEBUG « Throttle cache reset » garde `rule_name` et ajoute `vl_source`.

Alternatives écartées :
- *`invalidate_all` sur le cache partagé* : chaque reconnexion d'une source effacerait le dédoublonnage entretenu par les autres sources et laisserait passer une rafale de doublons, exactement le défaut que le change corrige.
- *Aucune remise à zéro* : régression du comportement FR7 pour la clé par défaut.
- *Ensemble complet des sources contributrices (`Mutex<HashSet>`)* : verrou sur le chemin chaud pour une information dont le reset n'a besoin que sous forme booléenne (« une autre source a contribué »).

### D3 — Borne du cache : 10 000 × nombre de sources

La capacité du `ThrottleStore` vaut `DEFAULT_MAX_CAPACITY * resolved.len()`. Le budget mémoire total reste celui d'aujourd'hui (une instance de 10 000 clés par tâche) et une règle mono-source garde exactement 10 000 clés. `with_capacity` reste disponible pour les tests.

Alternative écartée : *10 000 par règle* — une règle multi-sources avec clé par défaut verrait sa capacité effective divisée par le nombre de sources, régression silencieuse.

### D4 — Inchangés volontairement

- Clé de repli `<rule_name>:error` : désormais commune aux sources de la règle, ce qui est cohérent avec la portée par règle et avec le texte actuel de la spec (« compteur partagé »).
- Labels de métriques : la source de l'événement évalué, comme aujourd'hui.
- Avertissements `count == 0` / `window` nulle : toujours émis à la création de chaque tâche (requirement « Valeurs de count et window au niveau règle » non modifié, pour ne pas chevaucher `harden-config-validation`).

### D5 — Log INFO pour une clé partagée entre sources

Le changement de portée des clés personnalisées est silencieux par nature. Pour le rendre visible sans bloquer le démarrage, `RuleEngine::spawn_rule_tasks` émet, une fois par règle activée, avant la boucle sur les sources résolues, un log INFO lorsque les trois conditions suivantes sont réunies :
- la règle a au moins deux sources effectives (`resolve_sources(...).len() >= 2`) ;
- son throttle effectif (`rule.throttle` ou `defaults.throttle`) a une `key` personnalisée (la clé par défaut contient déjà la source) ;
- la clé ne référence pas `vl_source`.

La détection est statique : la clé est compilée dans un `minijinja::Environment` et l'on teste l'appartenance de `vl_source` à `Template::undeclared_variables(false)` (API disponible sans feature supplémentaire dans minijinja 2.x). Aucun rendu d'essai n'est fait. Une fonction pure `throttle::key_references_vl_source(key_template) -> Option<bool>` porte cette logique, et une fonction pure de décision dans `src/engine.rs` combine les trois conditions, ce qui permet de tester sans capturer les logs (aucune dépendance de test ajoutée) ; si la clé ne compile pas, elle renvoie `None` et aucun log n'est émis (l'erreur de compilation relève de la validation de configuration, non de ce change).

Le log porte les champs `rule_name`, `source_count` et `throttle_key` (le template de clé, qui n'est pas un secret) et un message du type « Throttle key does not reference vl_source: its counter is shared across the rule's sources; add {{ vl_source }} to the key to isolate them ». Le niveau INFO (et non WARN) est retenu parce que le partage est le comportement documenté et souvent voulu (`{{ rule_name }}`). Émis dans `spawn_rule_tasks`, il n'est pas répété à la relance d'une tâche après panic.

Alternatives écartées :
- *Recherche de la sous-chaîne `vl_source`* : faux positifs (commentaire, chaîne littérale) et faux négatifs (espacement, filtres) ; l'analyse minijinja est exacte pour les références de variables.
- *Log par tâche* : répétition inutile, N lignes pour un même constat.

### D6 — Documentation

- docs/architecture.md : « sliding window » → « fixed window » (ancrée sur le premier événement de la clé), portée par règle du cache, reset sélectif à la reconnexion ; mise à jour du commentaire du schéma des tâches.
- docs/configuration.md (section Throttling) : le compteur d'une clé est partagé par toutes les sources de la règle ; ajouter `{{ vl_source }}` pour un compteur par source ; la clé par défaut est déjà par source.
- examples/multi-source/README.md : remplacer « its own throttle bucket » par la description exacte (bucket isolé par la clé par défaut).
- MIGRATION.md : ajouter à la section « Upgrading to 2.1.0 » (la créer si elle n'existe pas) le changement de portée des clés personnalisées et le log INFO qui le signale.
- CHANGELOG.md : ajouter à la section `## [2.1.0]` (la créer si elle n'existe pas) une entrée `Fixed` (dédoublonnage entre sources désormais effectif) avec la mention du changement de comportement, et une entrée `Added` pour le log INFO.

## Risks / Trade-offs

- [Règles multi-sources à clé personnalisée sans `{{ vl_source }}` qui envoient moins d'alertes après mise à jour] → Changement documenté dans MIGRATION.md/CHANGELOG.md avec la correction en une ligne, et signalé au démarrage par le log INFO de D5 ; c'est la sémantique déjà promise par la documentation.
- [Log INFO émis pour une règle dont le partage est voulu (`{{ rule_name }}`)] → Une seule ligne par règle au démarrage, au niveau INFO ; coût négligeable.
- [Course entre le passage de `shared` à vrai et l'évaluation paresseuse du prédicat d'invalidation par moka] → Au pire une entrée devenue partagée au moment même du reset est supprimée ; effet borné à une alerte supplémentaire, identique au comportement actuel du reset.
- [`support_invalidation_closures()` ajoute un léger coût d'enregistrement des prédicats dans moka] → Les reconnexions sont rares ; l'impact sur `check()` est négligeable. Vérifier que les tests de performance restent dans les mêmes ordres de grandeur.
- [Une source très bavarde remplit le cache partagé et évince les clés des autres sources] → Capacité proportionnelle au nombre de sources (D3) ; comportement LRU inchangé par ailleurs.
- [Le cache survit désormais à une relance après panic] → Comportement souhaité (pas de rafale de doublons après un panic) ; couvert par un test dédié.

## Migration Plan

1. Version : 2.1.0. Aucun changement de configuration requis ; l'état de throttle est en mémoire, rien à migrer.
2. Avant la mise à jour, les opérateurs identifient les règles multi-sources (après mise à jour, le log INFO de D5 les désigne) ayant une `throttle.key` personnalisée sans `{{ vl_source }}` et y ajoutent `{{ vl_source }}` s'ils veulent garder un compteur par source.
3. Retour arrière : réinstaller la version précédente ; aucune donnée persistante n'est concernée.

## Open Questions

_Aucune._ Le change est livré dans la version 2.1.0.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`  ← ce change
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (4/11) : séquentiel avec `nonblocking-panic-supervision` (mêmes `supervise_tasks` / `RuleSpawnContext`).
