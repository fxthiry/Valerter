# Design

## Context

Voir proposal.md (Why). Le change regroupe douze correctifs indépendants, de la documentation, l'alignement des specs et du nettoyage, à livrer dans 2.1.0 (non publiée : aucune compatibilité à préserver avec les préversions 2.1.0, seulement avec 2.0.3). Contraintes : minijinja 2.24 (features `builtins`, `json`, sans `unstable_machinery`), reqwest 0.13, aucune nouvelle dépendance.

État observé qui conditionne les choix :

- `src/config/validation.rs:105-134` : un seul rendu contre la sentinelle `TruthyChainable` (toujours vraie, `ObjectRepr::Seq`, itération vide) ; le rendu s'arrête à la première erreur et toute erreur « acceptée » renvoie `Ok(())`.
- Les filtres intégrés de minijinja sont des fonctions publiques (`minijinja::filters::int`, `split`…, enregistrées dans `defaults.rs` par `Value::from_function`) ; `Value::call(&State, &[Value])` est public ; un filtre ou un test enregistré sous un nom existant remplace l'intégré. Les opérateurs arithmétiques (`value/ops.rs`) ne sont pas surchargeables par un `Object`.
- `src/tail.rs:420-425` journalise l'URL complète ; les erreurs reqwest affichées par `Connection failed` / `Stream read error` (`src/tail.rs` ~507, ~570) incluent aussi l'URL (`for url (...)`, reqwest 0.13 `error.rs:280`), alors que les notifiers utilisent déjà `e.without_url()`.
- `build_metrics_inventory` vit dans `src/main.rs:255` (binaire) : `tests/metrics_snapshot.rs:245-265` ne peut que le recopier.

## Goals / Non-Goals

**Goals:**
- Rendu d'essai sans faux négatif sur les cas du constat, sans faux positif nouveau (seules les erreurs `Unknown*`, `SyntaxError` et l'indice `/` restent refusées).
- Corrections minimales et locales, chacune couverte par un test qui échoue avant le correctif.

**Non-Goals:**
- Analyse statique de l'AST minijinja (exigerait `unstable_machinery`).
- Refonte de l'agrégation de `valerter_vl_source_up` (une tâche en échec met la jauge de toute la source à 0) : documentée seulement.
- Version de `Cargo.toml` et date du CHANGELOG (étape de release).

## Decisions

### D1. Rendu d'essai : deux passes et filtres intégrés enveloppés

Approche retenue, prototypée contre minijinja 2.24 (projet jetable hors dépôt) :

1. **Sentinelle paramétrée par passe.** `TruthyChainable` reçoit un mode `Truthy`/`Falsy` et un drapeau `leaf`.
   - Passe 1 (`Truthy`) : `is_true` vrai ; une sentinelle non-feuille itère **un** élément, lui-même une sentinelle feuille qui itère vide (sans ce drapeau, `{{ a | tojson }}` récursait à l'infini : débordement de pile constaté au prototype).
   - Passe 2 (`Falsy`) : `is_true` faux, itération vide, et les tests `defined`/`undefined` sont remplacés dans l'environnement de validation pour répondre « non défini » sur une sentinelle (`{% if x is defined %}…{% else %}` et `is not defined`).
   - L'erreur de la première passe qui échoue est renvoyée (passe 1 d'abord, messages inchangés).
2. **Filtres intégrés enveloppés.** Dans l'environnement de validation seulement, chaque filtre intégré de minijinja 2.24 (liste de `defaults.rs` : `safe`, `escape`/`e`, `lower`, `upper`, `title`, `capitalize`, `replace`, `length`/`count`, `dictsort`, `items`, `reverse`, `trim`, `join`, `split`, `lines`, `default`/`d`, `round`, `abs`, `int`, `float`, `attr`, `first`, `last`, `min`, `max`, `sort`, `list`, `string`, `bool`, `batch`, `slice`, `sum`, `indent`, `select`, `reject`, `selectattr`, `rejectattr`, `map`, `groupby`, `unique`, `chain`, `zip`, `pprint`, `format`, `tojson`) est réenregistré par une enveloppe `|state, args: Rest<Value>|` qui appelle `Value::from_function(minijinja::filters::<nom>).call(state, &args)`. Si l'appel échoue avec une erreur autre que `Unknown*`/`SyntaxError` **et** qu'un argument est une sentinelle, l'enveloppe renvoie une valeur de substitution : `0` pour `int` et `abs`, `0.0` pour `float` et `round` (l'arithmétique qui suit une conversion, `{{ count | int + 1 }}`, continue), une sentinelle feuille pour les autres (chaînage conservé). Sinon l'erreur d'origine est propagée. Les arguments nommés traversent `Rest<Value>` sans perte (vérifié : `sort(reverse=true)`, `round(2)`).
3. **Garde-fou de mise à jour.** Un test rend, pour chaque nom de la liste (avec ses arguments obligatoires), `{{ x | <nom>(...) }}{{ y | nosuchfilter }}` et exige l'erreur `UnknownFilter` sur `nosuchfilter` : si une montée de minijinja change un comportement, le test casse. valerter n'enregistre aucun filtre propre (vérifié : aucun `add_filter` dans `src/`), l'environnement de validation reste donc fidèle à celui de production.

Résultats du prototype : refusés désormais `{{ status | int }}-{{ host | truncat(10) }}`, `{{ x | float | round(2) }} {{ y | nosuch }}`, `{{ host | split('.') | first }} {{ host | nosuch }}`, un filtre inconnu dans `{% else %}`, `{% if not a %}`, `{% if a is not defined %}`, `{% for i in items %}` et `{% for k, v in m | items %}` ; acceptés `| length`, `| join`, `| default | upper`, `| replace | lower | trim`, `| tojson`, `| dictsort`, `| sum/max/min/sort/unique/reverse/batch`, `namespace` dans une boucle, comparaisons.

Limites restantes, documentées (spec `message-templating` et `docs/configuration.md#template-validation`) :
- une opération arithmétique sur un champ brut (`{{ count + 1 }}`) arrête la passe en cours sans erreur : la suite n'est pas vérifiée dans cette passe. En production, les champs VictoriaLogs sont des chaînes et cette expression échoue aussi : la doc recommande `{{ count | int + 1 }}` ;
- le corps d'un `elif` n'est atteint par aucune passe (la passe 1 prend le `if`, la passe 2 le `else`) ;
- une boucle imbriquée sur l'élément d'une boucle (`{% for y in x %}` dans `{% for x in a %}`) n'itère pas ; un déballage `{% for a, b in x %}` sans `| items` arrête la passe.

Alternatives écartées :
- *Seulement remplacer `int`/`float`/`round`/`abs`* (piste du constat) : laisse les faux négatifs après `split`, `upper`, `items`… (« value is not a string », constaté au prototype) et ne couvre aucune branche.
- *Parcours de l'AST* (`minijinja::machinery`) : feature `unstable_machinery`, API sans garantie de semver.
- *Recherche des noms de filtres par expression régulière dans la source* : fragile (chaînes, commentaires, `is`/`|` dans des littéraux).
- *Rendre la sentinelle numérique pour l'arithmétique* : impossible, les opérateurs ne consultent que les représentations internes (`ops.rs`).

### D2. Indice `/` : division entre identifiants simples

`slash_field_hint` parcourt les correspondances de `SLASH_FIELD_REGEX` (`captures_iter`) et ne retient que celles dont la partie gauche est un chemin pointé ou dont la partie droite contient `.`, `-` ou `/`. `{{ total/count }}` n'a plus d'indice, donc l'erreur `/ operator` est acceptée comme toute erreur arithmétique. Issue #41 (chemins pointés) inchangée. Conséquence : un champ de premier niveau `io/username` (sans `.`, `-` ni `/` supplémentaire) n'est plus détecté ; c'est indiscernable syntaxiquement d'une division, et ce cas est bien plus rare que les annotations pointées. Le test `slash_field_hint_top_level_key_suggests_rename` et la doc passent à `io/user-name`.

### D3. Destinations en double

Contrôle dans `Config::validate` (`src/config/types.rs` ~861), calqué sur celui de `vl_sources` (~686) avec un `HashSet` : `rule '<r>': notify.destinations contains duplicate entry '<x>' (each notifier may appear at most once)`. Pas de déduplication silencieuse dans la file : la config est refusée comme pour les sources.

### D4. `${VAR}` en une passe

`resolve_env_vars` (`src/config/env.rs:15-30`) utilise une regex `LazyLock` et `Regex::replace_all` avec une closure qui renvoie la valeur ou note le nom manquant (ordre d'apparition conservé, doublons inclus comme aujourd'hui). La sortie est construite à partir de la valeur d'origine uniquement.

### D5. Secrets dans les logs du streaming

- `debug!(url = %redact_url(&url), query = %self.config.query, ...)` : `redact_url` masque aussi la requête LogsQL (`?query=`), donc la requête est journalisée à part (non secrète).
- Erreurs reqwest : `e.without_url()` avant affichage dans `Connection failed` et `Stream read error`, comme les notifiers.
- Les messages `StreamError::ConnectionFailed(e.to_string())` restants (construction du client, `src/tail.rs:246`) ne contiennent pas d'URL ; ceux de `connect_and_receive` disparaissent avec D14.

### D6. Ordre déterministe

`NotifierRegistry::from_config` itère `notifiers_config` trié par nom ; `WebhookNotifier::from_config` itère `config.headers` trié par nom (premier en-tête invalide = premier alphabétique). Les tests construisent plusieurs `HashMap` dans la même exécution pour faire varier l'ordre d'itération.

### D7. Paquet Debian

- `prerm` `remove|deconfigure` : si `[ -d /run/systemd/system ]`, `systemctl stop valerter 2>/dev/null || true` sans test `is-active`, puis, sur `remove`, `systemctl disable valerter 2>/dev/null || true` (avant la suppression des fichiers).
- `postrm` : `remove` ne garde que `daemon-reload` ; `purge` inchangé. Les appels `systemctl` sont conditionnés à `[ -d /run/systemd/system ]` au lieu de `command -v systemctl` (un conteneur peut avoir le binaire sans gestionnaire actif).
- `postinst` : le bloc systemd (`src` lignes 39-65) est conditionné à `[ -d /run/systemd/system ]`, ce qui supprime la fausse alerte « failed to start » en conteneur/chroot.

Pas de test automatisé possible dans `cargo test` ; vérification `sh -n`, `shellcheck` et revue.

### D8. Sorties fatales et arrêt du runtime

- `main` ne renvoie plus `anyhow::Result` : une fonction `fatal(err: anyhow::Error) -> !` journalise `error!("{err:#}")` puis `std::process::exit(1)`. Elle couvre `config.compile` (`src/main.rs:173`), la construction des runtimes, le preflight de `--validate` (~178-183) et le résultat de `run`.
- Doublons supprimés : `run` ne journalise plus « Metrics recorder failed to initialize » (~369) ni « Engine error » (~442) avant de renvoyer la même erreur ; le message final est journalisé une seule fois par `fatal`. Les messages restent ceux attendus par les specs et `tests/integration_validate.rs:419,445`.
- `let result = runtime.block_on(run(cfg)); runtime.shutdown_timeout(Duration::from_secs(2));` puis traitement de `result` : une résolution DNS bloquée dans le pool bloquant ne retarde plus la sortie au-delà de 2 s. Le chemin `--validate` (runtime `current_thread`) fait de même.

Alternative écartée : garder `main() -> Result` avec un `Termination` personnalisé ; plus indirect et ne règle pas le doublon de logs.

### D9. Corps non-2xx borné

Nouveau module `src/http_body.rs` (`pub(crate)`) : `read_body_prefix(resp, max_bytes, deadline) -> Vec<u8>` qui lit `resp.chunk()` en boucle sous `tokio::time::timeout(deadline, …)`, s'arrête à `max_bytes` (tronqué) ou à l'échéance, et renvoie ce qui a été reçu. `response_error_body` (`src/tail.rs:172`) l'appelle avec 4 Kio / 5 s (512 caractères ≤ 2 Kio d'UTF-8, marge comprise) puis applique `String::from_utf8_lossy` et le traitement actuel. Réutilisé par Telegram (D11).

### D10. `valerter_vl_source_up` et inventaire des métriques

`build_metrics_inventory` déménage de `src/main.rs` vers `src/metrics.rs` (réexporté par `src/lib.rs`) avec ses tests (`src/main.rs:737`). `inventory.sources` devient l'ensemble trié des sources présentes dans `rule_sources` (au moins une règle activée les cible). `tests/metrics_snapshot.rs` appelle cette fonction sur un `RuntimeConfig` réel au lieu de recopier l'inventaire. La sémantique d'agrégation (dernier écrivain, une tâche en panne passe la source à 0) est documentée dans `docs/metrics.md`.

### D11. Repli Telegram

`ChatSendError::Client` devient `Client { status, description: Option<String> }`. Sur un 4xx (≠ 429), le corps est lu seulement pour un 400, via `read_body_prefix` (4 Kio ; la durée est déjà bornée par le timeout total de 10 s du client partagé) puis `serde_json` → champ `description`. Le repli a lieu si `parse_mode` est HTML, statut 400 et `description.to_lowercase().contains("can't parse entities")`. Les tests existants de repli renvoient désormais un corps Telegram réaliste.

### D12. Repli Mattermost

Canal de repli = `self.channel` s'il est défini et différent de `rule_channel`, sinon `None`. Interprétation de la décision utilisateur (« renvoyer d'abord avec le `channel` du notifier s'il existe, sinon sans `channel` ») : **un seul** renvoi, vers le canal du notifier ou à défaut le canal par défaut du webhook ; pas de troisième requête. Avertissement renommé `Mattermost rejected channel override, resending to notifier default` (champs `notifier_name`, `rule_name`, `channel`, `fallback_channel` optionnel, `status`), puisque le texte précédent (« without channel ») deviendrait faux.

### D13. Destination inconnue à l'exécution

On garde la garde défensive (inatteignable après preflight, mais la file est publique dans la lib) et on remplace le compteur ad hoc de `src/notify/queue.rs:233-239` par `record_permanent_failure(&payload, dest_name, "unknown")` : mêmes labels et même ordre que partout, et `valerter_alerts_failed_total` est incrémenté aussi. La supprimer obligerait à retirer `unknown` de la doc et des specs sans gain réel.

### D14. Nettoyage

- `RuleError::{Parse, Template, Queue, Panic}` supprimées (`src/error.rs:84-91`) ; `NoEnabledRules` documentée comme garde défensive. Si `ParseError`/`TemplateError` deviennent inutilisés, le compilateur le signalera et ils seront traités au même moment.
- `TailClient::connect_and_receive` (`src/tail.rs:302-343`) supprimée. Les 22 appels de `tests/integration_streaming.rs` passent par un utilitaire de test qui exécute `stream_with_reconnect` en collectant les lignes jusqu'à la fin de la première connexion (annulation par le gestionnaire de ligne ou délai, sur le modèle de l'utilitaire existant ~l.1009) ; les tests qui vérifiaient un `Err` (4xx, connexion refusée) vérifient la reconnexion (nombre de requêtes reçues, logs ou `valerter_reconnections_total`), ou sont supprimés quand un test `stream_with_reconnect` couvre déjà le cas. `test_timeout_detection` (~l.222) est supprimé (il ne teste aucun délai).
- Tests renommés : `engine_supervision_detects_completion` (`src/engine.rs:1062`) → `engine_run_returns_ok_when_cancelled_before_start` ; `send_partial_success_returns_ok_and_does_not_stop_after_failure` (`src/notify/telegram.rs:962`) → `send_reaches_every_chat` (ou suppression s'il double le test précédent).
- WARN `Webhook body is not valid JSON` : la capture de logs de `src/notify/mattermost.rs:549` (`CapturedLogs`) est reproduite dans `tests/common/logs.rs` (`tracing_subscriber` est une dépendance normale) et `tests/integration_notify.rs:1082` vérifie le WARN et l'absence du corps.

## Risks / Trade-offs

- [Templates acceptés par une préversion 2.1.0 désormais refusés] → C'est l'effet voulu ; 2.1.0 n'est pas publiée et l'entrée « Stricter configuration validation » du CHANGELOG/MIGRATION le couvre déjà, complétée.
- [Une montée de minijinja ajoute un filtre intégré non enveloppé] → Le filtre fonctionne normalement (pas de faux positif) ; au pire il peut arrêter une passe. Le test garde-fou liste les noms ; un commentaire renvoie à `defaults.rs`.
- [La passe 2 voit un faux positif « UnknownFunction » dans une branche morte] → Une branche contenant une fonction inconnue échouera quand elle sera atteinte : la refuser est correct.
- [Coût de validation doublé] → Deux rendus par template au démarrage, négligeable.
- [`{{ io/username }}` de premier niveau n'est plus signalé] → Indiscernable d'une division ; la doc explique le renommage et l'exemple passe à `io/user-name`.
- [`source_count` du log « Metrics initialized to zero » change de sens] → Documenté (sources ciblées).
- [Scripts Debian non testés automatiquement] → `sh -n`, `shellcheck`, et test manuel décrit dans tasks.md sur une machine systemd.

## Migration Plan

Livré dans 2.1.0 avant publication : entrées du CHANGELOG `## [2.1.0] - Unreleased` et de la section « Upgrading to 2.1.0 » de MIGRATION.md corrigées en place (Mattermost, shutdown ~20 s, échappement `${...}`), plus les nouvelles entrées (destinations en double, rendu d'essai plus strict, repli Telegram restreint, `vl_source_up`). Retour arrière : revert du commit, aucune donnée persistée.
