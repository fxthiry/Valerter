# Design

## Context

Voir proposal.md (Why) pour la motivation. État actuel du code, vérifié :

- `Config::validate()` (`src/config/types.rs`) borne `count`/`window` du throttle de règle mais ignore `defaults.throttle`, que `RuleEngine` utilise pourtant comme throttle par défaut (`src/engine.rs`). `Throttler::new` (`src/throttle.rs`) se contente d'un `tracing::warn!` pour `count == 0` ou `window == 0`.
- `throttle.key` n'est vérifié que par `validate_jinja_template` (compilation). Au rendu, `Throttler::render_key` bascule sur la clé `<règle>:error` en cas d'erreur.
- Les `body_template` webhook et Telegram ne sont que compilés à l'instanciation (`validate_body_template` locaux) ; l'email compile son template de corps mais ne fait de rendu d'essai que pour `subject_template`. Ces contrôles ne sont pas exécutés par `Config::validate`.
- `complete-validate-mode`, implémenté avant ce change, introduit un pré-vol partagé (`run_preflight`) exécuté au démarrage et par `--validate` après `Config::validate()` et `compile()` : il construit tous les notifiers (résolution des `${VAR}`, lecture et contrôle de `body_template_file`, compilation des templates de notifier, adresses, en-têtes, méthode, `chat_ids`…), vérifie les destinations et `email_body_html`, et journalise chaque erreur sous `Notifier configuration error` avec le préfixe `invalid notifier '<nom>': `. Tout contrôle ajouté dans un `from_config` (ou `create_notifier`) est donc automatiquement couvert par `--validate`.
- `validate_template_render` (`src/config/validation.rs`) rend avec le contexte sentinelle `TruthyChainable` (objet de type séquence) et rejette toute erreur. Vérifié avec minijinja 2.24 (version du `Cargo.lock`) : `| int`, `| float`, `| round`, `| abs`, `| split`, `a + 1` échouent tous sur la sentinelle (« cannot convert sequence to integer »…), alors que `| lower`, `| tojson`, `| e`, `| default`, `~` passent. Les filtres inconnus donnent `unknown filter`. Un `{{ a.io/b }}` donne « tried to use / operator on unsupported types sequence and sequence ».
- `slash_field_hint` propose `{{ fields["a/b"] }}` pour un nom de premier niveau, or aucune variable `fields` n'est injectée dans le contexte (`inject_context` n'ajoute que `rule_name` et `vl_source`).
- Les en-têtes des sources VictoriaLogs sont passés tels quels à `RequestBuilder::header` (`src/tail.rs`) : un nom invalide fait échouer chaque requête au moment de l'envoi, d'où une boucle de reconnexion.
- `validate_url` accepte sans contrôle toute valeur contenant `${`. Pour les sources, la résolution a lieu avant `validate()`, donc seule une valeur résolue contenant `${` échappe au contrôle. Pour webhook et Mattermost, l'URL résolue à l'instanciation n'est jamais revérifiée.
- `parse_mode` Telegram est transmis tel quel.
- `load_directory_generic` désérialise chaque fichier `.d/` en `HashMap<String, D>` et renvoie une `HashMap` ; `merge_rules` itère cette `HashMap` : l'ordre des règles issues de `rules.d/` varie d'une exécution à l'autre. Les erreurs de validation sur templates et notifiers suivent aussi l'ordre d'une `HashMap`.
- La collision intra-`.d/` construit `resource_type` par `dir_name.trim_end_matches(".d")`, d'où `duplicate rules name` / `templates` / `notifiers`, contre `rule` / `template` / `notifier` pour les collisions avec le fichier principal.

## Goals / Non-Goals

**Goals:**
- Toute erreur décelable sans événement réel est signalée par `Config::validate()` ou à l'instanciation des notifiers (les deux exécutées par `--validate`), jamais au premier envoi.
- Chaque contrôle n'existe qu'à un seul endroit : aucun contrôle de notifier n'est dupliqué entre `Config::validate()` et la construction des notifiers.
- Supprimer les faux positifs du rendu d'essai plutôt que d'en ajouter en l'étendant à de nouveaux templates.
- Aucun secret (URL, valeur d'en-tête) dans les nouveaux messages d'erreur.

**Non-Goals:**
- Faire construire les notifiers par `--validate` (déjà fait par `complete-validate-mode`) ou ajouter dans `Config::validate()` des contrôles de notifiers que le pré-vol couvre (rendu des `body_template`, `parse_mode`, `body_template_file`, URL résolues).
- Refuser une configuration dont toutes les règles sont désactivées (change `fix-daemon-exit-codes`).
- Exposer une variable `fields` dans le contexte de rendu (ce serait une fonctionnalité de templating, avec risque de collision avec un champ d'événement nommé `fields`).
- Valider les noms d'en-têtes webhook au chargement (déjà validés à l'instanciation) ou le contenu Markdown/HTML produit par les templates Telegram.
- Changer la sémantique du throttling (change `fix-cross-source-throttle-dedup`).

## Decisions

### D1. Rendu d'essai : ne rejeter que les erreurs indépendantes des valeurs
`validate_template_render` classe l'erreur minijinja par `ErrorKind` : `SyntaxError`, `UnknownFilter`, `UnknownTest`, `UnknownFunction`, `UnknownMethod` → rejet. `InvalidOperation` → rejet uniquement si `slash_field_hint(source)` trouve un chemin avec `/` et que le message porte sur l'opérateur `/` (comportement actuel de l'indice conservé). Toute autre erreur → acceptée (le contexte fictif ne permet pas de conclure).
- Alternative écartée : rendre la sentinelle « polymorphe » (nombre et chaîne à la fois). minijinja choisit le comportement selon `ObjectRepr` ; un objet ne peut pas être à la fois séquence (nécessaire pour `for`/`length`, cf. tests du ticket #25), nombre et chaîne. Le filtrage par type d'erreur est plus simple et robuste aux évolutions de minijinja.
- Alternative écartée : un second rendu avec un contexte de chaînes vides. Cela double le coût et ne règle pas `| int` sur chaîne vide (erreur aussi).
- Conséquence : `throttle.key`, `subject_template` et les `body_template` passent par cette même fonction, d'où une seule source de vérité.

### D2. Où placer les nouveaux contrôles
- `Config::validate()` : uniquement ce que le pré-vol de `complete-validate-mode` ne couvre pas, c'est-à-dire les sources, les règles et `defaults` : `defaults.throttle` (bornes, syntaxe, rendu de `key`), rendu de `throttle.key` des règles, en-têtes des sources, URL des sources sans exception `${`. Les contrôles existants de notifiers dans `Config::validate()` (URL brute avec exception `${`, `chat_ids` non vide) restent inchangés.
- Instanciation (`from_config` / `create_notifier`), seul emplacement des nouveaux contrôles de notifiers : rendu d'essai des `body_template` webhook et Telegram, rendu d'essai du template de corps email effectivement retenu (fichier, en ligne ou intégré), revérification de l'URL résolue webhook et Mattermost, validation et normalisation de `parse_mode` Telegram. Le pré-vol les exécute au démarrage comme en `--validate` ; ils ne sont pas recopiés dans `Config::validate()`.
- Messages : préfixe existant `invalid notifier '<nom>': ` (`ConfigError::InvalidNotifier`), journalisé sous `Notifier configuration error` par le pré-vol, suivi de `body_template: …`, `body_template render: …`, `parse_mode '…' is not supported (expected HTML, MarkdownV2 or Markdown)`, `url: invalid URL: …` ou `webhook_url: invalid URL: …`.
- Pas de double signalement : `Config::validate()` ne contrôle aucun template de notifier ni `parse_mode`, et le pré-vol ne s'exécute que si `Config::validate()` a réussi ; une URL de notifier littérale invalide est refusée par `Config::validate()` avant toute construction, une URL issue d'une `${VAR}` n'est contrôlée qu'à la construction.
- Le contrôle des sources utilise une variante `validate_resolved_url` (sans exception `${`) ; `validate_url` garde son exception pour les URL de notifiers non encore résolues. Les deux partagent le même cœur (analyse + schéma) et ne répètent jamais l'URL.

### D3. Préfixes d'erreur pour `defaults.throttle`
`ConfigError::ValidationError` avec `defaults.throttle.count must be >= 1 (0 would suppress every alert)`, `defaults.throttle.window must be > 0 (0s disables throttling)`, `defaults.throttle.key: <détail>`, `defaults.throttle.key render: <détail>`. On évite `InvalidTemplate { rule: "defaults" }` qui produirait `invalid template in rule 'defaults'`, trompeur si une règle s'appelle `defaults`. Pour les règles : `InvalidTemplate { rule, message: "throttle.key render: …" }`, cohérent avec l'existant `throttle.key: …`.
Les `tracing::warn!` de `Throttler::new` pour `count == 0`/`window == 0` deviennent inatteignables via la configuration ; ils sont conservés (garde pour un appel programmatique) mais le commentaire est mis à jour.

### D4. En-têtes des sources
Validation après résolution des `${VAR}` : `reqwest::header::HeaderName::from_bytes(nom)` et `HeaderValue::from_str(valeur résolue)`. Messages `victorialogs.<source>.headers: invalid header name '<nom>'` (le nom n'est pas secret) et `victorialogs.<source>.headers: invalid value for header '<nom>'` (valeur jamais répétée). Itération des en-têtes triée par nom pour un ordre d'erreurs stable. Le comportement à l'envoi (remplacement vs duplication) relève de `harden-vl-streaming`.
Le refus d'un nom ou d'une valeur d'en-tête invalide au chargement est porté par ce change ; `harden-vl-streaming` ne conserve à l'envoi qu'une garde défensive (pour un appel programmatique qui contournerait `Config::validate()`), sans spécifier de nouveau ce refus.

### D5. `parse_mode` Telegram
Ensemble fermé `HTML`, `MarkdownV2`, `Markdown` (valeurs documentées de l'API Bot), comparaison insensible à la casse, normalisation vers la forme canonique stockée dans le notifier. Helper unique (`normalize_parse_mode`) appelé par `TelegramNotifier::from_config`, donc exécuté au démarrage et par `--validate` via le pré-vol.
- Alternative écartée : accepter une valeur vide pour envoyer du texte brut (omettre `parse_mode`). Hors périmètre : nécessiterait de rendre le champ optionnel dans la charge utile et d'adapter le template par défaut, qui produit du HTML.

### D6. Ordre déterministe des règles `.d/`
`load_directory_generic` reste inchangé (désérialisation de chaque fichier en `HashMap<String, D>`, fichiers parcourus en ordre de chemin trié, résultat en `HashMap<String, (T, PathBuf)>`). `merge_rules` collecte les entrées issues de `rules.d/` dans un `Vec`, les trie par (chemin de fichier, nom de règle) puis les ajoute après les règles du fichier principal. L'ordre obtenu est stable d'un chargement à l'autre ; dans un même fichier, les règles suivent l'ordre alphabétique de leur nom et non l'ordre de déclaration YAML. `merge_hashmap` (templates, notifiers) est inchangé : leur ordre n'a pas d'effet à l'exécution.
Pour les erreurs de validation, `Config::validate()` itère templates et notifiers par nom trié (collecte des clés + `sort`), sans changer les types publics.
- Alternative écartée : conserver l'ordre de déclaration YAML en réécrivant `load_directory_generic` sur `serde_yaml::Mapping` (ou `IndexMap`). Plus de code et de risques pour un besoin limité à la stabilité de l'ordre ; le nom de règle est déjà unique, donc le tri (chemin, nom) est total.

### D7. Collision au singulier
`load_directory_generic` reçoit un `resource_type` explicite (`rule`, `template`, `notifier`) en plus de `dir_name` (utilisé dans les messages de parsing `rules.d (<chemin>)`). Le format de `ConfigError::DuplicateName` est inchangé.

### D8. Indice pour `/` au premier niveau
Quand le segment gauche n'a pas de préfixe pointé, l'indice devient : `field names containing '/' must use bracket notation on their parent object; a top-level field like 'a/b' has no parent and cannot be referenced directly: rename it in the rule query, e.g. `| rename "a/b" as a_b`, then use `{{ a_b }}` (see docs/configuration.md#fields-with-special-characters)`. Le cas avec préfixe est inchangé.

## Risks / Trade-offs

- [Des configurations en production aujourd'hui acceptées seront refusées au redémarrage après mise à jour du `.deb` (le service redémarre et peut échouer).] → Entrée **Breaking** dans `CHANGELOG.md` et section `MIGRATION.md` listant les nouveaux refus, avec la consigne de lancer `valerter --validate -c <config>` avec le nouveau binaire avant de redémarrer ; chaque message pointe le champ fautif.
- [D1 laisse passer des erreurs réelles de type (ex. `{{ host + 1 }}` sur une chaîne).] → Elles dépendent des valeurs de l'événement, et donc ne sont pas décidables à la validation ; elles restent couvertes par le message de repli (templates) et la clé de repli (throttle). Compromis assumé contre les faux positifs actuels.
- [Le classement par `ErrorKind` dépend de minijinja ; une montée de version pourrait reclasser une erreur.] → Tests unitaires figeant chaque cas (filtre/test/fonction inconnus rejetés ; `int`, `float`, `round`, `abs`, `split`, `+` acceptés ; indice `/` conservé).
- [Normaliser `parse_mode` change la valeur transmise pour une casse non canonique (`html` → `HTML`).] → L'API Bot traite déjà ces valeurs comme équivalentes ou les rejette ; la normalisation ne peut que corriger. Signalé dans le CHANGELOG.
- [Rendu d'essai du template email intégré à chaque démarrage.] → Coût négligeable (un rendu au démarrage).
- [Les erreurs de templates de notifier ne sont signalées qu'après la réussite de `Config::validate()` : une configuration qui cumule une erreur de règle et une erreur de `body_template` demande deux passes de `--validate`.] → Compromis assumé pour garder un seul emplacement par contrôle ; le pré-vol de `complete-validate-mode` rapporte en une passe toutes les erreurs de notifiers, de destinations et de templates e-mail.
- [Ordre des règles d'un même fichier `.d/` alphabétique plutôt que celui de déclaration.] → L'ordre des règles n'a pas de sémantique à l'exécution (une tâche par couple règle/source) ; seule la stabilité compte (logs, récapitulatif, métriques). Documenté dans `docs/configuration.md`.

## Migration Plan

1. Livrer les contrôles avec leurs tests et la documentation dans une même PR, en version 2.1.0.
2. `MIGRATION.md` : sous-partie « Stricter configuration validation » de la section « Upgrading to 2.1.0 », avec un tableau « ancien comportement → nouveau refus → correction » (`defaults.throttle` à 0, filtres inconnus dans `throttle.key` et `body_template`, `parse_mode`, en-têtes de source, URL résolues), et la commande `valerter --validate` à lancer avant la mise à jour.
3. Rollback : réinstaller la version précédente du `.deb` ; aucune donnée persistée n'est concernée.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`  ← ce change
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (9/11) : suit `complete-validate-mode` et `harden-vl-streaming` (garde défensive des en-têtes).
