# Tasks

## 1. Rendu d'essai sans faux positifs et indice `/` corrigé

- [x] 1.1 Dans `src/config/validation.rs`, faire classer par `ErrorKind` les erreurs de `validate_template_render` (D1) : rejet pour syntaxe, filtre/test/fonction/méthode inconnus et opérateur `/` sur un chemin de champ ; acceptation des autres erreurs d'exécution. Vérifier avec de nouveaux tests unitaires : `{{ status | int }}`, `| float`, `| round`, `| abs`, `| split(',') | first`, `{{ count + 1 }}` acceptés ; `| nosuchfilter`, `is nosuchtest`, `nosuchfunc()` rejetés ; les tests existants (#25, #41) restent verts.
- [x] 1.2 Corriger `slash_field_hint` pour le cas de premier niveau (D8) : plus de `fields[...]`, mention du pipe `rename`. Remplacer le test `slash_field_hint_top_level_key` par un test qui vérifie la présence de `rename` et l'absence de `fields[` ; garder le test du cas avec préfixe.
- [x] 1.3 Mettre à jour `docs/configuration.md` (sections « Fields with special characters » et validation des templates) pour décrire le cas de premier niveau et le fait que les conversions (`int`, `float`…) ne sont plus rejetées à la validation ; vérifier que les exemples du document passent `cargo test` (tests de templates existants) et que la section est cohérente avec le message de l'indice.

## 2. Throttle : `defaults.throttle` et rendu d'essai de la clé

- [x] 2.1 Dans `Config::validate()` (`src/config/types.rs`), valider `defaults.throttle` (D3) : `count >= 1`, `window > 0`, syntaxe et rendu d'essai de `key`, avec les messages préfixés `defaults.throttle.`. Vérifier par des tests dans `src/config/tests.rs` (count 0, window 0s, syntaxe invalide, filtre inconnu, configuration valide).
- [x] 2.2 Ajouter le rendu d'essai de `throttle.key` des règles (activées ou non) avec le message `invalid template in rule '<nom>': throttle.key render: …`. Vérifier par un test avec `{{ host | bad_filter }}` (rejet) et `{{ host }}-{{ status | int }}` (accepté).
- [x] 2.3 Mettre à jour le commentaire des `tracing::warn!` de `Throttler::new` (`src/throttle.rs`) et le test `bad_filter` de `src/throttle.rs` pour qu'il illustre une erreur dépendant de l'événement (`{{ port + 1 }}` avec une chaîne) ; vérifier que `cargo test throttle` passe.
- [x] 2.4 Documenter dans `docs/configuration.md` (sections `defaults` et `throttle`) que `defaults.throttle` suit les mêmes bornes que le throttle de règle et que `throttle.key` est rendu à la validation ; relire que `config/*/config.yaml` et `examples/*` respectent ces bornes (`valerter --validate -c <fichier>` réussit pour chacun, variables d'environnement factices fournies).

## 3. Sources VictoriaLogs : en-têtes et URL résolue

- [x] 3.1 Ajouter dans `src/config/validation.rs` un cœur commun d'analyse d'URL et une variante `validate_resolved_url` sans exception `${` (D2) ; l'utiliser pour `victorialogs.<source>.url`. Vérifier par des tests : URL résolue `ftp://…` rejetée, valeur résolue contenant `${` non valide rejetée, message sans l'URL.
- [x] 3.2 Valider dans `Config::validate()` les noms et valeurs résolues des `headers` de chaque source (D4), en ordre de nom trié. Vérifier par des tests : nom `X Token` rejeté avec `victorialogs.<source>.headers: invalid header name 'X Token'`, valeur contenant `\n` rejetée sans que la valeur apparaisse dans le message, en-tête `Authorization: Bearer …` accepté.
- [x] 3.3 Mettre à jour `docs/configuration.md` (section des sources `victorialogs`) pour mentionner ces contrôles ; vérifier la cohérence avec les messages des tests.

## 4. Notifiers : `body_template`, `parse_mode`, URL résolues

- [x] 4.1 Remplacer les `validate_body_template` locaux de `src/notify/webhook.rs` et `src/notify/telegram.rs` par compilation + `validate_template_render`, avec le message `body_template render: …` à l'instanciation (D2 : aucun contrôle équivalent dans `Config::validate()`). Vérifier par des tests unitaires dans chaque module (filtre inconnu rejeté, `| tojson` / `| e` acceptés) ; adapter les tests existants qui vérifient le préfixe `body_template` ; ajouter dans `tests/integration_validate.rs` un test où `valerter --validate` échoue (code 1, `Notifier configuration error`, `invalid notifier 'wh': body_template render:`) sur un `body_template` webhook avec filtre inconnu, via le pré-vol de `complete-validate-mode`.
- [x] 4.2 Dans `src/notify/email.rs`, ajouter le rendu d'essai du template de corps retenu (fichier, en ligne ou intégré) après sa compilation. Vérifier par des tests : `body_template_file` contenant un filtre inconnu rejeté, template intégré accepté.
- [x] 4.3 Ajouter un helper `normalize_parse_mode` (D5) et l'utiliser dans `TelegramNotifier::from_config` pour stocker la forme canonique. Vérifier par des tests : `html` → `HTML`, `markdownv2` → `MarkdownV2`, `Markdown2` rejeté, défaut `HTML` ; un test wiremock dans `tests/integration_notify.rs` vérifie que `parse_mode: html` produit `"parse_mode":"HTML"` dans la requête envoyée ; un test dans `tests/integration_validate.rs` vérifie que `valerter --validate` échoue (code 1, `invalid notifier 'tg': parse_mode 'Markdown2' is not supported`) sur `parse_mode: Markdown2`.
- [x] 4.4 Revérifier l'URL résolue dans `WebhookNotifier::from_config` (`url`) et dans `NotifierRegistry::create_notifier` pour Mattermost (`webhook_url`), via le cœur commun de 3.1. Vérifier par des tests : variable résolue en `ftp://…/SECRET` ou `not a url` rejetée avec `url: invalid URL:` / `webhook_url: invalid URL:` et message sans `SECRET`.
- [x] 4.5 Mettre à jour `docs/notifiers.md` (valeurs acceptées de `parse_mode`, rendu d'essai des `body_template` à l'instanciation, donc au démarrage et par `--validate`, contrôle des URL résolues) ; vérifier que les exemples de `body_template` du document passent le nouveau rendu d'essai (test qui charge chaque exemple, ou exécution de `--validate` sur un fichier reprenant ces exemples).

## 5. Chargement multi-fichiers : ordre et collisions

- [x] 5.1 Dans `merge_rules` (D6), trier les entrées issues de `rules.d/` par (chemin de fichier, nom de règle) avant de les ajouter après les règles du fichier principal ; `load_directory_generic` et `merge_hashmap` restent inchangés. Vérifier par un test avec une nouvelle fixture `tests/fixtures/multi-file-order/` (`rules.d/b.yaml` déclarant `z_rule` puis `a_rule`, `rules.d/a.yaml` déclarant `m_rule` : ordre attendu `main_rule`, `m_rule`, `a_rule`, `z_rule`, identique sur plusieurs chargements).
- [x] 5.2 Passer un `resource_type` explicite au singulier (D7) et mettre à jour les tests de collision intra-répertoire (`load_with_intra_directory_collision_fails` et équivalents templates/notifiers) pour vérifier `duplicate rule name` / `duplicate template name` / `duplicate notifier name`.
- [x] 5.3 Itérer templates et notifiers par nom trié dans `Config::validate()` ; vérifier par un test que deux templates invalides `beta` et `alpha` produisent les erreurs dans l'ordre `alpha`, `beta`.
- [x] 5.4 Mettre à jour `docs/configuration.md` (section multi-fichiers) pour documenter l'ordre de chargement des règles (fichier principal, puis entrées `.d/` triées par fichier puis par nom) et le format des messages de collision.

## 6. Changelog, migration et vérification d'ensemble

- [x] 6.1 Ajouter à la section `## [2.1.0]` de `CHANGELOG.md` (la créer si elle n'existe pas) les entrées **Breaking** (nouveaux refus) et **Fixed** (faux positifs du rendu d'essai, indice `/`, ordre des règles, message de collision) ; vérifier que chaque point de proposal.md y figure.
- [x] 6.2 Ajouter à la section « Upgrading to 2.1.0 » de `MIGRATION.md` (la créer si elle n'existe pas) la sous-partie « Stricter configuration validation » (tableau ancien comportement → nouveau refus → correction, consigne `valerter --validate -c /etc/valerter/config.yaml` avec le nouveau binaire avant de redémarrer) ; vérifier que chaque scénario **BREAKING** de proposal.md y a une ligne.
- [x] 6.3 Lancer `cargo fmt --check`, `cargo clippy -- -D warnings` et `cargo test` ; tous doivent passer.
- [x] 6.4 Lancer `valerter --validate -c` sur chaque configuration de `config/` et `examples/` (avec variables d'environnement factices) et vérifier qu'aucune ne régresse.
