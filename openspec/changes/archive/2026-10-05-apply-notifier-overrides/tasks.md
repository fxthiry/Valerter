# Tasks

## 1. Webhook : `${VAR}` dans body_template

- [x] 1.1 Dans `WebhookNotifier::from_config` (`src/notify/webhook.rs`), appeler `resolve_env_vars` sur la source du `body_template` avant `validate_body_template`, avec le préfixe d'erreur `body_template:` ; tests unitaires (`#[serial]`) : variable définie substituée, variable absente → erreur contenant `body_template` et le nom de la variable, `Debug` du notifier ne contient pas la valeur résolue
- [x] 1.2 Tests wiremock dans `tests/integration_notify.rs` : `"routing_key": "${ROUTING_KEY}"` avec `ROUTING_KEY=abc123` envoie `"routing_key": "abc123"` ; un `body` d'alerte contenant `${HOME}` inséré via `{{ body }}` est envoyé littéralement (pas de substitution sur le rendu) ; mettre à jour le test existant qui verrouillait l'envoi littéral d'un `${ROUTING_KEY}` présent dans le template
- [x] 1.3 Réécrire l'exemple PagerDuty de `docs/notifiers.md` et `config/config.example.yaml` avec `"routing_key": "${PAGERDUTY_ROUTING_KEY}"` (à la place de la valeur à remplacer laissée par `harden-notifier-payloads`) ; documenter la résolution `${VAR}` dans `body_template` (source seulement, échec au démarrage si non définie, mise en garde sur les valeurs contenant `{{`, `{%` ou `"`) ; étendre le test qui rend les exemples de la doc pour couvrir l'exemple PagerDuty avec la variable définie

## 2. Mattermost : override `mattermost_channel`

- [x] 2.1 Ajouter `mattermost_channel` (optionnel) à `AlertPayload` (`src/notify/payload.rs`), l'alimenter dans `src/engine.rs` depuis `ctx.rule.notify.mattermost_channel` (cloné une fois par tâche) et mettre à jour toutes les constructions de `AlertPayload` (tests compris) ; un test de `process_log_line` vérifie que le canal de la règle est transporté, et qu'il est absent pour une règle sans la clé
- [x] 2.2 Dans `MattermostNotifier::send`, utiliser `alert.mattermost_channel` en priorité sur `self.channel` ; tests unitaires et wiremock : canal de la règle prioritaire sur celui du notifier, canal du notifier à défaut, clé `channel` absente si aucun
- [x] 2.3 Vérifier que l'avertissement `mattermost_channel ignored - no mattermost notifier in destinations` reste émis (test existant de `warn_unused_mattermost_channels` inchangé et passant)

## 3. Mattermost : repli sans canal

- [x] 3.1 Dans `MattermostNotifier::send`, lorsque le canal provient de la règle et que la réponse est un 4xx autre que 429, journaliser `Mattermost rejected channel override, resending without channel` en `warn` (notifier, règle, canal demandé, statut ; jamais l'URL) et renvoyer une seule fois le message sans `channel`, soumis à la politique de relance habituelle ; un 4xx au renvoi est un échec définitif `client error: <statut>` ; aucun repli quand le canal vient du notifier
- [x] 3.2 Tests wiremock : override de règle, 400 puis 200 → 2 requêtes, la seconde sans clé `channel`, alerte envoyée ; 400 puis 400 → 2 requêtes et erreur `client error: 400 Bad Request` ; 403 puis 500 puis 200 → succès (le renvoi suit la politique de relance) ; canal du notifier seul et 400 → 1 requête ; override de règle et 429 → relance normale sans repli
- [x] 3.3 Documenter dans `docs/notifiers.md` (section Mattermost) l'override `notify.mattermost_channel` (priorité règle > notifier > webhook) et le repli sans canal avec son avertissement ; aligner le commentaire de `docs/configuration.md` et `config/config.example.yaml`

## 4. CHANGELOG, MIGRATION et vérification finale

- [x] 4.1 Ajouter à la section `## [2.1.0]` de `CHANGELOG.md` (la créer si elle n'existe pas) : Changed (BREAKING) — `${VAR}` résolu dans le `body_template` webhook, `notify.mattermost_channel` appliqué ; Added — repli Mattermost sans canal sur rejet 4xx de l'override
- [x] 4.2 Ajouter à la section « Upgrading to 2.1.0 » de `MIGRATION.md` (la créer si elle n'existe pas) les deux ruptures : (a) `${VAR}` dans `body_template` webhook — résolu au démarrage, échec si la variable n'est pas définie, comment repérer les templates concernés (rechercher `${` dans les `body_template`), avant/après de l'exemple PagerDuty ; (b) `mattermost_channel` désormais appliqué — les alertes changent de canal, retirer la clé pour conserver l'ancien comportement, repli sans canal et avertissement si le webhook est verrouillé ou le canal inexistant
- [x] 4.3 Vérification finale : `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` et `cargo test` passent
