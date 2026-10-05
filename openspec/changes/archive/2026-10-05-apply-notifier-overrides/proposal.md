# Proposal

## Why

Deux clés de configuration ne font pas ce que la documentation et l'intuition promettent. Dans le `body_template` du
notifier webhook, un `${VAR}` est envoyé littéralement alors que `url` et `headers` du même notifier sont résolus depuis
l'environnement : l'exemple PagerDuty historique envoyait ainsi `${PAGERDUTY_ROUTING_KEY}` en clair, et il est
impossible de garder un secret de corps hors du fichier de configuration. Côté Mattermost, `notify.mattermost_channel`
est documenté comme override du canal par règle (`docs/configuration.md`, `config/config.example.yaml`) mais il est
silencieusement ignoré. Corriger ces deux écarts change un comportement observable : c'est une rupture, livrée dans la
version 2.1.0 avec un guide de migration, et implémentée en dernier, après les changes de durcissement.

## What Changes

- **Webhook — BREAKING** : les motifs `${VAR}` du `body_template` sont résolus depuis l'environnement à l'instanciation
  du notifier, sur la source du template (jamais sur le rendu), comme `url` et `headers` ; une variable non définie fait
  échouer le démarrage. Un texte `${…}` littéral dans le template n'est donc plus envoyé tel quel. L'exemple PagerDuty de
  la doc et de `config/config.example.yaml` est réécrit avec `"routing_key": "${PAGERDUTY_ROUTING_KEY}"` à la place de
  la valeur à remplacer laissée par `harden-notifier-payloads`.
- **Mattermost — BREAKING** : `notify.mattermost_channel` est appliqué (priorité règle > `channel` du notifier > canal
  par défaut du webhook). Une règle qui définissait déjà la clé publiera désormais dans ce canal.
- **Mattermost** : repli de livraison — si un envoi portant le canal de la règle reçoit une réponse 4xx (autre que 429),
  le message est renvoyé une seule fois sans le champ `channel`, avec un avertissement indiquant la règle et le canal
  demandé, afin de ne pas perdre l'alerte (webhook verrouillé sur un canal, canal mal orthographié : la clé n'ayant
  jamais été exercée, ces erreurs de configuration sont probables).
- **Dispatch** : le payload d'alerte transporte le `mattermost_channel` optionnel de la règle.
- **MIGRATION.md** : la section « Upgrading to 2.1.0 » explique les deux ruptures et comment conserver l'ancien
  comportement.

## Capabilities

### New Capabilities
<!-- Aucune -->

### Modified Capabilities
- `notifier-webhook` : résolution des `${VAR}` dans `body_template` ; la règle « pas de substitution » ne porte plus que
  sur les valeurs rendues.
- `notifier-mattermost` : application de `notify.mattermost_channel` (remplace « Canal par règle non appliqué »), repli
  sans `channel` sur rejet 4xx de l'override, exception correspondante à « Pas de retry sur erreur client ».
- `notification-dispatch` : le payload d'alerte transporte le `mattermost_channel` optionnel de la règle.

## Impact

- Code : `src/notify/webhook.rs` (résolution dans `from_config`), `src/notify/mattermost.rs` (choix du canal, repli),
  `src/notify/payload.rs` (`AlertPayload`), `src/engine.rs` (construction de `AlertPayload`), toutes les constructions de
  `AlertPayload` dans les tests, `tests/integration_notify.rs`.
- Documentation : `docs/notifiers.md`, `docs/configuration.md`, `config/config.example.yaml`, `CHANGELOG.md`,
  `MIGRATION.md`.
- Aucune nouvelle dépendance, aucune nouvelle clé de configuration.
- Compatibilité : deux ruptures de comportement documentées dans MIGRATION.md (section 2.1.0) et dans le CHANGELOG.
- Dépend de `harden-notifier-payloads` (filtre `tojson` documenté, exemples réécrits) qui doit être appliqué avant.
