# Proposal

## Why

Les charges utiles produites par plusieurs notifiers sont fragiles ou ne correspondent pas à ce que promet la
documentation : le webhook envoie du JSON sans `Content-Type`, les exemples Slack/Discord/PagerDuty de
`docs/notifiers.md` produisent du JSON invalide dès qu'un titre ou un corps contient un guillemet ou un saut de ligne,
un message Telegram en `parse_mode` HTML rejeté en 400 (balise coupée par la troncature, `<` ou `&` non échappé dans un
template personnalisé) est perdu sans relance, la classification des erreurs SMTP repose sur des sous-chaînes du message
d'erreur, et la doc Mattermost décrit un pied de page qui n'existe pas. Une alerte perdue sur un 400 évitable est le pire
défaut d'un démon d'alerting : ces écarts doivent être corrigés, sans rupture de compatibilité, dans la version 2.1.0.

## What Changes

- **Webhook** : ajout de `Content-Type: application/json` lorsque l'opérateur n'a configuré aucun en-tête
  `Content-Type` (quelle que soit la casse) ; un `Content-Type` configuré reste prioritaire.
- **Webhook** : le filtre `tojson` (déjà fourni par minijinja) devient la manière documentée d'insérer une valeur dans
  un `body_template` JSON ; les exemples Slack, Discord, PagerDuty et Custom API (docs, `config/config.example.yaml`)
  sont réécrits avec `tojson`. L'exemple PagerDuty n'utilise plus de `${VAR}` dans le corps (non résolu dans cette
  version du code) : la clé de routage y figure comme valeur à remplacer, la variante avec `${PAGERDUTY_ROUTING_KEY}`
  étant apportée par le change `apply-notifier-overrides`.
- **Webhook** : avertissement `Webhook body is not valid JSON` journalisé (sans le contenu du corps) lorsque le corps
  rendu n'est pas du JSON valide alors que le `Content-Type` effectif est JSON ; l'envoi a quand même lieu.
- **Telegram** : repli en texte brut — lorsqu'un envoi en `parse_mode` HTML reçoit une réponse 400, le même texte est
  renvoyé une seule fois sans `parse_mode`, avec un avertissement. Cela couvre la troncature qui coupe une balise ou une
  entité comme les `<`/`&` non échappés d'un `body_template` personnalisé. La troncature reste une coupe simple à 4096
  points de code.
- **SMTP** : classification permanente/transitoire fondée sur le code de réponse SMTP structuré renvoyé par lettre
  (5xx permanent ; 4xx, erreurs réseau, TLS et délais transitoires) au lieu de sous-chaînes ; le texte de l'erreur ne
  sert plus à décider.
- **Mattermost (doc seulement)** : la description du pied de page dans `docs/notifiers.md` est alignée sur le format
  réel `valerter | <rule_name> | <vl_source> | <log_timestamp_formatted>`.

Hors périmètre, reportés au change `apply-notifier-overrides` (cassant) : résolution des `${VAR}` dans le
`body_template` webhook et application de `notify.mattermost_channel`.

## Capabilities

### New Capabilities
<!-- Aucune -->

### Modified Capabilities
- `notifier-webhook` : `Content-Type` JSON par défaut (remplace « Aucun Content-Type implicite »), filtre `tojson` et
  avertissement sur JSON invalide.
- `notifier-telegram` : repli en texte brut sur un rejet 400 en mode HTML.
- `notifier-email` : classification des erreurs SMTP par code de réponse.

## Impact

- Code : `src/notify/webhook.rs`, `src/notify/telegram.rs`, `src/notify/email.rs` (trait `EmailTransport` et
  `MockEmailTransport` à adapter à une erreur structurée), tests unitaires associés, `tests/integration_notify.rs`.
- Documentation : `docs/notifiers.md`, `config/config.example.yaml`, `CHANGELOG.md`.
- Aucune nouvelle dépendance (minijinja `json` est déjà activé).
- Compatibilité : aucune nouvelle clé, aucune rupture. Seul changement visible côté requête : l'en-tête
  `Content-Type: application/json` ajouté par défaut au webhook (un `Content-Type` configuré reste prioritaire), signalé
  dans le CHANGELOG.
