## ADDED Requirements

### Requirement: Canal par règle
Le système SHALL renseigner le champ `channel` du JSON envoyé avec `notify.mattermost_channel` de la règle lorsqu'il est défini, à défaut avec le `channel` du notifier, et MUST omettre `channel` si aucun des deux n'est défini ; il MUST journaliser au démarrage `mattermost_channel ignored - no mattermost notifier in destinations` pour toute règle activée qui définit `mattermost_channel` sans destination de type `mattermost`.

#### Scenario: Canal de la règle prioritaire
- **WHEN** une règle définit `mattermost_channel: alerts` et route vers un notifier Mattermost configuré avec `channel: ops`
- **THEN** le JSON envoyé contient `"channel":"alerts"`

#### Scenario: Canal du notifier par défaut
- **WHEN** une règle sans `mattermost_channel` route vers un notifier Mattermost configuré avec `channel: ops`
- **THEN** le JSON envoyé contient `"channel":"ops"`

#### Scenario: Aucun canal
- **WHEN** ni la règle ni le notifier ne définissent de canal
- **THEN** le JSON envoyé ne contient pas de clé `channel`

#### Scenario: Règle sans destination Mattermost
- **WHEN** une règle activée définit `mattermost_channel: alerts` et n'a qu'une destination webhook
- **THEN** l'avertissement est journalisé au démarrage et aucun autre notifier n'utilise ce canal

### Requirement: Repli sans canal sur rejet de l'override de règle
Le système SHALL, lorsqu'un envoi dont le champ `channel` provient de `notify.mattermost_channel` de la règle reçoit une réponse 4xx autre que 429, journaliser l'avertissement `Mattermost rejected channel override, resending without channel` avec le nom du notifier, le nom de la règle, le canal demandé et le statut (sans l'URL du webhook), puis renvoyer une seule fois le même message sans le champ `channel`. Ce renvoi MUST suivre la même politique de relance que tout envoi (5xx, 429 et erreurs réseau, au plus 3 tentatives) ; une réponse 4xx au renvoi MUST être traitée comme un échec définitif. Aucun repli n'a lieu lorsque le canal provient du `channel` du notifier ou qu'aucun canal n'est envoyé.

#### Scenario: Webhook verrouillé sur un canal
- **WHEN** une règle définit `mattermost_channel: alerts` et que le webhook répond 400 puis 200
- **THEN** deux requêtes sont émises, la seconde sans clé `channel`, l'alerte est comptée comme envoyée et l'avertissement mentionne la règle et `alerts`

#### Scenario: Repli également rejeté
- **WHEN** une règle définit `mattermost_channel: alerts` et que le webhook répond 400 puis 400
- **THEN** exactement deux requêtes sont émises et l'erreur `client error: 400 Bad Request` est remontée

#### Scenario: Pas de repli pour le canal du notifier
- **WHEN** une règle sans `mattermost_channel` route vers un notifier configuré avec `channel: ops` et que le webhook répond 400
- **THEN** une seule requête est émise

## MODIFIED Requirements

### Requirement: Champs de surcharge optionnels
Le système SHALL inclure au premier niveau du JSON les champs `channel`, `username` et `icon_url` uniquement lorsqu'ils sont configurés (pour `channel`, au niveau de la règle ou du notifier, hors renvoi de repli sans canal), et MUST les omettre entièrement sinon.

#### Scenario: Surcharges configurées
- **WHEN** `channel: alerts` et `username: bot` sont configurés mais pas `icon_url`
- **THEN** le JSON contient `"channel":"alerts"` et `"username":"bot"` et aucune clé `icon_url`

### Requirement: Pas de retry sur erreur client
Le système MUST abandonner immédiatement, sans nouvelle tentative, sur une réponse 4xx autre que 429, en journalisant `Mattermost returned client error, not retrying`, en incrémentant `valerter_notify_errors_total` et `valerter_alerts_failed_total`, et en renvoyant l'erreur `failed to send notification: client error: <statut>`, à la seule exception du renvoi unique sans canal décrit par « Repli sans canal sur rejet de l'override de règle ».

#### Scenario: Webhook invalide
- **WHEN** le webhook répond 400 à un envoi qui ne porte pas de canal issu de la règle
- **THEN** une seule requête est émise et l'erreur `client error: 400 Bad Request` est remontée

## REMOVED Requirements

### Requirement: Canal par règle non appliqué
**Reason**: La documentation (`docs/configuration.md`, `config/config.example.yaml`) présente `notify.mattermost_channel` comme un override du canal, mais la valeur était silencieusement ignorée ; remplacé par les requirements « Canal par règle » et « Repli sans canal sur rejet de l'override de règle », qui l'appliquent sans risque de perte d'alerte.
**Migration**: Une règle qui définit déjà `mattermost_channel` publiera désormais dans ce canal. Pour conserver l'ancien comportement, retirer la clé de la règle. Si le webhook entrant est verrouillé sur un canal ou si le canal n'existe pas, l'alerte est renvoyée sans canal (canal par défaut du webhook) avec un avertissement : corriger la clé ou le réglage du webhook.
