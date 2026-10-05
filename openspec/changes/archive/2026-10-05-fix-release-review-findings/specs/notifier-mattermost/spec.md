## MODIFIED Requirements

### Requirement: Résolution de webhook_url
Le système SHALL substituer les variables `${NOM}` de `webhook_url` à l'instanciation du notifier et MUST, en cas de variable non définie, échouer avec `invalid notifier '<nom>': webhook_url: invalid configuration: undefined environment variable: <NOM>`, l'erreur étant signalée par les logs et le code de sortie du démarrage, sans métrique dédiée.

#### Scenario: Variable non définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL` n'est pas défini
- **THEN** le démarrage échoue avec un message contenant `webhook_url` et `MM_URL`
- **AND** aucune série `valerter_notifier_config_errors_total` n'est émise

### Requirement: Pas de retry sur erreur client
Le système MUST abandonner immédiatement, sans nouvelle tentative, sur une réponse 4xx autre que 429, en journalisant `Mattermost returned client error, not retrying`, en incrémentant `valerter_notify_errors_total` et `valerter_alerts_failed_total`, et en renvoyant l'erreur `failed to send notification: client error: <statut>`, à la seule exception du renvoi unique décrit par « Repli sur le canal du notifier sur rejet de l'override de règle ».

#### Scenario: Webhook invalide
- **WHEN** le webhook répond 400 à un envoi qui ne porte pas de canal issu de la règle
- **THEN** une seule requête est émise et l'erreur `client error: 400 Bad Request` est remontée

## REMOVED Requirements

### Requirement: Repli sans canal sur rejet de l'override de règle
**Reason**: Le renvoi systématique sans `channel` envoyait l'alerte dans le canal par défaut du webhook même quand le notifier déclare son propre `channel`, contournant le choix de l'administrateur. Remplacé par « Repli sur le canal du notifier sur rejet de l'override de règle ».
**Migration**: Aucune action requise. Un notifier sans `channel` garde le comportement précédent (renvoi sans `channel`) ; un notifier avec `channel` reçoit désormais le renvoi dans ce canal. Le texte de l'avertissement change (voir la nouvelle exigence).

## ADDED Requirements

### Requirement: Repli sur le canal du notifier sur rejet de l'override de règle
Le système SHALL, lorsqu'un envoi dont le `channel` provient de `notify.mattermost_channel` reçoit un 4xx autre que 429, journaliser l'avertissement `Mattermost rejected channel override, resending to notifier default` puis renvoyer une seule fois le message avec le `channel` du notifier s'il est défini et différent, sinon sans `channel`. Ce renvoi MUST suivre la politique de relance habituelle ; un 4xx au renvoi MUST être un échec définitif. Sans canal de règle, aucun repli.

#### Scenario: Contenu de l'avertissement
- **WHEN** un repli a lieu
- **THEN** l'avertissement porte le nom du notifier, le nom de la règle, le canal demandé, le canal de repli (absent pour le canal par défaut du webhook) et le statut, mais pas l'URL du webhook

#### Scenario: Relances du renvoi
- **WHEN** le renvoi reçoit un 5xx, un 429 ou une erreur réseau
- **THEN** il est relancé comme tout envoi, au plus 3 tentatives

#### Scenario: Webhook verrouillé sur un canal
- **WHEN** une règle définit `mattermost_channel: alerts`, que le notifier n'a pas de `channel` et que le webhook répond 400 puis 200
- **THEN** deux requêtes sont émises, la seconde sans clé `channel`, l'alerte est comptée comme envoyée et l'avertissement mentionne la règle et `alerts`

#### Scenario: Repli sur le canal du notifier
- **WHEN** une règle définit `mattermost_channel: alerts`, que le notifier est configuré avec `channel: ops` et que le webhook répond 400 puis 200
- **THEN** deux requêtes sont émises, la seconde avec `"channel":"ops"`, et l'alerte est comptée comme envoyée

#### Scenario: Canal de la règle identique à celui du notifier
- **WHEN** une règle définit `mattermost_channel: ops`, que le notifier est configuré avec `channel: ops` et que le webhook répond 400 puis 200
- **THEN** deux requêtes sont émises, la seconde sans clé `channel`

#### Scenario: Repli également rejeté
- **WHEN** une règle définit `mattermost_channel: alerts` et que le webhook répond 400 puis 400
- **THEN** exactement deux requêtes sont émises et l'erreur `client error: 400 Bad Request` est remontée

#### Scenario: Pas de repli pour le canal du notifier
- **WHEN** une règle sans `mattermost_channel` route vers un notifier configuré avec `channel: ops` et que le webhook répond 400
- **THEN** une seule requête est émise
