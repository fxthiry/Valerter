# notifier-mattermost Specification

## Purpose
Cette capacité décrit le notifier `mattermost`, qui publie les alertes dans Mattermost via un webhook entrant : configuration, format du message (attachment unique, couleur, pied de page), politique de retry, traitement des réponses HTTP et protection de l'URL secrète. Le routage, la file et le fan-out relèvent de `notification-dispatch` ; le rendu du titre, du corps et de `accent_color` relève de `message-templating`.

## Requirements

### Requirement: Configuration du notifier Mattermost
Le système SHALL accepter pour un notifier `type: mattermost` la clé obligatoire `webhook_url` et les clés optionnelles `channel`, `username` et `icon_url`, et MUST rejeter la configuration si `webhook_url` est absente ou si une autre clé est présente.

#### Scenario: Configuration minimale
- **WHEN** un notifier déclare seulement `type: mattermost` et `webhook_url`
- **THEN** il est accepté et `channel`, `username`, `icon_url` sont absents

#### Scenario: webhook_url manquante
- **WHEN** un notifier `type: mattermost` ne déclare que `channel: "test"`
- **THEN** le chargement de la configuration échoue

### Requirement: Résolution de webhook_url
Le système SHALL substituer les variables `${NOM}` de `webhook_url` à l'instanciation du notifier et MUST, en cas de variable non définie, échouer avec `invalid notifier '<nom>': webhook_url: undefined environment variable: <NOM>`, l'erreur étant signalée par les logs et le code de sortie du démarrage, sans métrique dédiée.

#### Scenario: Variable non définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL` n'est pas défini
- **THEN** le démarrage échoue avec un message contenant `webhook_url` et `MM_URL`
- **AND** aucune série `valerter_notifier_config_errors_total` n'est émise

### Requirement: Requête d'envoi
Le système SHALL envoyer chaque alerte par une requête HTTP `POST` vers `webhook_url` avec un corps JSON (`Content-Type: application/json`).

#### Scenario: Envoi simple
- **WHEN** une alerte est routée vers un notifier Mattermost
- **THEN** une requête `POST` JSON est reçue sur l'URL du webhook

### Requirement: Champs de surcharge optionnels
Le système SHALL inclure au premier niveau du JSON les champs `channel`, `username` et `icon_url` uniquement lorsqu'ils sont configurés, et MUST les omettre entièrement sinon.

#### Scenario: Surcharges configurées
- **WHEN** `channel: alerts` et `username: bot` sont configurés mais pas `icon_url`
- **THEN** le JSON contient `"channel":"alerts"` et `"username":"bot"` et aucune clé `icon_url`

### Requirement: Attachment unique
Le système SHALL placer le message dans un tableau `attachments` contenant exactement un élément dont `fallback` et `title` valent le titre rendu et `text` vaut le corps rendu, sans transformation (le Markdown est interprété par Mattermost).

#### Scenario: Structure de l'attachment
- **WHEN** le titre rendu est `Test Alert` et le corps `Something happened`
- **THEN** l'unique attachment contient `"fallback":"Test Alert"`, `"title":"Test Alert"` et `"text":"Something happened"`

### Requirement: Couleur de l'attachment
Le système SHALL renseigner `color` de l'attachment avec l'`accent_color` du message rendu et MUST omettre la clé `color` lorsque le template ne définit pas d'`accent_color`.

#### Scenario: Couleur définie
- **WHEN** le template rendu a `accent_color: "#ff0000"`
- **THEN** l'attachment contient `"color":"#ff0000"`

#### Scenario: Couleur absente
- **WHEN** le template n'a pas d'`accent_color`
- **THEN** l'attachment ne contient pas de clé `color`

### Requirement: Pied de page de l'attachment
Le système SHALL renseigner `footer` avec la chaîne `valerter | <rule_name> | <vl_source> | <log_timestamp_formatted>`.

#### Scenario: Footer
- **WHEN** la règle `test_rule`, issue de la source `vlprod`, produit une alerte dont le log est horodaté `15/01/2026 10:49:35 UTC`
- **THEN** le footer vaut `valerter | test_rule | vlprod | 15/01/2026 10:49:35 UTC`

### Requirement: Succès sur réponse 2xx
Le système SHALL considérer l'envoi réussi dès qu'une réponse de statut 2xx est reçue, MUST arrêter alors les tentatives et incrémenter `valerter_alerts_sent_total` avec `notifier_type="mattermost"`.

#### Scenario: Succès au premier essai
- **WHEN** le webhook répond 200 à la première requête
- **THEN** une seule requête est émise et l'alerte est comptée comme envoyée

### Requirement: Pas de retry sur erreur client
Le système MUST abandonner immédiatement, sans nouvelle tentative, sur une réponse 4xx autre que 429, en journalisant `Mattermost returned client error, not retrying`, en incrémentant `valerter_notify_errors_total` et `valerter_alerts_failed_total`, et en renvoyant l'erreur `failed to send notification: client error: <statut>`.

#### Scenario: Webhook invalide
- **WHEN** le webhook répond 400
- **THEN** une seule requête est émise et l'erreur `client error: 400 Bad Request` est remontée

### Requirement: Retry sur erreur serveur, 429 et erreur réseau
Le système SHALL réessayer sur réponse 5xx, sur 429 et sur erreur réseau (timeout, connexion refusée), avec au total 3 tentatives au maximum séparées par des délais de 500 ms puis 1 s, en journalisant un avertissement à chaque échec.

#### Scenario: Erreur 500 puis succès
- **WHEN** le webhook répond 500 puis 200
- **THEN** deux requêtes sont émises, séparées d'environ 500 ms, et l'alerte est comptée comme envoyée

### Requirement: Échec après épuisement des tentatives
Le système MUST, après 3 tentatives infructueuses, journaliser `Failed to send alert after all retries`, incrémenter `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec `notifier_type="mattermost"`, et renvoyer l'erreur `max retries exceeded`.

#### Scenario: Erreur 500 persistante
- **WHEN** le webhook répond toujours 500
- **THEN** exactement 3 requêtes sont émises puis l'alerte est comptée comme échouée

### Requirement: Protection de l'URL du webhook
Le système MUST traiter `webhook_url` comme un secret : elle n'apparaît ni dans la représentation de débogage de la configuration ou du notifier (rendue `[REDACTED]` pour la configuration), ni dans les messages d'erreur de validation, ni dans les journaux d'erreur réseau, qui sont émis sans l'URL.

#### Scenario: Erreur réseau journalisée
- **WHEN** une tentative échoue faute de connexion
- **THEN** l'avertissement `Failed to send to Mattermost, retrying` ne contient pas l'URL du webhook

### Requirement: Canal par règle non appliqué
Le système SHALL accepter la clé `notify.mattermost_channel` d'une règle sans l'appliquer au message envoyé (seul le `channel` du notifier est utilisé), et MUST journaliser au démarrage l'avertissement `mattermost_channel ignored - no mattermost notifier in destinations` pour toute règle activée qui la définit sans avoir de destination de type `mattermost`.

#### Scenario: Règle sans destination Mattermost
- **WHEN** une règle activée définit `mattermost_channel: alerts` et n'a qu'une destination webhook
- **THEN** l'avertissement est journalisé au démarrage

#### Scenario: Règle avec destination Mattermost
- **WHEN** une règle définit `mattermost_channel: alerts` et route vers un notifier Mattermost sans `channel`
- **THEN** le JSON envoyé ne contient pas de clé `channel`

### Requirement: Validation de webhook_url résolue
Le système MUST, à l'instanciation du notifier et après substitution des variables `${NOM}`, vérifier que `webhook_url` est une URL analysable au schéma `http` ou `https`, et refuser de démarrer sinon avec `invalid notifier '<nom>': webhook_url: invalid URL: <détail>`, sans répéter l'URL.

#### Scenario: Variable résolue au mauvais schéma
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=htps://mm.example.com/hooks/SECRET`
- **THEN** le démarrage échoue avec un message contenant `webhook_url: invalid URL:` et ne contenant pas `SECRET`

#### Scenario: Variable résolue valide
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=https://mm.example.com/hooks/abc`
- **THEN** le notifier est créé et envoie vers cette URL
