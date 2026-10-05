# notifier-webhook Specification

## Purpose
Cette capacité décrit le notifier générique `webhook`, qui envoie les alertes vers un endpoint HTTP arbitraire : configuration (URL, méthode, en-têtes, template de corps), corps JSON par défaut, politique de retry, traitement des réponses HTTP et protection des secrets. Le routage, la file et le fan-out relèvent de `notification-dispatch` ; le rendu du titre et du corps du message relève de `message-templating`, seul le `body_template` propre au webhook est décrit ici.

## Requirements

### Requirement: Configuration du notifier webhook
Le système SHALL accepter pour un notifier `type: webhook` la clé obligatoire `url` et les clés optionnelles `method` (défaut `POST`), `headers` (table nom → valeur, vide par défaut) et `body_template` (absent par défaut), et MUST rejeter la configuration si `url` est absente ou si une autre clé est présente.

#### Scenario: Valeurs par défaut
- **WHEN** un notifier déclare seulement `type: webhook` et `url`
- **THEN** la méthode est `POST`, aucun en-tête personnalisé n'est envoyé et le corps par défaut est utilisé

#### Scenario: url manquante
- **WHEN** un notifier `type: webhook` ne déclare que `method: POST`
- **THEN** le chargement de la configuration échoue

### Requirement: Méthodes HTTP autorisées
Le système SHALL accepter les méthodes `POST` et `PUT` sans tenir compte de la casse et MUST refuser toute autre méthode au démarrage avec `invalid notifier '<nom>': unsupported method '<méthode>': only POST and PUT are supported`.

#### Scenario: PUT
- **WHEN** `method: PUT`
- **THEN** les alertes sont envoyées par requête `PUT`

#### Scenario: PATCH refusé
- **WHEN** `method: PATCH`
- **THEN** le démarrage échoue avec un message contenant `unsupported method 'PATCH'` et `POST and PUT`

### Requirement: Résolution de l'URL
Le système SHALL substituer les variables `${NOM}` de `url` à l'instanciation du notifier et MUST, en cas de variable non définie, échouer avec `invalid notifier '<nom>': url: undefined environment variable: <NOM>`.

#### Scenario: URL depuis l'environnement
- **WHEN** `url: "${WEBHOOK_URL}"` et `WEBHOOK_URL=https://resolved.example.com/hook`
- **THEN** les alertes sont envoyées vers `https://resolved.example.com/hook`

### Requirement: En-têtes personnalisés
Le système SHALL envoyer à chaque requête les en-têtes de `headers` après substitution des variables `${NOM}` dans leurs valeurs, et MUST refuser de démarrer avec `invalid notifier '<nom>': header '<clé>': <détail>` si une variable est absente, `invalid header name: <clé>` si le nom est invalide, ou `invalid header value for '<clé>'` si la valeur résolue est invalide.

#### Scenario: Jeton d'autorisation
- **WHEN** `headers: { Authorization: "Bearer ${API_TOKEN}" }` et `API_TOKEN=test-token-123`
- **THEN** chaque requête porte l'en-tête `Authorization: Bearer test-token-123`

#### Scenario: Variable d'en-tête manquante
- **WHEN** la valeur d'en-tête `Authorization` référence une variable non définie
- **THEN** le démarrage échoue avec un message contenant `header` et `Authorization`

### Requirement: Corps JSON par défaut
Le système SHALL, en l'absence de `body_template`, envoyer un objet JSON contenant exactement `alert_name` (nom du notifier), `rule_name`, `vl_source`, `title`, `body`, `timestamp` (instant d'envoi au format RFC 3339), `log_timestamp` et `log_timestamp_formatted`, et MUST n'y inclure ni `accent_color` ni couleur ni icône.

#### Scenario: Contenu du corps par défaut
- **WHEN** le notifier `webhook-1` envoie une alerte de la règle `cpu_alert` de titre `Test Alert`
- **THEN** le JSON contient `"alert_name":"webhook-1"`, `"rule_name":"cpu_alert"`, `"title":"Test Alert"` et un champ `timestamp` non vide
- **AND** il ne contient aucune clé `color`, `icon` ni `accent_color`

### Requirement: Validation du body_template au démarrage
Le système MUST vérifier la syntaxe Jinja du `body_template` à l'instanciation du notifier et refuser de démarrer en cas d'erreur avec `invalid notifier '<nom>': body_template: invalid template in rule 'webhook.body_template': <détail>`.

#### Scenario: Template mal formé
- **WHEN** `body_template` contient `{{ title`
- **THEN** le démarrage échoue avec un message contenant `body_template`

### Requirement: Rendu du body_template
Le système SHALL rendre le `body_template` avec les seules variables `title`, `body`, `rule_name`, `vl_source`, `log_timestamp` et `log_timestamp_formatted`, sans échappement automatique des valeurs, une variable inconnue étant rendue comme une chaîne vide, et MUST envoyer le résultat tel quel comme corps de la requête. Le filtre `tojson` MUST être disponible et produire une valeur JSON valide (chaîne entre guillemets, caractères spéciaux échappés), afin qu'un template comme `{"text": {{ body | tojson }}}` produise toujours du JSON valide.

#### Scenario: Template personnalisé
- **WHEN** `body_template` vaut `{"title": "{{ title }}", "rule": "{{ rule_name }}"}` pour la règle `test_rule` de titre `Test Alert`
- **THEN** le corps envoyé est `{"title": "Test Alert", "rule": "test_rule"}`

#### Scenario: Pas de substitution d'environnement dans le template
- **WHEN** `body_template` contient le texte `${ROUTING_KEY}`
- **THEN** le texte `${ROUTING_KEY}` est envoyé littéralement

#### Scenario: Valeur insérée avec tojson
- **WHEN** `body_template` vaut `{"text": {{ body | tojson }}}` et que le corps de l'alerte contient un guillemet, une barre oblique inverse et un saut de ligne
- **THEN** le corps envoyé est un JSON valide dont le champ `text` vaut exactement le corps de l'alerte

### Requirement: Échec de rendu à l'envoi
Le système MUST, si le rendu du `body_template` échoue au moment de l'envoi, abandonner l'alerte pour ce notifier sans émettre de requête ni de retry, avec l'erreur `failed to send notification: template render error: <détail>`.

#### Scenario: Erreur de rendu
- **WHEN** le rendu du template échoue pour une alerte
- **THEN** aucune requête HTTP n'est émise et l'échec est journalisé par le worker

### Requirement: Corps identique entre les tentatives
Le système SHALL construire le corps une seule fois par alerte et MUST réutiliser exactement le même corps pour chaque tentative.

#### Scenario: Retry
- **WHEN** une première tentative reçoit 500 puis la seconde réussit
- **THEN** les deux requêtes portent le même corps, y compris la même valeur de `timestamp`

### Requirement: Succès sur réponse 2xx
Le système SHALL considérer l'envoi réussi dès qu'une réponse de statut 2xx est reçue, MUST arrêter alors les tentatives et incrémenter `valerter_alerts_sent_total` avec `notifier_type="webhook"`.

#### Scenario: Succès au premier essai
- **WHEN** l'endpoint répond 200
- **THEN** une seule requête est émise et l'alerte est comptée comme envoyée

### Requirement: Pas de retry sur erreur client
Le système MUST abandonner immédiatement, sans nouvelle tentative, sur une réponse 4xx autre que 429, en journalisant `Webhook returned client error, not retrying`, en incrémentant `valerter_notify_errors_total` et `valerter_alerts_failed_total`, et en renvoyant l'erreur `failed to send notification: client error: <statut>`.

#### Scenario: Requête rejetée
- **WHEN** l'endpoint répond 400
- **THEN** une seule requête est émise et l'alerte est comptée comme échouée

### Requirement: Retry sur erreur serveur, 429 et erreur réseau
Le système SHALL réessayer sur réponse 5xx, sur 429 et sur erreur réseau, avec au total 3 tentatives au maximum séparées par des délais de 500 ms puis 1 s, en journalisant un avertissement à chaque échec.

#### Scenario: 429 puis succès
- **WHEN** l'endpoint répond 429 puis 200
- **THEN** deux requêtes sont émises et l'alerte est comptée comme envoyée

#### Scenario: 500 puis succès
- **WHEN** l'endpoint répond 500 puis 200
- **THEN** deux requêtes sont émises et l'alerte est comptée comme envoyée

### Requirement: Échec après épuisement des tentatives
Le système MUST, après 3 tentatives infructueuses, journaliser `Failed to send webhook alert after all retries`, incrémenter `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec `notifier_type="webhook"`, et renvoyer l'erreur `max retries exceeded`.

#### Scenario: Erreur 503 persistante
- **WHEN** l'endpoint répond toujours 503
- **THEN** exactement 3 requêtes sont émises puis l'alerte est comptée comme échouée

### Requirement: Protection de l'URL et des en-têtes
Le système MUST traiter `url` et les valeurs de `headers` comme des secrets : la représentation de débogage du notifier n'expose que son nom, sa méthode et la présence d'un `body_template`, celle de la configuration rend ces valeurs `[REDACTED]`, et les journaux d'erreur réseau sont émis sans l'URL.

#### Scenario: Débogage du notifier
- **WHEN** un notifier configuré avec `url: https://secret.example.com/abc123` et `Authorization: Bearer super-secret-token` est affiché en débogage
- **THEN** la sortie contient le nom du notifier et `POST` mais ni `secret.example.com`, ni `abc123`, ni `super-secret-token`

### Requirement: Content-Type JSON par défaut
Le système SHALL ajouter l'en-tête `Content-Type: application/json` à chaque requête lorsque `headers` ne contient aucun en-tête `Content-Type` (comparaison insensible à la casse du nom), que le corps soit le JSON par défaut ou issu de `body_template`, et MUST conserver tel quel un `Content-Type` configuré par l'opérateur, sans le dupliquer.

#### Scenario: Corps par défaut sans en-tête configuré
- **WHEN** aucun en-tête n'est configuré et `body_template` est absent
- **THEN** la requête porte le JSON par défaut et exactement un en-tête `Content-Type: application/json`

#### Scenario: body_template sans en-tête configuré
- **WHEN** un `body_template` est configuré et `headers` ne contient pas de `Content-Type`
- **THEN** la requête porte l'en-tête `Content-Type: application/json`

#### Scenario: Content-Type configuré prioritaire
- **WHEN** `headers: { content-type: "text/plain" }` est configuré
- **THEN** la requête porte un unique en-tête `Content-Type` de valeur `text/plain`

### Requirement: Avertissement sur un corps JSON invalide
Le système SHALL, lorsque le `Content-Type` effectif de la requête est JSON (`application/json` ou type à suffixe `+json`, sans tenir compte de la casse ni des paramètres) et que le corps rendu par `body_template` n'est pas un document JSON valide, journaliser l'avertissement `Webhook body is not valid JSON` avec le nom du notifier et de la règle mais sans le contenu du corps, et MUST envoyer quand même la requête.

#### Scenario: Guillemet non échappé
- **WHEN** `body_template` vaut `{"text": "{{ body }}"}` et que le corps de l'alerte contient `say "hi"`
- **THEN** l'avertissement `Webhook body is not valid JSON` est journalisé et la requête est émise

#### Scenario: Corps non JSON assumé
- **WHEN** `headers: { Content-Type: "text/plain" }` est configuré et que le corps rendu n'est pas du JSON
- **THEN** aucun avertissement n'est journalisé et la requête est émise
