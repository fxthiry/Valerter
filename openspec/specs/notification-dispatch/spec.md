# notification-dispatch Specification

## Purpose
Cette capacité décrit l'acheminement des alertes rendues vers les canaux de notification : déclaration des notifiers nommés et constitution du registre au démarrage, routage de chaque règle vers une ou plusieurs destinations, file asynchrone bornée entre le moteur de règles et le worker d'envoi, fan-out parallèle, contrat commun de retry/backoff et métriques d'envoi, comportement à l'arrêt. Le format des messages et les règles HTTP propres à chaque canal sont décrits dans `notifier-mattermost`, `notifier-webhook` et dans les specs email et Telegram ; le rendu des templates de message relève de `message-templating`.

## Requirements

### Requirement: Notifiers nommés et typés
Le système SHALL lire les notifiers depuis la section `notifiers` (fichier principal et `notifiers.d/`), sous forme de table nom → configuration dont la clé `type` vaut obligatoirement `mattermost`, `webhook`, `email` ou `telegram`, et MUST rejeter au chargement tout type inconnu ou tout champ non reconnu pour le type choisi.

#### Scenario: Deux notifiers de même type sous des noms distincts
- **WHEN** la configuration déclare `notifier-a` et `notifier-b`, tous deux `type: mattermost` avec leur propre `webhook_url`
- **THEN** les deux notifiers sont enregistrés et adressables indépendamment par leur nom

#### Scenario: Champ inconnu
- **WHEN** un notifier `type: telegram` contient une clé `icon_url`
- **THEN** le chargement de la configuration échoue

### Requirement: Au moins un notifier obligatoire
Le système MUST refuser une configuration ne déclarant aucun notifier après fusion de `config.yaml` et `notifiers.d/`, avec l'erreur `no notifiers configured: add notifiers in config.yaml or notifiers.d/`.

#### Scenario: Section notifiers absente
- **WHEN** ni `config.yaml` ni `notifiers.d/` ne définissent de notifier
- **THEN** la validation échoue avec le message `invalid configuration: no notifiers configured: add notifiers in config.yaml or notifiers.d/`

### Requirement: Construction du registre au démarrage avec collecte des erreurs
Le système SHALL instancier tous les notifiers au démarrage du démon comme en mode `--validate` (après la validation de la configuration), MUST collecter toutes les erreurs d'instanciation plutôt que s'arrêter à la première, journaliser chacune sous `Notifier configuration error`, puis refuser de démarrer avec l'erreur `Failed to create notifiers: <N> errors` ; l'instanciation MUST NOT effectuer d'appel réseau.

#### Scenario: Deux notifiers invalides
- **WHEN** deux notifiers référencent chacun une variable d'environnement non définie
- **THEN** deux erreurs `Notifier configuration error` sont journalisées
- **AND** le démon s'arrête en erreur avec `Failed to create notifiers: 2 errors` sans traiter aucune règle

#### Scenario: Mode validation
- **WHEN** le binaire est lancé avec `--validate` sur une configuration dont un notifier référence une variable d'environnement non définie
- **THEN** l'erreur est journalisée sous `Notifier configuration error` et le processus se termine avec le code 1 sans afficher de récapitulatif

#### Scenario: Instanciation sans réseau
- **WHEN** les notifiers sont instanciés (démarrage ou `--validate`) alors que leurs serveurs SMTP, webhooks ou API sont injoignables
- **THEN** l'instanciation réussit ; les erreurs de connexion n'apparaissent qu'à l'envoi d'une alerte

### Requirement: Substitution des variables d'environnement dans les secrets des notifiers
Le système SHALL remplacer, à l'instanciation des notifiers, chaque motif `${NOM}` (NOM conforme à `[A-Za-z_][A-Za-z0-9_]*`) des champs secrets par la valeur de la variable d'environnement correspondante, et MUST échouer si une variable est absente avec un message listant toutes les variables manquantes (`undefined environment variable: A` ou `undefined environment variables: A, B`) préfixé par `invalid notifier '<nom>': <champ>: `.

#### Scenario: Variable définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=https://mm.example.com/hooks/x`
- **THEN** le notifier envoie vers `https://mm.example.com/hooks/x`

#### Scenario: Variables manquantes
- **WHEN** un champ secret vaut `${UNDEFINED_A} and ${UNDEFINED_B}` et aucune des deux n'est définie
- **THEN** l'erreur mentionne `undefined environment variables: UNDEFINED_A, UNDEFINED_B`

### Requirement: Validation du schéma des URL de notifier
Le système MUST rejeter à la validation une `webhook_url` (Mattermost) ou une `url` (webhook) qui n'est pas une URL analysable de schéma `http` ou `https`, avec l'erreur `notifier '<nom>': webhook_url: <détail>` ou `notifier '<nom>': url: <détail>` sans recopier l'URL, et SHALL ignorer cette vérification lorsque la valeur contient `${`.

#### Scenario: Schéma non supporté
- **WHEN** `url: "ftp://example.com/x"`
- **THEN** la validation échoue avec un message contenant `unsupported scheme 'ftp' (expected http or https)`

#### Scenario: URL avec placeholder
- **WHEN** `webhook_url: "${MATTERMOST_WEBHOOK}"`
- **THEN** aucune erreur de schéma n'est émise à la validation

### Requirement: Destinations obligatoires par règle
Le système MUST exiger que `notify.destinations` de chaque règle contienne au moins un nom de notifier, sous peine de l'erreur `rule '<règle>': notify.destinations must contain at least one notifier`.

#### Scenario: Liste vide
- **WHEN** une règle déclare `destinations: []`
- **THEN** la validation échoue avec `invalid configuration: rule '<règle>': notify.destinations must contain at least one notifier`

### Requirement: Destinations inconnues refusées au démarrage
Le système MUST vérifier au démarrage que chaque destination de chaque règle (activée ou non) correspond à un notifier du registre, journaliser une erreur `Destination validation error` par règle fautive (`rule '<règle>': unknown notifier 'x'` ou `unknown notifiers 'x', 'y'`) et refuser de démarrer avec `Destination validation failed: <N> errors`.

#### Scenario: Faute de frappe dans une destination
- **WHEN** une règle référence `mattermost-ifra` alors que seul `mattermost-infra` existe
- **THEN** le démarrage échoue avec `rule '<règle>': unknown notifier 'mattermost-ifra'`

#### Scenario: Destinations valides
- **WHEN** toutes les destinations existent
- **THEN** le message `All rule destinations validated successfully` est journalisé et le démarrage continue

### Requirement: Contenu du payload d'alerte
Le système SHALL transmettre à chaque notifier, pour chaque alerte, le message rendu (`title`, `body`, `email_body_html` optionnel, `accent_color` optionnel), le nom de la règle, le nom de la source VictoriaLogs (`vl_source`), la liste des destinations de la règle, l'horodatage brut du log (`log_timestamp`, champ `_time` de l'événement) et sa version lisible (`log_timestamp_formatted`, format `DD/MM/YYYY HH:MM:SS TZ` dans le fuseau `timestamp_timezone`, secondes tronquées).

#### Scenario: Horodatage formaté
- **WHEN** l'événement a `_time = 2026-01-15T10:00:00Z` et `timestamp_timezone: Europe/Paris`
- **THEN** `log_timestamp` vaut `2026-01-15T10:00:00Z` et `log_timestamp_formatted` vaut `15/01/2026 11:00:00 CET`

#### Scenario: Champ _time absent
- **WHEN** l'événement ne contient pas de champ `_time`
- **THEN** un avertissement `Missing _time field in log, using current time` est journalisé et l'heure courante RFC 3339 est utilisée comme `log_timestamp`

#### Scenario: Horodatage non analysable
- **WHEN** `_time` n'est pas un horodatage RFC 3339 valide
- **THEN** `log_timestamp_formatted` reprend la valeur brute inchangée

### Requirement: File de notification bornée et non bloquante
Le système SHALL placer chaque alerte dans une file asynchrone unique de capacité 100 (non configurable, arrondie en interne à la puissance de deux supérieure, soit 128 emplacements effectifs), MUST ne jamais bloquer le producteur, et SHALL renvoyer l'erreur `notification queue closed` lorsque plus aucun consommateur n'est actif ; le moteur journalise alors `Failed to send to notification queue` et l'alerte est perdue.

#### Scenario: Envoi non bloquant
- **WHEN** une règle produit une alerte alors que le worker est occupé
- **THEN** l'alerte est mise en file immédiatement et la lecture du flux de logs continue

#### Scenario: Aucun consommateur
- **WHEN** une alerte est envoyée alors que le worker s'est arrêté
- **THEN** l'envoi échoue avec `notification queue closed`

### Requirement: Politique drop-oldest en cas de saturation
Le système MUST, lorsque la file est pleine, écraser les alertes les plus anciennes non encore consommées au profit des nouvelles, puis, lorsque le worker détecte la perte, journaliser l'avertissement `Queue full, dropping <N> oldest alerts` et incrémenter de N le compteur global `valerter_alerts_dropped_total`.

#### Scenario: Rafale dépassant la capacité
- **WHEN** plus d'alertes que la capacité effective sont produites avant que le worker ne les consomme
- **THEN** les plus anciennes sont abandonnées, les plus récentes sont conservées
- **AND** `valerter_alerts_dropped_total` augmente du nombre d'alertes perdues

### Requirement: Jauge de taille de file
Le système SHALL publier la jauge `valerter_queue_size` (initialisée à 0) et la mettre à jour après chaque mise en file, après chaque alerte traitée et après chaque détection de perte.

#### Scenario: Mise en file
- **WHEN** deux alertes sont en attente de traitement
- **THEN** `valerter_queue_size` vaut 2

### Requirement: Worker unique et traitement séquentiel FIFO
Le système SHALL consommer la file avec un worker unique qui traite les alertes une par une dans leur ordre d'arrivée, l'alerte suivante n'étant prise qu'une fois terminés tous les envois (retries compris) de l'alerte courante.

#### Scenario: Ordre préservé
- **WHEN** les alertes `rule_1` puis `rule_2` sont mises en file
- **THEN** `rule_1` est envoyée avant `rule_2`

#### Scenario: Destination lente
- **WHEN** une destination de l'alerte courante enchaîne les retries
- **THEN** les alertes suivantes restent en file jusqu'à la fin de ces retries

### Requirement: Fan-out parallèle et échecs indépendants
Le système SHALL envoyer chaque alerte à toutes ses destinations en parallèle, MUST rendre le résultat de chaque destination indépendant des autres, et SHALL journaliser chaque résultat séparément : `Notification sent successfully` (niveau info) ou `Failed to send notification after all retries` (niveau error, avec l'erreur, le notifier et la règle).

#### Scenario: Deux destinations
- **WHEN** une règle a pour destinations `mattermost-infra` et `mattermost-ops`
- **THEN** chaque notifier reçoit une requête pour la même alerte

#### Scenario: Échec partiel
- **WHEN** une destination répond en erreur et l'autre avec succès
- **THEN** la destination en succès reçoit bien l'alerte et l'échec de l'autre est journalisé sans affecter la première

### Requirement: Destination absente du registre à l'exécution
Le système MUST, si une destination d'une alerte n'existe pas dans le registre au moment de l'envoi, ignorer cette destination, journaliser l'erreur `Notifier not found in registry (validation should have caught this)` et incrémenter `valerter_notify_errors_total` avec `notifier_type="unknown"`, sans bloquer les autres destinations.

#### Scenario: Nom introuvable
- **WHEN** une alerte référence une destination inconnue du registre
- **THEN** seules les destinations connues reçoivent l'alerte et l'erreur est comptée

### Requirement: Contrat commun de retry et de backoff
Le système SHALL laisser chaque notifier gérer ses propres retries et MUST calculer les délais d'attente par backoff exponentiel `min(base × 2^tentative, max)` (tentative indexée à partir de 0, sans débordement) ; un notifier ne renvoie son résultat au worker qu'après succès ou abandon définitif.

#### Scenario: Progression du backoff
- **WHEN** la base vaut 500 ms et le maximum 5 s
- **THEN** les délais successifs sont 500 ms, 1 s, 2 s, 4 s puis 5 s pour toutes les tentatives suivantes

### Requirement: Client HTTP partagé
Le système SHALL utiliser pour les notifiers HTTP (Mattermost, webhook, Telegram) un client HTTP unique partagé, avec un timeout de 10 s par requête.

#### Scenario: Endpoint muet
- **WHEN** un endpoint de notification n'envoie aucune réponse
- **THEN** la tentative échoue au bout de 10 s et est traitée comme une erreur réseau

### Requirement: Métriques d'envoi par notifier
Le système SHALL, pour chaque envoi, incrémenter `valerter_alerts_sent_total` en cas de succès, et `valerter_notify_errors_total` ainsi que `valerter_alerts_failed_total` en cas d'échec définitif, avec les labels `rule_name`, `vl_source`, `notifier_name` et `notifier_type`.

#### Scenario: Succès Mattermost
- **WHEN** le notifier `mm-ops` délivre une alerte de la règle `cpu` issue de la source `vlprod`
- **THEN** `valerter_alerts_sent_total{rule_name="cpu",vl_source="vlprod",notifier_name="mm-ops",notifier_type="mattermost"}` augmente de 1

### Requirement: Arrêt sans vidage de la file
Le système SHALL, à la réception de SIGTERM ou SIGINT, arrêter le worker dès qu'il n'est plus en train de traiter une alerte, MUST laisser se terminer l'alerte en cours de traitement, et ne vide pas les alertes restant en file, qui sont perdues ; le processus attend la fin du worker au plus 5 s.

#### Scenario: Alertes en attente à l'arrêt
- **WHEN** SIGTERM est reçu alors que trois alertes attendent dans la file et qu'aucune n'est en cours d'envoi
- **THEN** le worker s'arrête sans envoyer ces trois alertes

#### Scenario: Envoi en cours à l'arrêt
- **WHEN** SIGTERM est reçu pendant l'envoi d'une alerte
- **THEN** l'envoi se poursuit et le processus l'attend au plus 5 s avant de terminer
