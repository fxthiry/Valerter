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
Le système SHALL remplacer, à l'instanciation des notifiers, chaque motif `${NOM}` (NOM conforme à `[A-Za-z_][A-Za-z0-9_]*`) des champs secrets par la valeur de la variable d'environnement correspondante, et MUST échouer si une variable est absente avec un message listant toutes les variables manquantes (`undefined environment variable: A` ou `undefined environment variables: A, B`) préfixé par `invalid notifier '<nom>': <champ>: invalid configuration: `.

#### Scenario: Variable définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=https://mm.example.com/hooks/x`
- **THEN** le notifier envoie vers `https://mm.example.com/hooks/x`

#### Scenario: Variables manquantes
- **WHEN** un champ secret vaut `${UNDEFINED_A} and ${UNDEFINED_B}` et aucune des deux n'est définie
- **THEN** l'erreur mentionne `invalid configuration: undefined environment variables: UNDEFINED_A, UNDEFINED_B`

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
Le système SHALL transmettre à chaque notifier, pour chaque alerte, le message rendu (`title`, `body`, `email_body_html` optionnel, `accent_color` optionnel), le nom de la règle, le nom de la source VictoriaLogs (`vl_source`), la liste des destinations de la règle, le canal Mattermost optionnel de la règle (`notify.mattermost_channel`), l'horodatage brut du log (`log_timestamp`, champ `_time` de l'événement) et sa version lisible (`log_timestamp_formatted`, format `DD/MM/YYYY HH:MM:SS TZ` dans le fuseau `timestamp_timezone`, secondes tronquées).

#### Scenario: Horodatage formaté
- **WHEN** l'événement a `_time = 2026-01-15T10:00:00Z` et `timestamp_timezone: Europe/Paris`
- **THEN** `log_timestamp` vaut `2026-01-15T10:00:00Z` et `log_timestamp_formatted` vaut `15/01/2026 11:00:00 CET`

#### Scenario: Champ _time absent
- **WHEN** l'événement ne contient pas de champ `_time`
- **THEN** un avertissement `Missing _time field in log, using current time` est journalisé et l'heure courante RFC 3339 est utilisée comme `log_timestamp`

#### Scenario: Horodatage non analysable
- **WHEN** `_time` n'est pas un horodatage RFC 3339 valide
- **THEN** `log_timestamp_formatted` reprend la valeur brute inchangée

#### Scenario: Canal Mattermost de la règle transmis
- **WHEN** une règle définit `notify.mattermost_channel: alerts`
- **THEN** chaque alerte de cette règle transporte le canal `alerts`, et une règle sans cette clé transporte un canal absent

### Requirement: File de notification bornée et non bloquante
Le système SHALL déposer chaque alerte dans une file asynchrone propre à chacune de ses destinations, de capacité exacte 100 alertes par destination (non configurable, sans arrondi), MUST ne jamais bloquer le producteur, et SHALL renvoyer l'erreur `notification queue closed` lorsque la livraison des notifications est arrêtée ; le moteur journalise alors `Failed to send to notification queue` et l'alerte est perdue.

#### Scenario: Envoi non bloquant
- **WHEN** une règle produit une alerte alors que le worker de chacune de ses destinations est occupé
- **THEN** l'alerte est mise en file immédiatement pour chaque destination et la lecture du flux de logs continue

#### Scenario: Capacité exacte par destination
- **WHEN** 100 alertes destinées au seul notifier `mm-ops` sont en attente et qu'une 101e est mise en file
- **THEN** exactement une alerte, la plus ancienne, est abandonnée pour `mm-ops`
- **AND** les 100 alertes les plus récentes restent en attente

#### Scenario: Aucun consommateur
- **WHEN** une alerte est envoyée alors que la livraison des notifications s'est arrêtée
- **THEN** l'envoi échoue avec `notification queue closed`

### Requirement: Politique drop-oldest en cas de saturation
Le système MUST, lorsque la file d'une destination est pleine, écraser l'alerte la plus ancienne non encore consommée de cette seule destination au profit de la nouvelle, incrémenter pour chaque alerte écrasée le compteur global `valerter_alerts_dropped_total` et le compteur `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}`, puis, lorsque le worker de la destination reprend une alerte, journaliser une seule fois l'avertissement `Queue full, dropping <N> oldest alerts` avec les champs `dropped_count` et `notifier`.

#### Scenario: Rafale dépassant la capacité
- **WHEN** plus d'alertes que la capacité d'une destination sont produites pour elle avant que son worker ne les consomme
- **THEN** les plus anciennes sont abandonnées, les plus récentes sont conservées
- **AND** `valerter_alerts_dropped_total` et `valerter_destination_alerts_dropped_total` de cette destination augmentent du nombre d'alertes perdues

#### Scenario: Saturation limitée à une destination
- **WHEN** une règle a pour destinations `webhook-down`, dont l'endpoint ne répond plus, et `mm-ops`, sain, et qu'elle produit 150 alertes
- **THEN** seules des alertes destinées à `webhook-down` sont abandonnées
- **AND** `mm-ops` reçoit les 150 alertes

### Requirement: Jauge de taille de file
Le système SHALL publier la jauge globale `valerter_queue_size`, égale à la somme des alertes en attente dans toutes les files de destination, et la jauge `valerter_destination_queue_size{notifier_name, notifier_type}` pour chaque destination, toutes initialisées à 0, et les mettre à jour après chaque mise en file, après chaque alerte prise en charge par un worker et après chaque abandon.

#### Scenario: Mise en file
- **WHEN** deux alertes de la règle `cpu`, dont les destinations sont `mm-ops` et `mm-infra`, sont en attente de traitement
- **THEN** `valerter_destination_queue_size` vaut 2 pour `mm-ops` et 2 pour `mm-infra`
- **AND** `valerter_queue_size` vaut 4

### Requirement: Fan-out parallèle et échecs indépendants
Le système SHALL livrer chaque alerte à toutes ses destinations en parallèle, chaque destination la recevant par sa propre file, MUST rendre le résultat et le délai de livraison de chaque destination indépendants des autres, et SHALL journaliser chaque résultat séparément : `Notification sent successfully` (niveau info) ou `Failed to send notification after all retries` (niveau error, avec l'erreur, le notifier et la règle).

#### Scenario: Deux destinations
- **WHEN** une règle a pour destinations `mattermost-infra` et `mattermost-ops`
- **THEN** chaque notifier reçoit une requête pour la même alerte

#### Scenario: Échec partiel
- **WHEN** une destination répond en erreur et l'autre avec succès
- **THEN** la destination en succès reçoit bien l'alerte et l'échec de l'autre est journalisé sans affecter la première

#### Scenario: Destination lente
- **WHEN** l'endpoint de `webhook-down` n'envoie aucune réponse et qu'une alerte a pour destinations `webhook-down` et `mm-ops`
- **THEN** `mm-ops` reçoit l'alerte sans attendre la fin des tentatives vers `webhook-down`

### Requirement: Destination absente du registre à l'exécution
Le système MUST, si une destination d'une alerte n'existe pas dans le registre au moment de la mise en file, ignorer cette destination, journaliser l'erreur `Notifier not found in registry (validation should have caught this)` et compter l'alerte comme un échec définitif pour cette destination : `valerter_notify_errors_total` et `valerter_alerts_failed_total` sont incrémentés une fois, avec les labels `rule_name`, `vl_source`, `notifier_name` (le nom introuvable) et `notifier_type="unknown"`, sans empêcher la mise en file pour les autres destinations.

#### Scenario: Nom introuvable
- **WHEN** une alerte référence une destination inconnue du registre
- **THEN** seules les destinations connues reçoivent l'alerte et l'erreur est comptée

#### Scenario: Compteurs de l'échec
- **WHEN** une alerte de la règle `r` issue de la source `s` référence la destination introuvable `ghost`
- **THEN** `valerter_notify_errors_total{rule_name="r",vl_source="s",notifier_name="ghost",notifier_type="unknown"}` et `valerter_alerts_failed_total` avec les mêmes labels valent 1

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

### Requirement: Livraison isolée par destination
Le système SHALL associer à chaque notifier du registre un worker de livraison dédié qui traite les alertes de sa file une par une dans leur ordre d'arrivée, l'alerte suivante n'étant prise qu'une fois terminé l'envoi (retries compris) de l'alerte courante, et MUST faire progresser les workers des différentes destinations indépendamment les uns des autres.

#### Scenario: Ordre préservé par destination
- **WHEN** les alertes `rule_1` puis `rule_2` sont mises en file pour la destination `mm-ops`
- **THEN** `mm-ops` reçoit `rule_1` avant `rule_2`

#### Scenario: Destination indisponible sans effet sur les autres
- **WHEN** l'endpoint de `webhook-down` enchaîne les timeouts et que des alertes destinées uniquement à `mm-ops` sont mises en file ensuite
- **THEN** ces alertes sont livrées à `mm-ops` sans attendre la fin des retries vers `webhook-down`

#### Scenario: Retries d'une destination
- **WHEN** une destination enchaîne les retries sur son alerte courante
- **THEN** les alertes suivantes de cette même destination restent dans sa file jusqu'à la fin de ces retries

### Requirement: Panique d'un notifier isolée
Le système MUST intercepter une panique survenant pendant l'envoi d'une alerte vers une destination, la journaliser au niveau error avec le message `Notifier panicked while sending alert` et les champs `notifier` et `rule_name`, la compter dans `valerter_notify_errors_total` et `valerter_alerts_failed_total` de cette destination, puis poursuivre avec l'alerte suivante de cette destination.

#### Scenario: Panique pendant un envoi
- **WHEN** le notifier `webhook-x` panique pendant l'envoi d'une alerte de la règle `cpu`
- **THEN** l'erreur `Notifier panicked while sending alert` est journalisée et comptée pour `webhook-x`
- **AND** l'alerte suivante de `webhook-x` est envoyée normalement
- **AND** les autres destinations continuent de recevoir leurs alertes

### Requirement: Vidage borné de la file à l'arrêt
Le système SHALL, lors d'un arrêt gracieux et une fois les tâches de règles arrêtées, laisser se terminer les envois en cours puis envoyer toutes les alertes restant en file, dans leur ordre d'arrivée pour une même destination et avec le contrat habituel de retry, jusqu'à ce que la file soit vide, MUST borner ce vidage à 20 secondes (délai fixe, non configurable) et SHALL terminer le vidage sans attendre dès que la file est vide.

#### Scenario: Alertes en attente à l'arrêt
- **WHEN** SIGTERM est reçu alors que trois alertes attendent dans la file et que leurs destinations répondent normalement
- **THEN** les trois alertes sont envoyées, dans leur ordre d'arrivée pour chaque destination, avant la fin du processus

#### Scenario: Envoi en cours à l'arrêt
- **WHEN** SIGTERM est reçu pendant l'envoi d'une alerte
- **THEN** cet envoi se poursuit, retries compris, dans la limite du délai de vidage

#### Scenario: File vide à l'arrêt
- **WHEN** SIGTERM est reçu alors qu'aucune alerte n'est en file ni en cours d'envoi
- **THEN** le vidage se termine immédiatement, sans attendre le délai de 20 secondes

#### Scenario: Aucune nouvelle alerte pendant le vidage
- **WHEN** le vidage de la file a commencé
- **THEN** plus aucune tâche de règle ne dépose d'alerte dans la file

#### Scenario: Destination muette pendant le vidage
- **WHEN** une alerte en file cible un endpoint qui ne répond jamais et que d'autres alertes la suivent
- **THEN** le vidage est interrompu au bout de 20 secondes et le processus poursuit son arrêt

### Requirement: Journalisation de l'issue du vidage
Le système SHALL journaliser au début du vidage le nombre d'alertes en file (`Waiting for notification worker to drain queue...`, champ `queued`), puis soit `Notification queue drained` (niveau info) lorsque la file a été entièrement traitée, soit, à l'expiration du délai, l'avertissement `Shutdown drain timeout reached, alerts not delivered` avec le champ `undelivered` égal au nombre d'alertes encore en file (toutes destinations confondues), les envois interrompus n'y étant pas comptés.

#### Scenario: Vidage complet
- **WHEN** toutes les alertes en file ont été traitées avant le délai
- **THEN** le log `Notification queue drained` est émis

#### Scenario: Délai dépassé
- **WHEN** le délai de 20 secondes expire alors que quatre alertes sont encore en file
- **THEN** le log WARN `Shutdown drain timeout reached, alerts not delivered` est émis avec `undelivered = 4`
