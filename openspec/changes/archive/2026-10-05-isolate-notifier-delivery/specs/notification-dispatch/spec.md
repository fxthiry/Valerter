# Spec Delta

## MODIFIED Requirements

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
Le système MUST, si une destination d'une alerte n'existe pas dans le registre au moment de la mise en file, ignorer cette destination, journaliser l'erreur `Notifier not found in registry (validation should have caught this)` et incrémenter `valerter_notify_errors_total` avec `notifier_type="unknown"`, sans empêcher la mise en file pour les autres destinations.

#### Scenario: Nom introuvable
- **WHEN** une alerte référence une destination inconnue du registre
- **THEN** seules les destinations connues reçoivent l'alerte et l'erreur est comptée

## ADDED Requirements

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

## REMOVED Requirements

### Requirement: Worker unique et traitement séquentiel FIFO
**Reason**: Un worker unique séquentiel laisse une seule destination lente ou indisponible bloquer la livraison vers toutes les autres (environ 31,5 s par alerte pour un endpoint HTTP muet).
**Migration**: Remplacé par « Livraison isolée par destination » : l'ordre FIFO est garanti par destination et non plus globalement. Aucun changement de configuration n'est nécessaire.
