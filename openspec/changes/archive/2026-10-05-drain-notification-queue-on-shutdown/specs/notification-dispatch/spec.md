## ADDED Requirements

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

## REMOVED Requirements

### Requirement: Arrêt sans vidage de la file
**Reason**: Ce comportement perdait silencieusement, à chaque arrêt ou redémarrage du service, toutes les alertes en attente et coupait au bout de 5 s l'alerte en cours d'envoi. Il est remplacé par le vidage borné de la file à l'arrêt.
**Migration**: Aucune action de configuration. Un arrêt peut désormais durer jusqu'à environ 20 s de plus lorsque des alertes sont en attente ; les orchestrateurs dont le délai d'arrêt est inférieur à 30 s (par exemple `docker stop`, 10 s par défaut) doivent l'allonger pour bénéficier du vidage. Un second SIGTERM/SIGINT force l'arrêt immédiat.
