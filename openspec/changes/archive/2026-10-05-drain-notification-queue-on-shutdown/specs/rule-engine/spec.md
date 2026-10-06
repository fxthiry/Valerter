## MODIFIED Requirements

### Requirement: Arrêt gracieux sur signal
Le démon SHALL déclencher l'arrêt gracieux à la réception de SIGTERM ou SIGINT (sous Unix ; Ctrl+C uniquement sur les autres plateformes), en annulant toutes les tâches de règles, puis, une fois toutes ces tâches arrêtées, en laissant au worker de notifications au plus 20 secondes pour vider la file et au serveur de métriques au plus 2 secondes pour se terminer, avant de quitter avec le code 0. Un second SIGTERM ou SIGINT reçu pendant l'arrêt MUST provoquer la sortie immédiate du processus avec le code 1.

#### Scenario: Réception de SIGTERM
- **WHEN** le démon reçoit SIGTERM
- **THEN** les logs « Received SIGTERM », « Initiating graceful shutdown », « Shutdown signal received, aborting all rules », « All rule tasks stopped », « Waiting for notification worker to drain queue... » puis « valerter shutdown complete » sont émis
- **AND** le processus se termine avec le code 0

#### Scenario: Réception de SIGINT
- **WHEN** le démon reçoit SIGINT
- **THEN** le log « Received SIGINT (Ctrl+C) » est émis et la même séquence d'arrêt est suivie

#### Scenario: Alertes en file à l'arrêt
- **WHEN** l'arrêt est demandé alors que des alertes attendent dans la file
- **THEN** le vidage de la file ne commence qu'après « All rule tasks stopped »
- **AND** le worker termine l'alerte en cours et envoie les alertes restantes dans la limite de 20 secondes, et le processus se termine avec le code 0 même si ce délai expire

#### Scenario: Second signal
- **WHEN** un second SIGTERM ou SIGINT est reçu pendant l'arrêt, quelle qu'en soit la phase (arrêt des tâches, vidage de la file ou attente du serveur de métriques)
- **THEN** le log WARN « Second shutdown signal received, forcing immediate exit » est émis
- **AND** le processus se termine immédiatement avec le code 1, sans attendre la fin des envois en cours ni le vidage de la file
