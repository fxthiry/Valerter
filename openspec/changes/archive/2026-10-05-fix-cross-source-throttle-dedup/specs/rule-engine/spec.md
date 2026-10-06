## MODIFIED Requirements

### Requirement: État isolé par tâche
Chaque tâche (règle, source) SHALL posséder son propre parser et sa propre connexion au flux ; l'état de throttling est en revanche partagé par toutes les tâches d'une même règle (voir la capacité `throttling`), l'isolation entre sources étant assurée par la clé de throttling par défaut, qui contient le nom de la source.

#### Scenario: Événements identiques sur deux sources
- **WHEN** deux sources émettent le même événement pour une même règle utilisant la clé de throttling par défaut
- **THEN** les deux événements passent le throttling à leur première occurrence et produisent chacun une alerte

#### Scenario: Événements identiques avec une clé commune aux sources
- **WHEN** deux sources émettent le même événement pour une même règle dont `throttle.key` vaut `{{ rule_name }}` avec `count: 1`
- **THEN** une seule alerte est produite

#### Scenario: Défaillance de connexion d'une source
- **WHEN** la connexion de la tâche (règle, `vlprod`) échoue
- **THEN** la tâche (règle, `vldev`) continue de recevoir et de traiter ses lignes avec son propre parser
