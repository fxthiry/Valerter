## ADDED Requirements

### Requirement: Relance après panic non bloquante avec backoff
Le moteur SHALL, lorsqu'une tâche panique, journaliser l'incident, incrémenter `valerter_rule_panics_total{rule_name, vl_source}` puis relancer la tâche du même couple (règle, source) avec la même configuration après un délai croissant (5 s, doublé à chaque panic consécutif, plafonné à 5 min), sans limite du nombre de relances, sauf si l'arrêt est demandé. Le compteur de panics consécutifs d'un couple SHALL repartir de zéro après 10 minutes de fonctionnement sans panic. Le délai de relance MUST NOT suspendre la supervision des autres tâches ni la prise en compte de l'arrêt.

#### Scenario: Panic puis relance
- **WHEN** une tâche panique pour la première fois alors qu'aucun arrêt n'est en cours
- **THEN** le message ERROR « Rule task panicked - CRITICAL » est journalisé avec `rule_name` et `vl_source`
- **AND** le message « Respawning rule-source task after panic delay » est journalisé avec `delay_secs = 5` et `consecutive_panics = 1`
- **AND** après 5 secondes la tâche est relancée et « Rule-source task respawned after panic » est journalisé

#### Scenario: Panics consécutifs
- **WHEN** une tâche relancée panique à nouveau moins de 10 minutes après sa relance
- **THEN** le délai avant la relance suivante est le double du précédent (5 s, 10 s, 20 s, 40 s…), sans jamais dépasser 300 secondes
- **AND** `consecutive_panics` est incrémenté dans le message « Respawning rule-source task after panic delay »

#### Scenario: Remise à zéro après fonctionnement stable
- **WHEN** une tâche relancée fonctionne au moins 10 minutes sans paniquer puis panique
- **THEN** ce panic est traité comme un premier panic : délai de 5 secondes et `consecutive_panics = 1`

#### Scenario: Aucun abandon
- **WHEN** un couple (règle, source) panique un grand nombre de fois consécutives
- **THEN** il est relancé après chaque panic, au plus tard 300 secondes après celui-ci
- **AND** `valerter_rule_panics_total{rule_name, vl_source}` est incrémenté à chaque panic, `valerter_rule_errors_total` ne l'étant pas

#### Scenario: Panic pendant l'arrêt
- **WHEN** une tâche panique et que l'arrêt est demandé avant ou pendant son délai de relance
- **THEN** la tâche n'est pas relancée
- **AND** l'attente de relance est interrompue immédiatement, sans retarder l'arrêt

#### Scenario: Panic d'une tâche inconnue
- **WHEN** une tâche panique sans que son couple (règle, source) puisse être retrouvé
- **THEN** « Rule task panicked but context not found - CRITICAL » est journalisé et `valerter_rule_panics_total{rule_name="unknown", vl_source="unknown"}` est incrémenté, sans relance

#### Scenario: Supervision maintenue pendant le délai
- **WHEN** le moteur attend l'expiration du délai de relance d'un couple
- **THEN** la fin, l'erreur fatale ou le panic d'autres tâches sont traités sans attendre la fin de ce délai
- **AND** une demande d'arrêt est prise en compte immédiatement

#### Scenario: Panics simultanés
- **WHEN** deux couples paniquent à quelques millisecondes d'intervalle
- **THEN** chacun est relancé à l'expiration de son propre délai, les délais n'étant pas cumulés

#### Scenario: Tâche en attente de relance
- **WHEN** toutes les tâches se sont arrêtées sauf une qui attend l'expiration de son délai de relance après panic
- **THEN** elle compte comme active : le moteur ne signale pas la fin inattendue de toutes les tâches et relance cette tâche à l'expiration du délai

## REMOVED Requirements

### Requirement: Relance après panic
**Reason**: Le délai fixe de 5 s bloquait la boucle de supervision (autres tâches non surveillées, arrêt retardé) et les relances n'étaient pas espacées. Remplacé par « Relance après panic non bloquante avec backoff ».
**Migration**: Aucune action de configuration. Les relances restent illimitées ; le délai croît désormais de 5 s à 5 min pour un couple qui panique en boucle. Surveiller `valerter_rule_panics_total` pour être alerté.
