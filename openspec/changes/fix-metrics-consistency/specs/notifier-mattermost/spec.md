## MODIFIED Requirements

### Requirement: Résolution de webhook_url
Le système SHALL substituer les variables `${NOM}` de `webhook_url` à l'instanciation du notifier et MUST, en cas de variable non définie, échouer avec `invalid notifier '<nom>': webhook_url: undefined environment variable: <NOM>`, l'erreur étant signalée par les logs et le code de sortie du démarrage, sans métrique dédiée.

#### Scenario: Variable non définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL` n'est pas défini
- **THEN** le démarrage échoue avec un message contenant `webhook_url` et `MM_URL`
- **AND** aucune série `valerter_notifier_config_errors_total` n'est émise
