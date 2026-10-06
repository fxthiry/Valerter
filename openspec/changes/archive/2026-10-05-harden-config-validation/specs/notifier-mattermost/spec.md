## ADDED Requirements

### Requirement: Validation de webhook_url résolue
Le système MUST, à l'instanciation du notifier et après substitution des variables `${NOM}`, vérifier que `webhook_url` est une URL analysable au schéma `http` ou `https`, et refuser de démarrer sinon avec `invalid notifier '<nom>': webhook_url: invalid URL: <détail>`, sans répéter l'URL.

#### Scenario: Variable résolue au mauvais schéma
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=htps://mm.example.com/hooks/SECRET`
- **THEN** le démarrage échoue avec un message contenant `webhook_url: invalid URL:` et ne contenant pas `SECRET`

#### Scenario: Variable résolue valide
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=https://mm.example.com/hooks/abc`
- **THEN** le notifier est créé et envoie vers cette URL
