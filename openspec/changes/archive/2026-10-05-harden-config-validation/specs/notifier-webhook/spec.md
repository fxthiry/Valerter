## ADDED Requirements

### Requirement: Rendu d'essai du body_template
Le système MUST, en plus de la vérification syntaxique, effectuer un rendu d'essai du `body_template` à l'instanciation du notifier (démarrage du démon et mode `--validate`), et refuser un template utilisant un filtre, un test ou une fonction inconnu avec un message `invalid notifier '<nom>': body_template render: <détail>`.

#### Scenario: Filtre inconnu
- **WHEN** `body_template` vaut `{"alert": "{{ title | nosuchfilter }}"}`
- **THEN** le démarrage comme `valerter --validate` échouent avec un message contenant `body_template render` et `nosuchfilter`, avant tout envoi

#### Scenario: Filtres intégrés acceptés
- **WHEN** `body_template` vaut `{"alert": {{ title | tojson }}, "rule": "{{ rule_name | upper }}"}`
- **THEN** le notifier est créé sans erreur

### Requirement: Validation de l'URL résolue
Le système MUST, à l'instanciation du notifier et après substitution des variables `${NOM}`, vérifier que `url` est une URL analysable au schéma `http` ou `https`, et refuser de démarrer sinon avec `invalid notifier '<nom>': url: invalid URL: <détail>`, sans répéter l'URL.

#### Scenario: Variable résolue au mauvais schéma
- **WHEN** `url: "${WEBHOOK_URL}"` et `WEBHOOK_URL=ftp://hooks.example.com/SECRET`
- **THEN** le démarrage échoue avec un message contenant `url: invalid URL: unsupported scheme 'ftp'` et ne contenant pas `SECRET`

#### Scenario: Variable résolue non analysable
- **WHEN** `url: "${WEBHOOK_URL}"` et `WEBHOOK_URL=not a url`
- **THEN** le démarrage échoue avec un message contenant `url: invalid URL:`
