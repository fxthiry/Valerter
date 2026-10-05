## MODIFIED Requirements

### Requirement: Résolution de l'URL
Le système SHALL substituer les variables `${NOM}` de `url` à l'instanciation du notifier et MUST, en cas de variable non définie, échouer avec `invalid notifier '<nom>': url: invalid configuration: undefined environment variable: <NOM>`.

#### Scenario: URL depuis l'environnement
- **WHEN** `url: "${WEBHOOK_URL}"` et `WEBHOOK_URL=https://resolved.example.com/hook`
- **THEN** les alertes sont envoyées vers `https://resolved.example.com/hook`

#### Scenario: Variable d'URL non définie
- **WHEN** `url: "${WEBHOOK_URL}"` et `WEBHOOK_URL` n'est pas définie
- **THEN** le démarrage échoue avec `invalid notifier '<nom>': url: invalid configuration: undefined environment variable: WEBHOOK_URL`

### Requirement: Validation du body_template au démarrage
Le système MUST vérifier la syntaxe Jinja du `body_template` à l'instanciation du notifier et refuser de démarrer en cas d'erreur avec `invalid notifier '<nom>': body_template: <détail>`, où `<détail>` est le message d'erreur du moteur de templates.

#### Scenario: Template mal formé
- **WHEN** `body_template` contient `{{ title`
- **THEN** le démarrage échoue avec un message commençant par `invalid notifier '<nom>': body_template: ` suivi de l'erreur de syntaxe

### Requirement: Résolution des variables d'environnement du body_template
Le système SHALL substituer les motifs `${NOM}` de la source du `body_template` par la valeur de la variable d'environnement à l'instanciation du notifier, avant la vérification de syntaxe, et MUST refuser de démarrer avec `invalid notifier '<nom>': body_template: invalid configuration: undefined environment variable: <NOM>` si une variable est absente ; les valeurs issues des événements ne sont jamais soumises à cette substitution, et la source résolue MUST NOT apparaître dans la représentation de débogage du notifier ni dans les journaux, à une exception près : le message d'une erreur de syntaxe du template résolu peut citer un fragment de la source (cas d'une valeur substituée contenant `{{`, `{%` ou un caractère qui casse la syntaxe). Un `${...}` littéral SHALL pouvoir être produit en écrivant `{{ '$' }}{NOM}`, que la substitution ne reconnaît pas et que le rendu restitue en `${NOM}`.

#### Scenario: Clé de routage depuis l'environnement
- **WHEN** `body_template` contient `"routing_key": "${ROUTING_KEY}"` et `ROUTING_KEY=abc123`
- **THEN** le corps envoyé contient `"routing_key": "abc123"`

#### Scenario: Variable non définie
- **WHEN** `body_template` référence `${ROUTING_KEY}` et cette variable n'est pas définie
- **THEN** le démarrage échoue avec un message contenant `body_template` et `ROUTING_KEY`

#### Scenario: Valeur résolue non exposée
- **WHEN** un notifier dont le `body_template` a été résolu avec un secret est affiché en débogage ou journalise une erreur
- **THEN** la sortie ne contient pas la valeur résolue

#### Scenario: Placeholder littéral
- **WHEN** `body_template` contient `"note": "{{ '$' }}{NOT_A_VAR}"` et `NOT_A_VAR` n'est pas définie
- **THEN** le notifier est créé et le corps envoyé contient `"note": "${NOT_A_VAR}"`
