## ADDED Requirements

### Requirement: Résolution des variables d'environnement du body_template
Le système SHALL substituer les motifs `${NOM}` de la source du `body_template` par la valeur de la variable d'environnement à l'instanciation du notifier, avant la vérification de syntaxe, et MUST refuser de démarrer avec `invalid notifier '<nom>': body_template: undefined environment variable: <NOM>` si une variable est absente ; les valeurs issues des événements ne sont jamais soumises à cette substitution, et la source résolue MUST NOT apparaître dans la représentation de débogage du notifier ni dans les journaux.

#### Scenario: Clé de routage depuis l'environnement
- **WHEN** `body_template` contient `"routing_key": "${ROUTING_KEY}"` et `ROUTING_KEY=abc123`
- **THEN** le corps envoyé contient `"routing_key": "abc123"`

#### Scenario: Variable non définie
- **WHEN** `body_template` référence `${ROUTING_KEY}` et cette variable n'est pas définie
- **THEN** le démarrage échoue avec un message contenant `body_template` et `ROUTING_KEY`

#### Scenario: Valeur résolue non exposée
- **WHEN** un notifier dont le `body_template` a été résolu avec un secret est affiché en débogage ou journalise une erreur
- **THEN** la sortie ne contient pas la valeur résolue

## MODIFIED Requirements

### Requirement: Rendu du body_template
Le système SHALL rendre le `body_template` (après résolution des variables d'environnement de sa source) avec les seules variables `title`, `body`, `rule_name`, `vl_source`, `log_timestamp` et `log_timestamp_formatted`, sans échappement automatique des valeurs, une variable inconnue étant rendue comme une chaîne vide, et MUST envoyer le résultat tel quel comme corps de la requête. Le filtre `tojson` MUST être disponible et produire une valeur JSON valide (chaîne entre guillemets, caractères spéciaux échappés), afin qu'un template comme `{"text": {{ body | tojson }}}` produise toujours du JSON valide.

#### Scenario: Template personnalisé
- **WHEN** `body_template` vaut `{"title": "{{ title }}", "rule": "{{ rule_name }}"}` pour la règle `test_rule` de titre `Test Alert`
- **THEN** le corps envoyé est `{"title": "Test Alert", "rule": "test_rule"}`

#### Scenario: Pas de substitution d'environnement dans le template
- **WHEN** le `body` d'une alerte contient le texte `${ROUTING_KEY}` et le template insère `{{ body }}`
- **THEN** le texte `${ROUTING_KEY}` est envoyé littéralement : la substitution des variables d'environnement ne s'applique qu'à la source du template, jamais aux valeurs rendues

#### Scenario: Valeur insérée avec tojson
- **WHEN** `body_template` vaut `{"text": {{ body | tojson }}}` et que le corps de l'alerte contient un guillemet, une barre oblique inverse et un saut de ligne
- **THEN** le corps envoyé est un JSON valide dont le champ `text` vaut exactement le corps de l'alerte
