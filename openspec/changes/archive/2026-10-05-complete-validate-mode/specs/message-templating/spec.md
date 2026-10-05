## MODIFIED Requirements

### Requirement: Corps HTML obligatoire pour les destinations email
Le système MUST refuser de démarrer le démon lorsqu'une règle activée a au moins une destination de type email et que son template ne définit pas `email_body_html`, avec l'erreur `template '<t>' requires email_body_html field when used with email destination '<dest>' (rule '<r>')` puis l'échec `Email template validation failed: <n> errors` ; cette vérification est également effectuée par `--validate`, qui se termine alors avec le code 1.

#### Scenario: Template sans corps HTML vers un email
- **WHEN** la règle activée `r` utilise le template `t` sans `email_body_html` et la destination email `ops-mail`
- **THEN** le démarrage échoue avec `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')`

#### Scenario: Règle désactivée
- **WHEN** la même règle est désactivée
- **THEN** aucune erreur n'est levée pour ce template

#### Scenario: Détection par --validate
- **WHEN** `valerter --validate` est lancé sur la configuration de la règle activée `r` ci-dessus
- **THEN** l'erreur `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')` est journalisée et le code de sortie est 1
