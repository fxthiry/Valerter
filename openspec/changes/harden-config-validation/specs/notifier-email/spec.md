## ADDED Requirements

### Requirement: Rendu d'essai du template de corps
Le système MUST, à l'instanciation du notifier, effectuer un rendu d'essai du template de corps retenu (`body_template_file`, `body_template` ou template intégré) après sa vérification syntaxique, et refuser la configuration si le template utilise un filtre, un test ou une fonction inconnu, avec `invalid notifier '<nom>': body_template render: <détail>` ; ce contrôle s'exécute au démarrage du démon comme en mode `--validate` (construction des notifiers du pré-vol) et n'est pas dupliqué dans la validation de la configuration.

#### Scenario: Filtre inconnu dans body_template_file
- **WHEN** `body_template_file` désigne un fichier contenant `{{ body | nosuchfilter }}`
- **THEN** le démarrage échoue avec un message contenant `body_template render` et `nosuchfilter`

#### Scenario: Filtre inconnu dans body_template en ligne
- **WHEN** `valerter --validate` est lancé sur une configuration dont le notifier email `<nom>` déclare `body_template: <p>{{ title | nosuchfilter }}</p>` sans `body_template_file`
- **THEN** l'erreur `invalid notifier '<nom>': body_template render: <détail mentionnant nosuchfilter>` est journalisée sous `Notifier configuration error` et le code de sortie est 1

#### Scenario: Template intégré
- **WHEN** ni `body_template` ni `body_template_file` n'est défini
- **THEN** le rendu d'essai du template intégré réussit et le notifier est créé
