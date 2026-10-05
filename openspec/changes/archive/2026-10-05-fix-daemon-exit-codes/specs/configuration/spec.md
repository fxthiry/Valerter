## MODIFIED Requirements

### Requirement: Présence minimale de notifiers, templates et règles
Le système SHALL exiger, après fusion des répertoires `.d/`, au moins un notifier, au moins un template et au moins une règle, dont au moins une règle activée ; ce contrôle fait partie de la validation de la configuration et s'applique donc aussi bien au démarrage qu'en mode `--validate`.

#### Scenario: Aucun notifier
- **WHEN** ni `config.yaml` ni `notifiers.d/` ne définissent de notifier
- **THEN** la validation signale `no notifiers configured: add notifiers in config.yaml or notifiers.d/`, même si la variable d'environnement `MATTERMOST_WEBHOOK` est définie

#### Scenario: Aucun template
- **WHEN** aucun template n'est défini
- **THEN** la validation signale `no templates defined: add templates in config.yaml or templates.d/`

#### Scenario: Aucune règle
- **WHEN** aucune règle n'est définie
- **THEN** la validation signale `no rules defined: add rules in config.yaml or rules.d/`

#### Scenario: Toutes les règles désactivées
- **WHEN** au moins une règle est définie et toutes ont `enabled: false`
- **THEN** la validation signale `all rules are disabled: enable at least one rule in config.yaml or rules.d/`, en plus des autres erreurs éventuelles
- **AND** `valerter --validate` se termine avec le code 1

#### Scenario: Au moins une règle activée
- **WHEN** la configuration contient des règles désactivées et au moins une règle activée (explicitement ou par défaut)
- **THEN** cette erreur n'est pas signalée
