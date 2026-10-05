## ADDED Requirements

### Requirement: Validation et normalisation de parse_mode
Le système MUST n'accepter pour `parse_mode` que `HTML`, `MarkdownV2` ou `Markdown`, sans tenir compte de la casse, et SHALL transmettre la forme canonique correspondante ; toute autre valeur MUST être refusée à l'instanciation du notifier (démarrage du démon et mode `--validate`), avec `invalid notifier '<nom>': parse_mode '<valeur>' is not supported (expected HTML, MarkdownV2 or Markdown)`. Le défaut reste `HTML`.

#### Scenario: MarkdownV2
- **WHEN** `parse_mode: MarkdownV2` est configuré
- **THEN** chaque requête contient `"parse_mode": "MarkdownV2"`

#### Scenario: Casse normalisée
- **WHEN** `parse_mode: html` est configuré
- **THEN** chaque requête contient `"parse_mode": "HTML"`

#### Scenario: Valeur inconnue
- **WHEN** `parse_mode: Markdown2` est configuré sur le notifier `tg`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': parse_mode 'Markdown2' is not supported (expected HTML, MarkdownV2 or Markdown)` et aucune requête n'est envoyée

### Requirement: Rendu d'essai du body_template
Le système MUST, en plus de la vérification syntaxique, effectuer un rendu d'essai du `body_template` à l'instanciation du notifier (démarrage du démon et mode `--validate`), et refuser un template utilisant un filtre, un test ou une fonction inconnu avec un message `invalid notifier '<nom>': body_template render: <détail>`.

#### Scenario: Filtre inconnu
- **WHEN** `body_template: "<b>{{ title | nosuchfilter }}</b>"` est configuré sur le notifier `tg`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': body_template render: <détail mentionnant nosuchfilter>`

#### Scenario: Template avec échappement
- **WHEN** `body_template: "<b>{{ title | e }}</b>\n{{ body | e }}"` est configuré
- **THEN** le notifier est créé sans erreur

## REMOVED Requirements

### Requirement: parse_mode transmis tel quel
**Reason**: Une valeur erronée (`Markdown2`, `markdown_v2`…) était transmise sans contrôle et l'API Bot répondait HTTP 400 à chaque alerte. Remplacé par « Validation et normalisation de parse_mode ».
**Migration**: Utiliser `HTML`, `MarkdownV2` ou `Markdown` (casse libre) ; toute autre valeur est refusée au démarrage et par `valerter --validate`.
