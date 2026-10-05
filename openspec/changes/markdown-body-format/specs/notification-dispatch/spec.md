## ADDED Requirements

### Requirement: Format de sortie des notifiers
Le système SHALL associer à chaque notifier un format de sortie, donné par sa clé optionnelle `format` ou, à défaut, par son type : `markdown` pour Mattermost, `telegram_html` pour Telegram (`plain` si `parse_mode` n'est pas `HTML`), `html` pour l'email, `plain` pour le webhook. Il MUST refuser à l'instanciation (démarrage et `--validate`) un format non accepté par le type, avec `invalid notifier '<nom>': format '<valeur>' is not supported for <type> notifiers (expected <liste>)`.

#### Scenario: Formats par défaut
- **WHEN** quatre notifiers `mattermost`, `telegram` (sans `parse_mode`), `email` et `webhook` sont déclarés sans clé `format`
- **THEN** leurs formats de sortie sont respectivement `markdown`, `telegram_html`, `html` et `plain`

#### Scenario: Format accepté
- **WHEN** un notifier webhook déclare `format: markdown`
- **THEN** le notifier est créé avec le format `markdown`

#### Scenario: Format refusé
- **WHEN** le notifier email `mail` déclare `format: plain`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'mail': format 'plain' is not supported for email notifiers (expected html)`

#### Scenario: Liste des formats acceptés
- **WHEN** un notifier déclare un format hors de la liste de son type
- **THEN** l'erreur liste `markdown` pour Mattermost, `telegram_html, plain` pour Telegram, `html` pour l'email et `plain, markdown, html` pour le webhook

### Requirement: Corps transmis aux notifiers selon le format
Le système SHALL transmettre à chaque notifier, comme corps du message, le `body` rendu tel quel lorsque le template est `body_format: text`, et le rendu du corps Markdown dans le format de sortie du notifier lorsqu'il est `markdown` ; les rendus `html` et `telegram_html` MUST être marqués comme déjà échappés pour les templates de notifier (un `| e` les laisse intacts), les rendus `plain` et `markdown` non. Chaque rendu est calculé au plus une fois par alerte et partagé entre destinations.

#### Scenario: Template texte inchangé
- **WHEN** une alerte d'un template `text` dont le corps vaut `**a** <b>` est routée vers Mattermost, Telegram et un webhook
- **THEN** chaque notifier reçoit exactement `**a** <b>` comme corps, comme sans ce change

#### Scenario: Template Markdown vers plusieurs formats
- **WHEN** une alerte d'un template `markdown` dont le corps vaut `**{{ host }}**` (`host=a_b`) est routée vers Mattermost, Telegram et un webhook par défaut
- **THEN** Mattermost reçoit `**a\_b**`, Telegram `<b>a_b</b>` et le webhook `a_b`

#### Scenario: Rendu calculé une fois
- **WHEN** une alerte `markdown` est routée vers deux notifiers Telegram
- **THEN** le rendu `telegram_html` est calculé une seule fois pour les deux
