## MODIFIED Requirements

### Requirement: Schéma de configuration Telegram
Le système SHALL accepter un notifier `type: telegram` avec les clés obligatoires `bot_token` (chaîne) et `chat_ids`
(liste de chaînes), et les clés optionnelles `parse_mode` (défaut `HTML`), `disable_notification`,
`disable_web_page_preview` (booléens, non transmis s'ils sont absents), `body_template` et `format` (`telegram_html`
ou `plain`, voir `notification-dispatch`) ; toute clé inconnue MUST être rejetée au chargement.

#### Scenario: Valeurs par défaut
- **WHEN** un notifier déclare seulement `type: telegram`, `bot_token` et `chat_ids`
- **THEN** le notifier est créé avec `parse_mode` `HTML`, sans `disable_notification` ni `disable_web_page_preview`, avec le template de corps par défaut et le format de sortie `telegram_html`

#### Scenario: Clé inconnue rejetée
- **WHEN** le notifier contient une clé non prévue (par exemple `chat_id`)
- **THEN** le chargement de la configuration échoue

### Requirement: Rendu du texte
Le système SHALL rendre le texte une seule fois par alerte avec `body_template`, ou à défaut avec
`<b>{{ title|e }}</b>\n{{ body|e }}`, dans un contexte exposant `title`, `body` (le corps transmis au notifier, voir
« Corps transmis aux notifiers selon le format » de `notification-dispatch`, jamais `email_body_html`), `rule_name`,
`vl_source`, `log_timestamp`, `log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`),
sans échappement automatique : seuls les filtres explicites (`|e`) échappent `<`, `>` et `&`, et ils laissent intact
un corps `telegram_html`, déjà échappé.

#### Scenario: Template par défaut échappé
- **WHEN** aucun `body_template` n'est configuré et que le corps de l'alerte contient `a < b & c`
- **THEN** le texte envoyé contient `a &lt; b &amp; c` après le titre en gras

#### Scenario: Template personnalisé non échappé
- **WHEN** `body_template: "{{ body }}"` est configuré et que le corps contient `<b>gras</b>`
- **THEN** le texte envoyé contient `<b>gras</b>` tel quel

#### Scenario: Échec de rendu à l'envoi
- **WHEN** le rendu du template échoue pour une alerte
- **THEN** aucune requête n'est envoyée et le notifier renvoie une erreur `template error: ...`

#### Scenario: Balisage dans le template et valeurs échappées
- **WHEN** `body_template: "<b>{{ title|e }}</b>\n<code>{{ log.host|e }}</code>"` est configuré, que le titre vaut `Disk` et que l'événement porte `host=<web&01>`
- **THEN** le texte envoyé vaut `<b>Disk</b>\n<code>&lt;web&amp;01&gt;</code>`

#### Scenario: Corps Markdown avec le template par défaut
- **WHEN** aucun `body_template` n'est configuré et qu'une alerte de titre `Disk` d'un template `markdown` a pour corps `**{{ host }}** < 10%` avec `host=a_b`
- **THEN** le texte envoyé vaut `<b>Disk</b>\n<b>a_b</b> &lt; 10%`

## ADDED Requirements

### Requirement: Cohérence entre format et parse_mode
Le système MUST refuser à l'instanciation (démarrage et `--validate`) un notifier Telegram dont `format` vaut `telegram_html` alors que `parse_mode` n'est pas `HTML`, avec `invalid notifier '<nom>': format 'telegram_html' requires parse_mode HTML` ; sans clé `format`, un notifier en `parse_mode` `MarkdownV2` ou `Markdown` reçoit le format `plain`.

#### Scenario: Incohérence refusée
- **WHEN** le notifier `tg` déclare `parse_mode: MarkdownV2` et `format: telegram_html`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': format 'telegram_html' requires parse_mode HTML`

#### Scenario: Défaut en MarkdownV2
- **WHEN** un notifier déclare `parse_mode: MarkdownV2` sans `format` et reçoit une alerte d'un template `markdown` dont le corps vaut `**{{ v }}**` avec `v=1.5`
- **THEN** la variable `body` de son `body_template` vaut `1.5`, que `{{ body | mdv2_escape }}` transforme en `1\.5`
