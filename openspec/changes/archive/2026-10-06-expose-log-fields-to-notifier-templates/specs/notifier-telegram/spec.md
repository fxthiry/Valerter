## MODIFIED Requirements

### Requirement: Rendu du texte
Le système SHALL rendre le texte une seule fois par alerte avec `body_template`, ou à défaut avec
`<b>{{ title|e }}</b>\n{{ body|e }}`, dans un contexte exposant `title`, `body` (le `body` du message, jamais
`email_body_html`), `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted` et `log` (champs de
l'événement, voir `message-templating`), sans échappement automatique : seuls les filtres explicites (`|e`) échappent
`<`, `>` et `&`.

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
