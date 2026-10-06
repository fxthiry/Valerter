## MODIFIED Requirements

### Requirement: Rendu du sujet et du corps
Le système SHALL rendre, une seule fois par alerte, le sujet avec `subject_template` et le corps avec le template de
corps, dans un contexte exposant `title`, `body`, `rule_name`, `vl_source`, `accent_color`, `log_timestamp`,
`log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`) ; dans le corps, `body` MUST
valoir le `email_body_html` rendu (à défaut le `body` du message), inséré tel quel sans échappement, tandis que les
autres variables, y compris les valeurs lues dans `log`, sont échappées en HTML automatiquement.

#### Scenario: Corps HTML inséré sans échappement
- **WHEN** l'alerte a `email_body_html` égal à `<p>Erreur</p>` et le template de corps contient `{{ body }}`
- **THEN** le corps de l'email contient `<p>Erreur</p>` non échappé, sans qu'un filtre `| safe` soit nécessaire

#### Scenario: Titre échappé dans le corps
- **WHEN** le titre de l'alerte contient `<script>` et le template de corps contient `{{ title }}`
- **THEN** le corps de l'email contient `&lt;script&gt;`

#### Scenario: Échec de rendu à l'envoi
- **WHEN** le rendu du sujet ou du corps échoue pour une alerte
- **THEN** aucun email n'est envoyé et le notifier renvoie une erreur `template error: ...`

#### Scenario: Champ du log échappé dans le corps
- **WHEN** le template de corps contient `<td>{{ log.host }}</td>` et que l'événement porte `host=<b>x</b>`
- **THEN** le corps de l'email contient `<td>&lt;b&gt;x&lt;&#x2f;b&gt;</td>`

#### Scenario: Champ du log dans le sujet
- **WHEN** `subject_template: "[{{ log.severity | upper }}] {{ title }}"` est configuré, que l'événement porte `severity=crit` et que le titre vaut `Disk`
- **THEN** le sujet vaut `[CRIT] Disk`
