## MODIFIED Requirements

### Requirement: Schéma de configuration email
Le système SHALL accepter un notifier `type: email` avec les clés obligatoires `smtp.host` (chaîne), `smtp.port`
(entier 16 bits), `from`, `to` (liste) et `subject_template`, et les clés optionnelles `smtp.username`,
`smtp.password`, `smtp.tls` (défaut `starttls`), `smtp.tls_verify` (défaut `true`), `body_template`,
`body_template_file` et `format` (seule valeur acceptée : `html`, voir `notification-dispatch`) ; toute clé inconnue
dans le notifier ou dans `smtp` MUST être rejetée au chargement.

#### Scenario: Configuration minimale acceptée
- **WHEN** un notifier déclare `type: email`, `smtp.host`, `smtp.port`, `from`, `to` et `subject_template` seulement
- **THEN** le notifier est créé avec `tls: starttls`, `tls_verify: true`, sans authentification et avec le template de corps intégré

#### Scenario: Clé inconnue rejetée
- **WHEN** la section `smtp` contient une clé non prévue (par exemple `timeout`)
- **THEN** le chargement de la configuration échoue

#### Scenario: Clé obligatoire manquante
- **WHEN** `subject_template` est absent
- **THEN** le chargement de la configuration échoue

### Requirement: Rendu du sujet et du corps
Le système SHALL rendre, une seule fois par alerte, le sujet avec `subject_template` et le corps avec le template de
corps, dans un contexte exposant `title`, `body`, `rule_name`, `vl_source`, `accent_color`, `log_timestamp`,
`log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`) ; dans le sujet, `body` vaut le
corps d'un template `text` tel quel, ou le rendu `plain` d'un template `markdown` ; dans le corps, `body` MUST valoir,
par priorité, le `email_body_html` rendu, sinon le rendu `html` d'un template `markdown`, inséré tel quel sans
échappement, sinon le `body` du message échappé en HTML, tandis que les autres variables, y compris les valeurs lues
dans `log`, sont échappées en HTML automatiquement.

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

#### Scenario: Corps Markdown sans email_body_html
- **WHEN** une alerte d'un template `markdown` sans `email_body_html` a pour corps `**{{ host }}**` avec `host=<x>`
- **THEN** le corps de l'email contient `<p><strong>&lt;x&gt;</strong></p>`

#### Scenario: email_body_html prioritaire sur le rendu Markdown
- **WHEN** une alerte d'un template `markdown` définit aussi `email_body_html` égal à `<p>custom</p>`
- **THEN** le corps de l'email contient `<p>custom</p>` et pas le rendu `html` du corps Markdown

#### Scenario: Corps texte échappé
- **WHEN** une alerte d'un template `text` sans `email_body_html` (message de repli) a pour corps `Template render failed: <x>`
- **THEN** le corps de l'email contient `Template render failed: &lt;x&gt;`

### Requirement: Exigence de email_body_html au démarrage
Le système MUST refuser de démarrer lorsqu'une règle activée a au moins une destination de type `email` et que son
template de message (s'il existe), de `body_format` `text`, ne définit pas `email_body_html`, en journalisant pour
chaque cas `template '<template>' requires email_body_html field when used with email destination(s) '<nom>' (rule '<règle>')`
puis en échouant avec `Email template validation failed: <n> errors` ; un template `body_format: markdown` est
dispensé de cette exigence.

#### Scenario: Template sans email_body_html
- **WHEN** une règle activée route vers un notifier email et que son template ne définit que `title` et `body`
- **THEN** le démarrage échoue avec `Email template validation failed: 1 errors`

#### Scenario: Règle désactivée ignorée
- **WHEN** la règle concernée a `enabled: false`
- **THEN** cette vérification ne produit pas d'erreur pour elle

#### Scenario: Template Markdown dispensé
- **WHEN** une règle activée route vers un notifier email et que son template `body_format: markdown` ne définit que `title` et `body`
- **THEN** le démarrage réussit et le corps de l'email est le rendu `html` du corps
