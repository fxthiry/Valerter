## MODIFIED Requirements

### Requirement: Configuration du notifier Mattermost
Le système SHALL accepter pour un notifier `type: mattermost` la clé obligatoire `webhook_url` et les clés optionnelles `channel`, `username`, `icon_url` et `format` (seule valeur acceptée : `markdown`, voir `notification-dispatch`), et MUST rejeter la configuration si `webhook_url` est absente ou si une autre clé est présente.

#### Scenario: Configuration minimale
- **WHEN** un notifier déclare seulement `type: mattermost` et `webhook_url`
- **THEN** il est accepté et `channel`, `username`, `icon_url` sont absents

#### Scenario: webhook_url manquante
- **WHEN** un notifier `type: mattermost` ne déclare que `channel: "test"`
- **THEN** le chargement de la configuration échoue

#### Scenario: Format explicite
- **WHEN** un notifier Mattermost déclare `format: markdown`
- **THEN** il est accepté, avec le même comportement que sans cette clé

### Requirement: Attachment unique
Le système SHALL placer le message dans un tableau `attachments` contenant exactement un élément dont `fallback` et `title` valent le titre rendu et `text` vaut le corps transmis au notifier (voir « Corps transmis aux notifiers selon le format » de `notification-dispatch`) : le corps rendu sans transformation pour un template `text`, le rendu `markdown` pour un template `markdown` (le Markdown est interprété par Mattermost).

#### Scenario: Structure de l'attachment
- **WHEN** le titre rendu est `Test Alert` et le corps `Something happened`
- **THEN** l'unique attachment contient `"fallback":"Test Alert"`, `"title":"Test Alert"` et `"text":"Something happened"`

#### Scenario: Corps Markdown
- **WHEN** une alerte d'un template `markdown` a pour corps `**{{ host }}** at {{ ts }}` avec `host=web_01` et `ts=10:49:35`
- **THEN** l'attachment contient `"text":"**web\\_01** at 10:49:35"` (JSON de `**web\_01** at 10:49:35`)
