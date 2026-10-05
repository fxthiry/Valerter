## MODIFIED Requirements

### Requirement: Variables d'environnement dans les notifiers
Le système SHALL résoudre les variables d'environnement des secrets de notifier (URL de webhook, en-têtes, jeton de bot, identifiants SMTP) lors de la construction des notifiers, au démarrage du démon comme en mode `--validate`, et non pendant le chargement ; la validation d'URL de notifier MUST accepter sans les vérifier les valeurs contenant `${`.

#### Scenario: Placeholder accepté à la validation
- **WHEN** un notifier Mattermost déclare `webhook_url: "${MATTERMOST_WEBHOOK}"`
- **THEN** la validation de la configuration ne signale aucune erreur pour cette URL

#### Scenario: Variable indéfinie au démarrage
- **WHEN** le démon démarre et qu'un notifier `mattermost-ops` référence une variable indéfinie
- **THEN** l'erreur `invalid notifier 'mattermost-ops': webhook_url: invalid configuration: undefined environment variable: <NOM>` est journalisée et le démarrage échoue avec `Failed to create notifiers: <n> errors`

#### Scenario: Variable indéfinie en mode validation
- **WHEN** `valerter --validate` est lancé et qu'un notifier `mattermost-ops` référence une variable indéfinie
- **THEN** la même erreur `invalid notifier 'mattermost-ops': webhook_url: invalid configuration: undefined environment variable: <NOM>` est journalisée et le processus se termine avec le code 1

### Requirement: Validations de démarrage dépendant des notifiers
Le système SHALL, au démarrage du démon comme en mode `--validate`, refuser toute règle (activée ou non) dont une destination ne correspond à aucun notifier déclaré, puis refuser toute règle activée ayant une destination email dont le template n'a pas d'`email_body_html` ; ces contrôles MUST être exécutés même si la construction d'un notifier a échoué, un notifier déclaré mais en échec n'étant pas signalé comme destination inconnue.

#### Scenario: Destination inconnue
- **WHEN** au démarrage une règle `r` liste les destinations `a` et `b`, absentes des notifiers
- **THEN** l'erreur `rule 'r': unknown notifiers 'a', 'b'` est journalisée et le démarrage échoue avec `Destination validation failed: <n> errors`

#### Scenario: Email sans `email_body_html`
- **WHEN** au démarrage une règle activée `r` utilise le template `t` sans `email_body_html` et la destination email `email-ops`
- **THEN** l'erreur `template 't' requires email_body_html field when used with email destination 'email-ops' (rule 'r')` est journalisée et le démarrage échoue avec `Email template validation failed: <n> errors`

#### Scenario: Canal Mattermost sans destination Mattermost
- **WHEN** une règle activée définit `notify.mattermost_channel` sans aucune destination de type Mattermost
- **THEN** un avertissement `mattermost_channel ignored - no mattermost notifier in destinations` est journalisé et le démarrage continue

#### Scenario: Mêmes contrôles en mode validation
- **WHEN** `valerter --validate` est lancé sur une configuration présentant une destination inconnue ou un template e-mail sans `email_body_html`
- **THEN** les mêmes erreurs sont journalisées et le processus se termine avec le code 1

#### Scenario: Notifier en échec et template e-mail
- **WHEN** le notifier email `email-ops` échoue à se construire (variable indéfinie) et qu'une règle activée l'utilise avec un template sans `email_body_html`
- **THEN** l'erreur de construction du notifier et l'erreur `template '<t>' requires email_body_html field ...` sont toutes deux journalisées, sans erreur `unknown notifier 'email-ops'`
