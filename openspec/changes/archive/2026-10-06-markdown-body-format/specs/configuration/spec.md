## MODIFIED Requirements

### Requirement: Validations de démarrage dépendant des notifiers
Le système SHALL, au démarrage du démon comme en mode `--validate`, refuser toute règle (activée ou non) dont une destination ne correspond à aucun notifier déclaré, puis refuser toute règle activée ayant une destination email dont le template, de `body_format` `text`, n'a pas d'`email_body_html` ; ces contrôles MUST être exécutés même si la construction d'un notifier a échoué, un notifier déclaré mais en échec n'étant pas signalé comme destination inconnue.

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

#### Scenario: Template Markdown vers un email
- **WHEN** une règle activée utilise vers `email-ops` un template `body_format: markdown` sans `email_body_html`
- **THEN** aucune erreur `requires email_body_html` n'est journalisée et le contrôle réussit
