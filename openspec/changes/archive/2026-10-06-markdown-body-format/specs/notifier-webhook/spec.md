## MODIFIED Requirements

### Requirement: Configuration du notifier webhook
Le système SHALL accepter pour un notifier `type: webhook` la clé obligatoire `url` et les clés optionnelles `method` (défaut `POST`), `headers` (table nom → valeur, vide par défaut), `body_template` (absent par défaut) et `format` (`plain`, `markdown` ou `html`, défaut `plain`, voir `notification-dispatch`), et MUST rejeter la configuration si `url` est absente ou si une autre clé est présente.

#### Scenario: Valeurs par défaut
- **WHEN** un notifier déclare seulement `type: webhook` et `url`
- **THEN** la méthode est `POST`, aucun en-tête personnalisé n'est envoyé, le corps par défaut est utilisé et le format de sortie est `plain`

#### Scenario: url manquante
- **WHEN** un notifier `type: webhook` ne déclare que `method: POST`
- **THEN** le chargement de la configuration échoue

### Requirement: Corps JSON par défaut
Le système SHALL, en l'absence de `body_template`, envoyer un objet JSON contenant exactement `alert_name` (nom du notifier), `rule_name`, `vl_source`, `title`, `body` (corps transmis au notifier, voir « Corps transmis aux notifiers selon le format » de `notification-dispatch`), `timestamp` (instant d'envoi au format RFC 3339), `log_timestamp` et `log_timestamp_formatted`, et MUST n'y inclure ni `accent_color` ni couleur ni icône.

#### Scenario: Contenu du corps par défaut
- **WHEN** le notifier `webhook-1` envoie une alerte de la règle `cpu_alert` de titre `Test Alert`
- **THEN** le JSON contient `"alert_name":"webhook-1"`, `"rule_name":"cpu_alert"`, `"title":"Test Alert"` et un champ `timestamp` non vide
- **AND** il ne contient aucune clé `color`, `icon` ni `accent_color`

#### Scenario: Corps Markdown en texte brut par défaut
- **WHEN** un webhook sans `format` reçoit une alerte d'un template `markdown` dont le corps vaut `**{{ host }}** [logs](https://vl.example.com)` avec `host=web-01`
- **THEN** le champ `body` du JSON vaut `web-01 logs (https://vl.example.com)`

### Requirement: Rendu du body_template
Le système SHALL rendre le `body_template` (après résolution des variables d'environnement de sa source) avec les seules variables `title`, `body` (corps transmis au notifier, voir « Corps transmis aux notifiers selon le format » de `notification-dispatch`), `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`), sans échappement automatique des valeurs, une variable inconnue étant rendue comme une chaîne vide, et MUST envoyer le résultat tel quel comme corps de la requête. Le filtre `tojson` MUST être disponible et produire une valeur JSON valide (chaîne entre guillemets, caractères spéciaux échappés), afin qu'un template comme `{"text": {{ body | tojson }}}` produise toujours du JSON valide.

#### Scenario: Template personnalisé
- **WHEN** `body_template` vaut `{"title": "{{ title }}", "rule": "{{ rule_name }}"}` pour la règle `test_rule` de titre `Test Alert`
- **THEN** le corps envoyé est `{"title": "Test Alert", "rule": "test_rule"}`

#### Scenario: Pas de substitution d'environnement dans le template
- **WHEN** le `body` d'une alerte contient le texte `${ROUTING_KEY}` et le template insère `{{ body }}`
- **THEN** le texte `${ROUTING_KEY}` est envoyé littéralement : la substitution des variables d'environnement ne s'applique qu'à la source du template, jamais aux valeurs rendues

#### Scenario: Valeur insérée avec tojson
- **WHEN** `body_template` vaut `{"text": {{ body | tojson }}}` et que le corps de l'alerte contient un guillemet, une barre oblique inverse et un saut de ligne
- **THEN** le corps envoyé est un JSON valide dont le champ `text` vaut exactement le corps de l'alerte

#### Scenario: Champs du log dans le corps
- **WHEN** `body_template` vaut `{"host": {{ log.host | tojson }}, "pod": {{ log["k8s.pod"] | tojson }}}` pour un événement `host=web-01` et `k8s.pod=api-7f`
- **THEN** le corps envoyé est `{"host": "web-01", "pod": "api-7f"}`

#### Scenario: Pas de substitution d'environnement dans les champs du log
- **WHEN** un champ de l'événement contient `${ROUTING_KEY}` et que le template insère ce champ via `log`
- **THEN** le texte `${ROUTING_KEY}` est envoyé littéralement

#### Scenario: Corps Markdown pour une cible Markdown
- **WHEN** un webhook déclare `format: markdown` et `body_template: {"content": {{ body | tojson }}}`, et reçoit une alerte d'un template `markdown` dont le corps vaut `**{{ host }}**` avec `host=a_b`
- **THEN** le corps envoyé est `{"content": "**a\\_b**"}`
