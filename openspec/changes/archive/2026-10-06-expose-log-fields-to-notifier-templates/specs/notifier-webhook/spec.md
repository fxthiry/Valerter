## MODIFIED Requirements

### Requirement: Rendu du body_template
Le système SHALL rendre le `body_template` (après résolution des variables d'environnement de sa source) avec les seules variables `title`, `body`, `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`), sans échappement automatique des valeurs, une variable inconnue étant rendue comme une chaîne vide, et MUST envoyer le résultat tel quel comme corps de la requête. Le filtre `tojson` MUST être disponible et produire une valeur JSON valide (chaîne entre guillemets, caractères spéciaux échappés), afin qu'un template comme `{"text": {{ body | tojson }}}` produise toujours du JSON valide.

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
