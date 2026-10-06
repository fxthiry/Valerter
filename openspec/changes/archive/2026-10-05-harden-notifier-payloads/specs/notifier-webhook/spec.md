## ADDED Requirements

### Requirement: Content-Type JSON par défaut
Le système SHALL ajouter l'en-tête `Content-Type: application/json` à chaque requête lorsque `headers` ne contient aucun en-tête `Content-Type` (comparaison insensible à la casse du nom), que le corps soit le JSON par défaut ou issu de `body_template`, et MUST conserver tel quel un `Content-Type` configuré par l'opérateur, sans le dupliquer.

#### Scenario: Corps par défaut sans en-tête configuré
- **WHEN** aucun en-tête n'est configuré et `body_template` est absent
- **THEN** la requête porte le JSON par défaut et exactement un en-tête `Content-Type: application/json`

#### Scenario: body_template sans en-tête configuré
- **WHEN** un `body_template` est configuré et `headers` ne contient pas de `Content-Type`
- **THEN** la requête porte l'en-tête `Content-Type: application/json`

#### Scenario: Content-Type configuré prioritaire
- **WHEN** `headers: { content-type: "text/plain" }` est configuré
- **THEN** la requête porte un unique en-tête `Content-Type` de valeur `text/plain`

### Requirement: Avertissement sur un corps JSON invalide
Le système SHALL, lorsque le `Content-Type` effectif de la requête est JSON (`application/json` ou type à suffixe `+json`, sans tenir compte de la casse ni des paramètres) et que le corps rendu par `body_template` n'est pas un document JSON valide, journaliser l'avertissement `Webhook body is not valid JSON` avec le nom du notifier et de la règle mais sans le contenu du corps, et MUST envoyer quand même la requête.

#### Scenario: Guillemet non échappé
- **WHEN** `body_template` vaut `{"text": "{{ body }}"}` et que le corps de l'alerte contient `say "hi"`
- **THEN** l'avertissement `Webhook body is not valid JSON` est journalisé et la requête est émise

#### Scenario: Corps non JSON assumé
- **WHEN** `headers: { Content-Type: "text/plain" }` est configuré et que le corps rendu n'est pas du JSON
- **THEN** aucun avertissement n'est journalisé et la requête est émise

## MODIFIED Requirements

### Requirement: Rendu du body_template
Le système SHALL rendre le `body_template` avec les seules variables `title`, `body`, `rule_name`, `vl_source`, `log_timestamp` et `log_timestamp_formatted`, sans échappement automatique des valeurs, une variable inconnue étant rendue comme une chaîne vide, et MUST envoyer le résultat tel quel comme corps de la requête. Le filtre `tojson` MUST être disponible et produire une valeur JSON valide (chaîne entre guillemets, caractères spéciaux échappés), afin qu'un template comme `{"text": {{ body | tojson }}}` produise toujours du JSON valide.

#### Scenario: Template personnalisé
- **WHEN** `body_template` vaut `{"title": "{{ title }}", "rule": "{{ rule_name }}"}` pour la règle `test_rule` de titre `Test Alert`
- **THEN** le corps envoyé est `{"title": "Test Alert", "rule": "test_rule"}`

#### Scenario: Pas de substitution d'environnement dans le template
- **WHEN** `body_template` contient le texte `${ROUTING_KEY}`
- **THEN** le texte `${ROUTING_KEY}` est envoyé littéralement

#### Scenario: Valeur insérée avec tojson
- **WHEN** `body_template` vaut `{"text": {{ body | tojson }}}` et que le corps de l'alerte contient un guillemet, une barre oblique inverse et un saut de ligne
- **THEN** le corps envoyé est un JSON valide dont le champ `text` vaut exactement le corps de l'alerte

## REMOVED Requirements

### Requirement: Aucun Content-Type implicite
**Reason**: Les endpoints JSON courants (Slack, Discord, PagerDuty, API REST) rejettent ou interprètent mal un corps JSON sans `Content-Type` ; l'absence d'en-tête par défaut faisait perdre des alertes sur un 400 non relancé. Remplacé par « Content-Type JSON par défaut ».
**Migration**: Aucune action requise pour un endpoint JSON. Un endpoint qui attend un autre type de contenu doit déclarer explicitement son `Content-Type` dans `headers`, qui reste prioritaire.
