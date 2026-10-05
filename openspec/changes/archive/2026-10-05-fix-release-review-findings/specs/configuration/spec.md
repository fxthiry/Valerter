## MODIFIED Requirements

### Requirement: Résolution des variables d'environnement
Le système SHALL remplacer chaque motif `${NOM}` (avec `NOM` conforme à `[A-Za-z_][A-Za-z0-9_]*`) par la valeur de la variable d'environnement correspondante, en conservant le texte autour, et MUST échouer en listant toutes les variables non définies d'une même valeur. La substitution MUST se faire en une seule passe sur la valeur d'origine : le texte inséré depuis une variable n'est jamais lui-même soumis à substitution, même s'il contient `${...}`.

#### Scenario: Substitution multiple
- **WHEN** une valeur vaut `https://${HOST}/hooks/${TOKEN}` avec `HOST` et `TOKEN` définies
- **THEN** la valeur résolue est l'URL avec les deux variables substituées

#### Scenario: Variable définie mais vide
- **WHEN** une valeur vaut `before${EMPTY}after` et `EMPTY` est définie à la chaîne vide
- **THEN** la valeur résolue est `beforeafter`

#### Scenario: Variables non définies
- **WHEN** une valeur référence `${A}` et `${B}`, toutes deux absentes de l'environnement
- **THEN** la résolution échoue avec `undefined environment variables: A, B` (au singulier `undefined environment variable: A` s'il n'y en a qu'une)

#### Scenario: Pas de substitution en chaîne
- **WHEN** une valeur vaut `${A}-${B}` avec `A` définie à `${B}` et `B` définie à `x`
- **THEN** la valeur résolue est `${B}-x`

### Requirement: Validation des règles
Le système SHALL valider pour chaque règle la regex du parser, la syntaxe Jinja puis un rendu d'essai de `throttle.key`, les bornes du throttle propre à la règle, l'existence de `notify.template`, la présence d'au moins une destination, l'absence de doublon dans `notify.destinations` et l'absence de pipes LogsQL non supportés par l'endpoint `/tail` ; les clés `name`, `query`, `parser`, `notify.template` et `notify.destinations` MUST être présentes.

#### Scenario: Regex invalide
- **WHEN** la règle `invalid_regex_rule` déclare une regex non compilable
- **THEN** la validation signale `invalid regex pattern in rule 'invalid_regex_rule': <erreur>`

#### Scenario: Template inexistant
- **WHEN** une règle `r` référence `notify.template: missing`
- **THEN** la validation signale `invalid template in rule 'r': notify.template 'missing' not found in templates`

#### Scenario: Destinations vides
- **WHEN** une règle `r` déclare `destinations: []`
- **THEN** la validation signale `rule 'r': notify.destinations must contain at least one notifier`

#### Scenario: Destination en double
- **WHEN** une règle `r` déclare `destinations: [mattermost-ops, mattermost-ops]`
- **THEN** la validation signale `rule 'r': notify.destinations contains duplicate entry 'mattermost-ops' (each notifier may appear at most once)`, au démarrage comme avec `--validate`, et aucune alerte n'est livrée deux fois au même notifier

#### Scenario: Clé de throttle invalide
- **WHEN** une règle `r` déclare un `throttle.key` à la syntaxe Jinja invalide
- **THEN** la validation signale `invalid template in rule 'r': throttle.key: <erreur>`

#### Scenario: Filtre inconnu dans la clé de throttle
- **WHEN** une règle `r` déclare `throttle.key: "{{ host | bad_filter }}"`
- **THEN** la validation signale `invalid template in rule 'r': throttle.key render: <erreur mentionnant bad_filter>`

#### Scenario: Throttle de règle à zéro
- **WHEN** une règle `r` déclare `throttle.count: 0` et `throttle.window: 0s`
- **THEN** la validation signale `rule 'r': throttle.count must be >= 1 (0 would suppress every alert)` et `rule 'r': throttle.window must be > 0 (0s disables throttling)`

#### Scenario: Pipe d'agrégation dans la requête
- **WHEN** la requête d'une règle `r` contient `| stats by (host) count()` (ou l'un des pipes `stats`, `sort`, `top`, `uniq`, `limit`, `offset`, `first`, `last`, `facets`, `join`, `field_names`, `field_values`, `block_stats`, `blocks_count`, `union`, insensible à la casse)
- **THEN** la validation signale `rule 'r': invalid query: pipe 'stats' is not supported by the VictoriaLogs /tail endpoint ...`

### Requirement: Validation des templates
Le système SHALL vérifier pour chaque template la syntaxe Jinja puis un rendu d'essai de `title`, `body` et, s'il est présent, `email_body_html`, le rendu d'essai tolérant les variables absentes et les accès chaînés (`{{ a.b.c }}`) mais détectant les filtres inconnus, y compris après une conversion de type, dans une branche `else` ou dans un corps de boucle (voir « Validation par rendu d'essai » de `message-templating`, qui décrit aussi les limites restantes) ; `accent_color` MUST respecter le format `#rrggbb`.

#### Scenario: Erreur de syntaxe
- **WHEN** le template `t` a un `body` valant `{% if unclosed`
- **THEN** la validation signale `invalid template in rule 'template:t': body: <erreur>`

#### Scenario: Filtre inconnu
- **WHEN** le template `t` utilise `{{ name | truncate(50) }}` dans son `title`
- **THEN** la validation signale `invalid template in rule 'template:t': title render: <erreur mentionnant truncate>`

#### Scenario: Filtre inconnu dans une branche else
- **WHEN** le template `t` a un `body` valant `{% if host %}{{ host }}{% else %}{{ host | nosuch }}{% endif %}`
- **THEN** la validation signale `invalid template in rule 'template:t': body render: <erreur mentionnant nosuch>`

#### Scenario: Champ contenant une barre oblique
- **WHEN** un template contient `{{ ocp.openshift.io/decision }}`
- **THEN** l'erreur de rendu est suivie de `hint: field names containing '/' must use bracket notation, e.g. `{{ ocp.openshift["io/decision"] }}` ...`

#### Scenario: Couleur invalide
- **WHEN** le template `t` déclare `accent_color: "#fff"`
- **THEN** la validation signale `template 't': invalid hex color '#fff': must be in format #rrggbb (e.g., #ff0000)`

#### Scenario: Ancien nom de champ
- **WHEN** un template utilise la clé `body_html` au lieu de `email_body_html`
- **THEN** le chargement échoue pour champ inconnu

### Requirement: Ordre déterministe des erreurs de validation
Le système SHALL produire les erreurs de validation dans un ordre stable d'un chargement à l'autre : règles dans l'ordre de chargement, templates et notifiers dans l'ordre alphabétique de leur nom. Les erreurs `Notifier configuration error` journalisées à la construction des notifiers (démarrage et `--validate`) MUST suivre l'ordre alphabétique des noms de notifier, et lorsqu'un notifier webhook déclare plusieurs en-têtes invalides, l'en-tête signalé MUST être le premier dans l'ordre alphabétique de leur nom.

#### Scenario: Deux templates invalides
- **WHEN** les templates `beta` et `alpha` ont chacun un `body` invalide
- **THEN** l'erreur concernant `alpha` précède celle concernant `beta`, à chaque exécution

#### Scenario: Deux notifiers invalides à la construction
- **WHEN** les notifiers `zeta` et `alpha` référencent chacun une variable d'environnement non définie
- **THEN** l'erreur `Notifier configuration error` concernant `alpha` précède celle concernant `zeta`, à chaque exécution

#### Scenario: Plusieurs en-têtes de webhook invalides
- **WHEN** un notifier webhook déclare les en-têtes au nom invalide `Bad Header B` et `Bad Header A`
- **THEN** l'erreur signalée est `invalid header name: Bad Header A`, à chaque exécution
