## MODIFIED Requirements

### Requirement: Validation des sources VictoriaLogs
Le système SHALL exiger au moins une source, des noms de source conformes à `^[a-zA-Z0-9_]+$`, des URL de source analysables au schéma `http` ou `https` après résolution des variables d'environnement (sans exception pour les valeurs contenant `${`), et des en-têtes `headers` dont chaque nom est un nom d'en-tête HTTP valide et chaque valeur résolue une valeur d'en-tête HTTP valide, chaque violation produisant une erreur de validation distincte qui MUST NOT répéter l'URL ni la valeur d'en-tête.

#### Scenario: Aucune source
- **WHEN** `victorialogs` est une table vide
- **THEN** la validation signale `victorialogs: at least one source required (define e.g. ...)`

#### Scenario: Nom de source invalide
- **WHEN** une source s'appelle `vl-prod`
- **THEN** la validation signale `victorialogs source name 'vl-prod' is invalid: must match `^[a-zA-Z0-9_]+$`` en expliquant l'ambiguïté avec la clé de throttle par défaut `{rule}-{source}:global`

#### Scenario: URL de source invalide
- **WHEN** l'URL d'une source `default` vaut `ftp://vl:9428` ou n'est pas une URL
- **THEN** la validation signale `victorialogs.default.url: invalid URL: ...` sans répéter l'URL fautive

#### Scenario: URL résolue au mauvais schéma
- **WHEN** la source `default` déclare `url: "${VL_URL}"` et `VL_URL` vaut `ftp://vl:9428`
- **THEN** la validation signale `victorialogs.default.url: invalid URL: unsupported scheme 'ftp' (expected http or https)`

#### Scenario: URL résolue contenant encore `${`
- **WHEN** la variable référencée par l'URL d'une source `default` vaut une chaîne contenant `${` qui n'est pas une URL valide
- **THEN** la validation signale `victorialogs.default.url: invalid URL: ...` au lieu d'accepter la valeur sans contrôle

#### Scenario: Nom d'en-tête invalide
- **WHEN** la source `default` déclare `headers: { "X Token": "abc" }` (espace dans le nom)
- **THEN** la validation signale `victorialogs.default.headers: invalid header name 'X Token'`

#### Scenario: Valeur d'en-tête invalide
- **WHEN** la source `default` déclare un en-tête `Authorization` dont la valeur résolue contient un saut de ligne
- **THEN** la validation signale `victorialogs.default.headers: invalid value for header 'Authorization'` sans répéter la valeur

### Requirement: Configuration multi-fichiers
Le système SHALL charger, dans le répertoire du fichier principal, les répertoires `rules.d/`, `templates.d/` et `notifiers.d/` s'ils existent, en ne traitant que les fichiers réguliers d'extension `.yaml` ou `.yml`, non cachés (nom ne commençant pas par `.`), dans l'ordre alphabétique des chemins, et MUST fusionner leur contenu avec les sections correspondantes du fichier principal. L'ordre des règles fusionnées MUST être déterministe : règles du fichier principal dans l'ordre déclaré, puis règles de `rules.d/` triées par chemin de fichier puis, dans un même fichier, par nom de règle.

#### Scenario: Format des fichiers `.d/`
- **WHEN** un fichier `rules.d/security.yaml` contient une table dont les clés sont `auth_failure` et `brute_force`
- **THEN** deux règles nommées `auth_failure` et `brute_force` sont ajoutées après les règles du fichier principal (la clé YAML fait office de `name`)

#### Scenario: Ordre déterministe des règles
- **WHEN** `config.yaml` déclare la règle `main_rule`, `rules.d/b.yaml` déclare dans cet ordre `z_rule` puis `a_rule`, et `rules.d/a.yaml` déclare `m_rule`
- **THEN** l'ordre des règles chargées est `main_rule`, `m_rule`, `a_rule`, `z_rule`, identique à chaque chargement

#### Scenario: Répertoire absent ou vide
- **WHEN** aucun répertoire `.d/` n'existe, ou qu'ils existent mais sont vides
- **THEN** seule la configuration du fichier principal est utilisée, sans erreur

#### Scenario: Fichier vide et fichiers ignorés
- **WHEN** `rules.d/` contient un fichier `.yaml` vide (ou ne contenant que des blancs), un fichier `.hidden.yaml`, un `ignored.txt` et un `ignored.json`
- **THEN** aucun de ces fichiers n'ajoute de règle et le chargement réussit

#### Scenario: Sections entièrement déportées
- **WHEN** le fichier principal ne contient ni `templates`, ni `rules`, ni `notifiers` et que ces éléments sont fournis par les répertoires `.d/`
- **THEN** la configuration chargée est complète et passe la validation

#### Scenario: Fichier `.d/` invalide
- **WHEN** `rules.d/bad.yaml` contient du YAML invalide ou une règle non conforme
- **THEN** le chargement échoue avec `invalid configuration: rules.d (<chemin>/bad.yaml): <erreur>`

#### Scenario: Répertoire illisible
- **WHEN** un répertoire `.d/` existe mais ne peut pas être lu
- **THEN** le chargement échoue avec `failed to read directory '<chemin>': <erreur>`

### Requirement: Détection des collisions de noms
Le système SHALL refuser au chargement tout nom de règle, de template ou de notifier défini plusieurs fois entre le fichier principal et un répertoire `.d/`, ou entre deux fichiers d'un même répertoire `.d/`, avec un message citant les deux emplacements et nommant le type de ressource au singulier (`rule`, `template`, `notifier`) quel que soit l'endroit de la collision.

#### Scenario: Collision entre fichier principal et `.d/`
- **WHEN** la règle `collision_rule` est définie dans `config.yaml` et dans `rules.d/conflict.yaml`
- **THEN** le chargement échoue avec `duplicate rule name 'collision_rule': defined in '<...>/config.yaml' and '<...>/rules.d/conflict.yaml'`

#### Scenario: Collision de template ou de notifier
- **WHEN** un template (resp. notifier) porte le même nom dans `config.yaml` et dans `templates.d/` (resp. `notifiers.d/`)
- **THEN** le chargement échoue avec `duplicate template name '...'` (resp. `duplicate notifier name '...'`) citant les deux fichiers

#### Scenario: Collision entre deux fichiers d'un même répertoire
- **WHEN** `rules.d/a.yaml` et `rules.d/b.yaml` définissent tous deux `collision_rule`
- **THEN** le chargement échoue avec `duplicate rule name 'collision_rule': defined in '<...>/a.yaml' and '<...>/b.yaml'`, le premier fichier dans l'ordre alphabétique étant cité en premier

#### Scenario: Collision de template entre deux fichiers de `templates.d/`
- **WHEN** `templates.d/a.yaml` et `templates.d/b.yaml` définissent tous deux le template `t`
- **THEN** le chargement échoue avec `duplicate template name 't': defined in '<...>/a.yaml' and '<...>/b.yaml'`

#### Scenario: Doublon de règle dans le fichier principal
- **WHEN** la liste `rules` du fichier principal contient deux règles nommées `r`
- **THEN** la validation signale `duplicate rule name 'r': rule names must be unique (they key throttling and metrics)`

### Requirement: Validation des règles
Le système SHALL valider pour chaque règle la regex du parser, la syntaxe Jinja puis un rendu d'essai de `throttle.key`, les bornes du throttle propre à la règle, l'existence de `notify.template`, la présence d'au moins une destination et l'absence de pipes LogsQL non supportés par l'endpoint `/tail` ; les clés `name`, `query`, `parser`, `notify.template` et `notify.destinations` MUST être présentes.

#### Scenario: Regex invalide
- **WHEN** la règle `invalid_regex_rule` déclare une regex non compilable
- **THEN** la validation signale `invalid regex pattern in rule 'invalid_regex_rule': <erreur>`

#### Scenario: Template inexistant
- **WHEN** une règle `r` référence `notify.template: missing`
- **THEN** la validation signale `invalid template in rule 'r': notify.template 'missing' not found in templates`

#### Scenario: Destinations vides
- **WHEN** une règle `r` déclare `destinations: []`
- **THEN** la validation signale `rule 'r': notify.destinations must contain at least one notifier`

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

## ADDED Requirements

### Requirement: Validation de defaults.throttle
Le système MUST appliquer à `defaults.throttle` les mêmes contrôles qu'au throttle d'une règle (`count >= 1`, `window > 0`, syntaxe puis rendu d'essai de `key`), chaque violation produisant une erreur de validation préfixée par `defaults.throttle.`.

#### Scenario: count et window nuls dans defaults
- **WHEN** `defaults.throttle` déclare `count: 0` et `window: 0s`
- **THEN** la validation signale `defaults.throttle.count must be >= 1 (0 would suppress every alert)` et `defaults.throttle.window must be > 0 (0s disables throttling)`

#### Scenario: Clé par défaut à la syntaxe invalide
- **WHEN** `defaults.throttle.key` vaut `{% if host %}{{ host`
- **THEN** la validation signale `defaults.throttle.key: <erreur>`

#### Scenario: Filtre inconnu dans la clé par défaut
- **WHEN** `defaults.throttle.key` vaut `{{ host | bad_filter }}`
- **THEN** la validation signale `defaults.throttle.key render: <erreur mentionnant bad_filter>`

#### Scenario: defaults.throttle valide
- **WHEN** `defaults.throttle` vaut `{ key: "{{ host }}", count: 5, window: 60s }`
- **THEN** aucune erreur n'est signalée pour `defaults.throttle`

### Requirement: Ordre déterministe des erreurs de validation
Le système SHALL produire les erreurs de validation dans un ordre stable d'un chargement à l'autre : règles dans l'ordre de chargement, templates et notifiers dans l'ordre alphabétique de leur nom.

#### Scenario: Deux templates invalides
- **WHEN** les templates `beta` et `alpha` ont chacun un `body` invalide
- **THEN** l'erreur concernant `alpha` précède celle concernant `beta`, à chaque exécution
