# configuration Specification

## Purpose
Cette capacité décrit comment valerter charge sa configuration YAML (fichier principal et répertoires `rules.d/`, `templates.d/`, `notifiers.d/`), résout les variables d'environnement, protège les secrets et valide l'ensemble de façon fail-fast avant de démarrer. Elle couvre la déclaration des sources `victorialogs.<name>`, le champ `vl_sources` des règles, les valeurs par défaut et les validations de démarrage qui dépendent des notifiers. Les champs propres à chaque type de notifier sont détaillés dans les capacités `notifier-*`, la sémantique du throttling dans la capacité de throttling et le streaming dans la capacité de streaming ; les arguments de la ligne de commande et les codes de sortie sont décrits dans `cli`.

## Requirements

### Requirement: Chargement du fichier principal
Le système SHALL lire le fichier de configuration désigné par la CLI (par défaut `/etc/valerter/config.yaml`) et le désérialiser en YAML ; tout échec de lecture ou de parsing MUST interrompre le chargement avec une erreur explicite.

#### Scenario: Fichier introuvable
- **WHEN** le chemin de configuration ne désigne aucun fichier lisible
- **THEN** le chargement échoue avec le message `failed to load config file: <chemin>: <erreur système>`

#### Scenario: YAML invalide
- **WHEN** le fichier contient un YAML syntaxiquement invalide ou non conforme au schéma
- **THEN** le chargement échoue avec un message préfixé par `invalid configuration: ` suivi de l'erreur du parseur YAML

### Requirement: Schéma strict et sections obligatoires
Le système SHALL rejeter au chargement toute clé inconnue, à la racine comme dans chaque sous-section (sources, `metrics`, `defaults`, `throttle`, templates, règles, `parser`, `parser.json`, notifiers, `smtp`), et MUST exiger les sections `victorialogs` et `defaults` (avec `defaults.throttle`).

#### Scenario: Clé inconnue à la racine
- **WHEN** le fichier contient une clé racine non prévue par le schéma
- **THEN** le chargement échoue avec une erreur `invalid configuration: ` mentionnant le champ inconnu

#### Scenario: Clé `defaults.notify` rejetée
- **WHEN** la section `defaults` contient une clé `notify`
- **THEN** le chargement échoue avec une erreur mentionnant `notify`

#### Scenario: Section `defaults` absente
- **WHEN** le fichier ne contient pas de section `defaults`
- **THEN** le chargement échoue pour champ manquant

### Requirement: Valeurs par défaut
Le système SHALL appliquer les valeurs par défaut suivantes lorsque la clé est omise : `metrics.enabled` = `true`, `metrics.port` = `9090`, `defaults.timestamp_timezone` = `UTC`, `defaults.max_streams` = `50`, `rules[].enabled` = `true`, `rules[].vl_sources` = liste vide, `victorialogs.<name>.tls.verify` = `true`, `templates`, `rules` et `notifiers` vides.

#### Scenario: Configuration minimale
- **WHEN** une configuration ne définit ni `metrics`, ni `defaults.timestamp_timezone`, ni `defaults.max_streams`, ni `enabled` sur ses règles
- **THEN** les métriques sont activées sur le port 9090, le fuseau est `UTC`, le plafond de flux vaut 50 et chaque règle est activée

#### Scenario: TLS des sources vérifié par défaut
- **WHEN** une source déclare un bloc `tls` sans clé `verify`
- **THEN** la vérification TLS de cette source reste activée

### Requirement: Déclaration des sources VictoriaLogs
Le système SHALL lire `victorialogs` comme une table de sources nommées, chacune avec `url` obligatoire et `basic_auth` (`username` et `password` tous deux obligatoires), `headers` (table nom → valeur) et `tls.verify` optionnels, et MUST rejeter au chargement l'ancien format v1 à URL unique avec un message de migration.

#### Scenario: Plusieurs sources nommées
- **WHEN** `victorialogs` contient les clés `vlprod` et `vldev`, chacune avec une `url`
- **THEN** la configuration expose deux sources, itérées dans l'ordre alphabétique de leur nom

#### Scenario: Format v1 détecté
- **WHEN** `victorialogs` contient directement une clé `url` (forme v1.x)
- **THEN** le chargement échoue avec un message commençant par `Configuration incompatible with valerter v2.0.0.` qui montre la forme avant/après (`victorialogs.default.url`), mentionne `vl_sources: [default]` et renvoie vers `MIGRATION.md`

#### Scenario: Basic Auth incomplet
- **WHEN** une source déclare `basic_auth` avec `username` mais sans `password`
- **THEN** le chargement échoue

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

### Requirement: Référencement des sources par les règles
Le système SHALL valider que chaque entrée de `vl_sources` d'une règle (activée ou non) désigne une source déclarée et n'apparaît qu'une fois ; une liste vide ou omise signifie que la règle cible toutes les sources.

#### Scenario: Source inconnue
- **WHEN** une règle `r` déclare `vl_sources: [staging]` alors que seules `prod` et `dev` existent
- **THEN** la validation signale `rule 'r': vl_sources references unknown source 'staging' (known sources: [dev, prod])`

#### Scenario: Entrée dupliquée
- **WHEN** une règle `r` déclare `vl_sources: [prod, prod]`
- **THEN** la validation signale `rule 'r': vl_sources contains duplicate entry 'prod' (each source may appear at most once)`

### Requirement: Plafond du nombre de flux
Le système SHALL calculer le nombre total de flux comme la somme, sur les règles activées, du nombre de sources déclarées si `vl_sources` est vide ou de la longueur de `vl_sources` sinon, et MUST refuser la configuration si ce total dépasse `defaults.max_streams` ou si `defaults.max_streams` vaut 0.

#### Scenario: Plafond dépassé
- **WHEN** 3 règles activées sans `vl_sources` et 20 sources donnent 60 flux pour un plafond de 50
- **THEN** la validation signale `defaults.max_streams exceeded: 60 stream(s) required by enabled rules > cap of 50. ...`

#### Scenario: Plafond exactement atteint
- **WHEN** le total de flux est égal à `defaults.max_streams`
- **THEN** la validation passe

#### Scenario: Règles désactivées ignorées
- **WHEN** une règle désactivée ciblerait toutes les sources
- **THEN** elle ne compte pas dans le total de flux

#### Scenario: Plafond nul
- **WHEN** `defaults.max_streams` vaut 0
- **THEN** la validation signale `defaults.max_streams must be >= 1 ...`

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

### Requirement: Références croisées entre fichiers
Le système SHALL résoudre les références de template et de notifier après fusion, de sorte qu'une règle d'un fichier puisse référencer un template ou un notifier défini dans n'importe quel autre fichier.

#### Scenario: Règle `.d/` utilisant un template du fichier principal
- **WHEN** une règle de `rules.d/` référence `inline_template` défini dans `config.yaml` et une règle de `config.yaml` référence `template_from_dir` défini dans `templates.d/`
- **THEN** la validation passe

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

### Requirement: Variables d'environnement dans les sources VictoriaLogs
Le système SHALL résoudre les variables d'environnement dans `url`, `basic_auth.username`, `basic_auth.password` et chaque valeur de `headers` de toutes les sources pendant le chargement, avant la validation, et MUST faire échouer le chargement si une variable est indéfinie.

#### Scenario: Sources résolues au chargement
- **WHEN** la source `vlprod` déclare `url: "${VL_URL}"`, `basic_auth: { username: "${VL_USER}", password: "${VL_PASS}" }` et `headers: { Authorization: "Bearer ${VL_TOKEN}" }` avec ces variables définies
- **THEN** la configuration chargée contient les valeurs substituées et l'URL validée est l'URL résolue

#### Scenario: Variable indéfinie dans une source
- **WHEN** la source `vlprod` déclare `url: "${UNSET_VAR}"` et la variable n'existe pas
- **THEN** le chargement échoue avec un message contenant `victorialogs source 'vlprod'` et `UNSET_VAR`

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

### Requirement: Masquage des secrets
Le système SHALL représenter toute valeur secrète (mot de passe Basic Auth et valeurs d'en-têtes des sources, URL de webhook Mattermost, URL et en-têtes de webhook, jeton de bot Telegram, mot de passe SMTP) par `[REDACTED]` dans ses formes `Debug` et `Display`, et MUST NOT répéter une URL invalide dans les messages d'erreur de validation d'URL.

#### Scenario: Debug d'une configuration de notifier
- **WHEN** une configuration de notifier de chaque type contenant des secrets est formatée en `Debug`
- **THEN** aucun secret n'apparaît et la sortie contient `REDACTED`

#### Scenario: Basic Auth d'une source
- **WHEN** une source avec `basic_auth` est formatée en `Debug`
- **THEN** le nom d'utilisateur apparaît et le mot de passe est rendu `[REDACTED]`

#### Scenario: URL de webhook invalide
- **WHEN** une URL `htps://mm.example.com/hooks/SECRET` est rejetée
- **THEN** le message d'erreur ne contient pas `SECRET`

### Requirement: Validation fail-fast exhaustive
Le système SHALL valider la configuration fusionnée avant tout démarrage, sur toutes les règles y compris celles désactivées, en collectant l'ensemble des erreurs plutôt qu'en s'arrêtant à la première.

#### Scenario: Règle désactivée invalide
- **WHEN** une règle `disabled_invalid_rule` avec `enabled: false` contient une regex invalide
- **THEN** la validation échoue en citant `disabled_invalid_rule`

#### Scenario: Plusieurs erreurs
- **WHEN** la configuration contient à la fois une regex invalide et un template invalide
- **THEN** la validation retourne les deux erreurs

### Requirement: Présence minimale de notifiers, templates et règles
Le système SHALL exiger, après fusion des répertoires `.d/`, au moins un notifier, au moins un template et au moins une règle, dont au moins une règle activée ; ce contrôle fait partie de la validation de la configuration et s'applique donc aussi bien au démarrage qu'en mode `--validate`.

#### Scenario: Aucun notifier
- **WHEN** ni `config.yaml` ni `notifiers.d/` ne définissent de notifier
- **THEN** la validation signale `no notifiers configured: add notifiers in config.yaml or notifiers.d/`, même si la variable d'environnement `MATTERMOST_WEBHOOK` est définie

#### Scenario: Aucun template
- **WHEN** aucun template n'est défini
- **THEN** la validation signale `no templates defined: add templates in config.yaml or templates.d/`

#### Scenario: Aucune règle
- **WHEN** aucune règle n'est définie
- **THEN** la validation signale `no rules defined: add rules in config.yaml or rules.d/`

#### Scenario: Toutes les règles désactivées
- **WHEN** au moins une règle est définie et toutes ont `enabled: false`
- **THEN** la validation signale `all rules are disabled: enable at least one rule in config.yaml or rules.d/`, en plus des autres erreurs éventuelles
- **AND** `valerter --validate` se termine avec le code 1

#### Scenario: Au moins une règle activée
- **WHEN** la configuration contient des règles désactivées et au moins une règle activée (explicitement ou par défaut)
- **THEN** cette erreur n'est pas signalée

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

### Requirement: Validation du fuseau horaire
Le système SHALL vérifier que `defaults.timestamp_timezone` est un nom de fuseau IANA reconnu.

#### Scenario: Fuseau inconnu
- **WHEN** `defaults.timestamp_timezone` vaut `Mars/Olympus`
- **THEN** la validation signale `defaults.timestamp_timezone 'Mars/Olympus' is not a valid timezone`

### Requirement: Validation des notifiers
Le système SHALL rejeter au chargement tout notifier dont le `type` n'est pas `mattermost`, `webhook`, `email` ou `telegram`, et MUST déléguer à chaque type la validation de ses propres champs (URL `http`/`https` pour `webhook_url` et `url`, `chat_ids` non vide pour Telegram, etc., détaillés dans les capacités `notifier-*`).

#### Scenario: Type inconnu
- **WHEN** un notifier déclare `type: slack`
- **THEN** le chargement échoue

#### Scenario: URL de notifier invalide
- **WHEN** un notifier webhook `wh` déclare `url: "not a url"`
- **THEN** la validation signale `notifier 'wh': url: invalid URL: ...`

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
