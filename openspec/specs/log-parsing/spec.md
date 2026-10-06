# log-parsing Specification

## Purpose
Cette capacité décrit la transformation de chaque ligne NDJSON reçue de VictoriaLogs en un ensemble de champs exploitable par le throttling et les templates : décodage JSON de l'événement, conservation des champs intégrés (`_msg`, `_time`, `_stream`, `_stream_id`) et personnalisés, extraction optionnelle par expression régulière à groupes nommés appliquée à `_msg` et par chemins `json.fields`, et comportement en cas d'échec (ligne ignorée, journalisation, métrique). La réception et le découpage des lignes relèvent de victorialogs-streaming ; la compilation et la validation de la regex au chargement relèvent de configuration ; le rendu des templates et le calcul des clés de throttling relèvent de leurs capacités respectives ; la définition des métriques relève d'observability.

## Requirements

### Requirement: Décodage JSON de l'événement
Le système SHALL décoder chaque ligne reçue comme un objet JSON dont tous les champs sont au premier niveau, et MUST rejeter avec une erreur `invalid_json` toute ligne qui n'est pas du JSON valide ou dont la racine n'est pas un objet (tableau, chaîne, nombre, `null`).

#### Scenario: Ligne non JSON
- **WHEN** la ligne reçue est `not valid json at all`
- **THEN** le parsing échoue avec le type d'erreur `invalid_json`

#### Scenario: Racine qui n'est pas un objet
- **WHEN** la ligne reçue est `["a","b"]`
- **THEN** le parsing échoue avec le type d'erreur `invalid_json`

### Requirement: Conservation de tous les champs de l'événement
Le système SHALL conserver dans le résultat du parsing tous les champs de l'objet JSON reçu (champs intégrés VictoriaLogs et champs personnalisés), avec leurs types JSON d'origine, que la règle configure ou non `regex` ou `json.fields` ; les champs extraits s'ajoutent à cet ensemble.

#### Scenario: Événement avec champs personnalisés
- **WHEN** la ligne est `{"_time":"2026-01-09T10:00:00Z","_stream":"{hostname=\"srv-01\"}","_stream_id":"00000000000000007e59d624b556563c","_msg":"test message","hostname":"srv-01","severity":"6"}`
- **THEN** le résultat contient `_time`, `_stream`, `_stream_id`, `_msg`, `hostname` et `severity` avec leurs valeurs d'origine

#### Scenario: Règle sans extraction
- **WHEN** la règle a un bloc `parser` sans `regex` ni `json`
- **THEN** le résultat est l'objet JSON reçu, sans champ ajouté (hors `StringInserts` décodé, voir plus bas)

### Requirement: Champs intégrés VictoriaLogs
Le système SHALL exposer tels quels les champs intégrés envoyés par VictoriaLogs : `_msg` (message du log, cible de la regex), `_time` (horodatage de l'événement), `_stream` (étiquettes du flux sous forme de chaîne) et `_stream_id` ; `_time`, lorsqu'il est présent et de type chaîne, MUST être utilisé comme horodatage du log dans l'alerte, et à défaut l'heure courante (RFC 3339) est utilisée avec l'avertissement `Missing _time field in log, using current time`.

#### Scenario: `_msg` contenant du JSON
- **WHEN** `_msg` vaut la chaîne `{"level":"ERROR","message":"failed"}`
- **THEN** `_msg` reste une chaîne dans le résultat (il n'est pas décodé)

#### Scenario: `_time` absent
- **WHEN** une ligne valide ne contient pas `_time`
- **THEN** l'alerte produite porte l'heure courante comme horodatage du log et un avertissement est journalisé

### Requirement: Extraction par expression régulière sur `_msg`
Le système SHALL, lorsque `parser.regex` est configuré, appliquer l'expression régulière (syntaxe de la crate Rust `regex`, recherche non ancrée) uniquement à la valeur de `_msg`, et ajouter au résultat un champ chaîne par groupe nommé `(?P<nom>...)` ayant participé à la correspondance ; un groupe nommé n'ayant pas participé n'ajoute aucun champ, et une regex sans groupe nommé n'ajoute aucun champ.

#### Scenario: Groupes nommés simples
- **WHEN** la regex est `(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<method>\w+) (?P<path>/\S+)` et `_msg` vaut `192.168.1.1 GET /api/users`
- **THEN** le résultat contient `ip="192.168.1.1"`, `method="GET"`, `path="/api/users"`
- **AND** `_msg` est conservé inchangé

#### Scenario: Regex sans groupe nommé
- **WHEN** la regex est `ERROR` et `_msg` vaut `ERROR occurred` dans un événement à trois champs
- **THEN** la ligne est acceptée et le résultat contient exactement les trois champs d'origine

### Requirement: Priorité des champs extraits
Le système SHALL écraser, dans le résultat, tout champ existant portant le même nom qu'un champ extrait (par la regex ou par `json.fields`), la valeur extraite l'emportant sur la valeur d'origine.

#### Scenario: Groupe nommé homonyme d'un champ existant
- **WHEN** l'événement contient `host="a"` et la regex extrait un groupe `host` valant `b`
- **THEN** le résultat contient `host="b"`

### Requirement: Absence de correspondance de la regex
Le système SHALL ignorer la ligne lorsque la regex configurée ne trouve aucune correspondance dans `_msg`, avec le type d'erreur `regex_no_match` ; aucune alerte n'est produite pour cette ligne pour cette règle.

#### Scenario: Message ne correspondant pas
- **WHEN** la regex est `(?P<error>ERROR:.*)` et `_msg` vaut `INFO: all good`
- **THEN** la ligne est ignorée avec le type d'erreur `regex_no_match`

### Requirement: `_msg` absent ou non textuel avec regex
Le système SHALL ignorer la ligne avec le type d'erreur `invalid_json` (message `_msg missing or not a string`) lorsqu'une regex est configurée et que `_msg` est absent ou n'est pas une chaîne ; sans regex configurée, l'absence de `_msg` n'est pas une erreur.

#### Scenario: `_msg` manquant
- **WHEN** une regex est configurée et la ligne est `{"_time":"2026-01-09T10:00:00Z","_stream":"{}"}`
- **THEN** la ligne est ignorée avec le type d'erreur `invalid_json`

### Requirement: Extraction par chemins `json.fields`
Le système SHALL, lorsque `parser.json.fields` est configuré, résoudre chaque chemin de la liste sur l'objet racine de l'événement en interprétant chaque `.` comme un niveau d'imbrication, et ajouter la valeur trouvée (de n'importe quel type JSON) au premier niveau du résultat sous le nom du dernier segment du chemin.

#### Scenario: Champ racine
- **WHEN** `json.fields: [hostname, severity]` et l'événement contient `hostname="srv-01"` et `severity="6"`
- **THEN** le résultat contient `hostname="srv-01"` et `severity="6"`

#### Scenario: Chemin imbriqué
- **WHEN** `json.fields: [metadata.labels.app.version]` et l'événement contient `{"metadata":{"labels":{"app":{"version":"1.2.3"}}}}`
- **THEN** le résultat contient `version="1.2.3"` au premier niveau

#### Scenario: Clé plate contenant des points
- **WHEN** `json.fields: [nginx.http.status]` et l'événement contient la clé littérale `"nginx.http.status":"400"` sans objet `nginx` imbriqué
- **THEN** le chemin n'est pas trouvé et aucun champ `status` n'est ajouté
- **AND** la clé `nginx.http.status` reste présente dans le résultat comme tout champ d'origine

### Requirement: Chemin `json.fields` introuvable
Le système SHALL ignorer silencieusement un chemin de `json.fields` absent de l'événement (journalisation au niveau debug `JSON field not found in log`) sans faire échouer le parsing de la ligne.

#### Scenario: Chemin inexistant
- **WHEN** `json.fields: [nonexistent.field]` et l'événement ne contient pas `nonexistent`
- **THEN** la ligne est acceptée et le résultat ne contient ni `field` ni `nonexistent`

### Requirement: Ordre d'application regex puis JSON
Le système SHALL, lorsqu'une règle configure à la fois `regex` et `json.fields`, appliquer d'abord la regex à `_msg`, puis résoudre les chemins `json.fields` sur l'objet enrichi des champs extraits par la regex.

#### Scenario: Chemin désignant un champ issu de la regex
- **WHEN** la regex extrait `level` et `json.fields: [level]`
- **THEN** la ligne est acceptée et `level` contient la valeur extraite par la regex

### Requirement: Décodage du champ `StringInserts`
Le système SHALL, lorsqu'un événement contient un champ `StringInserts` de type chaîne dont le contenu est du JSON valide, remplacer ce champ par la valeur JSON décodée ; si le contenu n'est pas du JSON valide, la chaîne est conservée telle quelle.

#### Scenario: Événement Windows
- **WHEN** l'événement contient `"StringInserts":"[\"S-1-5-21\",\"user\",\"DOMAIN\",\"0x123\",3]"`
- **THEN** `StringInserts` est un tableau de 5 éléments dont le premier est `S-1-5-21`

### Requirement: Ligne ignorée en cas d'échec de parsing
Le système SHALL, pour toute ligne dont le parsing échoue, ignorer la ligne pour la règle concernée (ni throttling, ni template, ni notification), incrémenter `valerter_parse_errors_total{rule_name, vl_source, error_type}` avec `error_type` valant `regex_no_match` ou `invalid_json`, et poursuivre le traitement des lignes suivantes sans interrompre le flux. Une absence de correspondance MUST être journalisée au niveau debug (`Regex did not match, skipping log`) et un JSON invalide au niveau warn (`Invalid JSON in log`, avec le message d'erreur).

#### Scenario: Ligne invalide suivie d'une ligne valide
- **WHEN** une ligne `not json` puis une ligne JSON valide correspondant à la règle arrivent sur le même flux
- **THEN** `valerter_parse_errors_total{error_type="invalid_json"}` augmente de 1 et un avertissement est journalisé
- **AND** la ligne valide est traitée normalement

#### Scenario: Absence de correspondance silencieuse
- **WHEN** une ligne ne correspond pas à la regex de la règle
- **THEN** `valerter_parse_errors_total{error_type="regex_no_match"}` augmente de 1 et seul un message debug est journalisé

### Requirement: Comptage des lignes acceptées
Le système SHALL incrémenter `valerter_logs_matched_total{rule_name, vl_source}` pour chaque ligne dont le parsing réussit, avant l'application du throttling.

#### Scenario: Ligne acceptée puis limitée
- **WHEN** une ligne est parsée avec succès puis rejetée par le throttling
- **THEN** `valerter_logs_matched_total` a tout de même été incrémenté pour cette ligne

### Requirement: Vue imbriquée des clés pointées
Le système SHALL, lorsque les champs parsés servent de contexte au rendu des templates ou de la clé de throttling, ajouter pour chaque clé de premier niveau contenant des points (ex. `nginx.http.request_id`) une structure imbriquée équivalente (`nginx` → `http` → `request_id`) fusionnée avec les objets imbriqués existants, en conservant la clé plate d'origine ; lorsque le premier segment désigne déjà un champ scalaire, la clé pointée n'est pas développée et un avertissement est journalisé. Une clé de plus de 32 segments MUST NOT être développée : seule la clé plate est conservée et un avertissement est journalisé.

#### Scenario: Clé plate pointée
- **WHEN** l'événement contient `"nginx.http.request_id":"x"`
- **THEN** le contexte expose à la fois `nginx.http.request_id` (clé plate) et l'objet imbriqué `nginx.http.request_id` valant `x`

#### Scenario: Collision avec un scalaire
- **WHEN** l'événement contient `"a":"scalar"` et `"a.b":1`
- **THEN** `a` reste `"scalar"`, `a.b` reste une clé plate et un avertissement `skipping dotted-key expansion: top-level scalar already exists` est journalisé

#### Scenario: Clé de plus de 32 segments
- **WHEN** l'événement contient une clé de 33 segments, ou de 20 000 segments (40 Ko), séparés par des points
- **THEN** la clé reste une clé plate, aucun objet imbriqué n'est créé pour elle, un avertissement `skipping dotted-key expansion: too many segments` est journalisé et le traitement de l'événement se poursuit sans arrêt du processus
