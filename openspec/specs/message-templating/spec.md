# message-templating Specification

## Purpose
Le templating transforme les champs d'un événement VictoriaLogs parsé en message d'alerte (titre, corps, corps HTML pour l'email, couleur d'accent) à l'aide de templates nommés au format Jinja2, rendus par minijinja. Il couvre le contexte de rendu, l'échappement HTML, le message de repli en cas d'erreur, les horodatages transmis aux notificateurs et la vérification des templates au démarrage. La validation de structure de la configuration relève de `configuration`, le calcul de la clé de throttle de `throttling`, et les templates propres aux notificateurs (`subject_template`, `body_template`) ainsi que l'envoi relèvent de `notifiers`.

## Requirements

### Requirement: Champs d'un template
Le système SHALL accepter, pour chaque template nommé de `templates` (ou de `templates.d/`), les champs `title` (obligatoire), `body` (obligatoire), `email_body_html` (optionnel) et `accent_color` (optionnel), et MUST rejeter tout autre champ.

#### Scenario: Template minimal
- **WHEN** un template ne définit que `title: "{{ rule_name }}"` et `body: "{{ _msg }}"`
- **THEN** le template est accepté et son rendu ne produit ni corps HTML ni couleur d'accent

#### Scenario: Champ inconnu
- **WHEN** un template contient un champ `subject`
- **THEN** le chargement de la configuration échoue

### Requirement: Moteur minijinja et syntaxe Jinja2
Le système SHALL rendre `title`, `body` et `email_body_html` avec minijinja, en prenant en charge les expressions, conditions (`{% if %}`), boucles (`{% for %}`) et les filtres intégrés de minijinja (ex. `default`, `upper`, `lower`, `length`, `tojson`) ; aucun filtre supplémentaire n'est fourni, si bien que des filtres absents de minijinja comme `truncate` sont inconnus.

#### Scenario: Condition
- **WHEN** `title: "{% if severity == \"critical\" %}CRITICAL{% else %}Warning{% endif %}"` est rendu avec `severity=critical`
- **THEN** le titre vaut `CRITICAL`

#### Scenario: Filtre inexistant
- **WHEN** un template utilise `{{ _msg | truncate(50) }}`
- **THEN** le filtre est traité comme inconnu (rejet au démarrage, voir la validation par rendu d'essai)

### Requirement: Contexte de rendu issu de l'événement
Le système SHALL exposer comme variables de premier niveau tous les champs de l'événement parsé, y compris les champs VictoriaLogs présents (`_msg`, `_time`, `_stream`, `_stream_id`) et les champs extraits par le parseur, avec accès aux objets imbriqués par la notation pointée, et MUST préserver les caractères Unicode.

#### Scenario: Champs imbriqués
- **WHEN** `title: "Server: {{ data.server.hostname }}"` est rendu avec `{"data": {"server": {"hostname": "prod-server-01"}}}`
- **THEN** le titre vaut `Server: prod-server-01`

#### Scenario: Message brut et horodatage brut
- **WHEN** `body: "{{ _msg }} @ {{ _time }}"` est rendu sur un événement
- **THEN** le corps contient exactement le `_msg` et le `_time` de l'événement

### Requirement: Dépliage des clés pointées
Le système SHALL exposer chaque champ plat dont le nom contient des points (ex. `nginx.http.request_id`) également sous forme d'objets imbriqués, fusionnés avec les objets existants ; si le premier segment correspond déjà à un champ scalaire, ce scalaire est conservé, le dépliage de cette clé est ignoré et un avertissement est journalisé.

#### Scenario: Champ plat pointé
- **WHEN** `body: "id={{ nginx.http.request_id }}"` est rendu avec le champ plat `"nginx.http.request_id": "abc"`
- **THEN** le corps vaut `id=abc`

#### Scenario: Collision avec un scalaire
- **WHEN** l'événement contient `"a": "x"` et `"a.b": "y"`
- **THEN** `{{ a }}` vaut `x` et `{{ a.b }}` est rendu vide

### Requirement: Variables synthétiques rule_name et vl_source
Le système SHALL injecter dans le contexte de `title`, `body` et `email_body_html` les variables `rule_name` (nom de la règle déclenchée) et `vl_source` (nom de la source VictoriaLogs de l'événement), qui prennent le pas sur tout champ d'événement de même nom.

#### Scenario: Collision avec un champ d'événement
- **WHEN** `title: "{{ vl_source }}"` est rendu pour la source `vlprod` sur un événement contenant `vl_source=evil`
- **THEN** le titre vaut `vlprod`

### Requirement: Variables indéfinies rendues vides
Le système SHALL rendre toute variable ou tout attribut absent du contexte comme une chaîne vide, sans erreur de rendu.

#### Scenario: Champ manquant
- **WHEN** `body: "Missing: {{ nonexistent }}"` est rendu sur un événement sans ce champ
- **THEN** le corps vaut `Missing: ` et aucune erreur n'est levée

#### Scenario: Champs vides
- **WHEN** `body: "[{{ request_id }}][{{ user_id }}]"` est rendu avec `request_id: ""` et sans `user_id`
- **THEN** le corps vaut `[][]`

### Requirement: Horodatages réservés aux templates des notificateurs
Le système SHALL calculer `log_timestamp` et `log_timestamp_formatted` après le rendu du template et les fournir uniquement aux contextes des notificateurs (avec `title`, `body`, `rule_name` et `vl_source`) ; ils ne sont pas définis dans `title`, `body` ni `email_body_html`.

#### Scenario: Horodatage dans un titre
- **WHEN** `title: "Alerte {{ log_timestamp_formatted }}"` est rendu
- **THEN** le titre vaut `Alerte ` (variable indéfinie rendue vide)

### Requirement: Valeur de log_timestamp
Le système SHALL renseigner `log_timestamp` avec la valeur brute du champ `_time` de l'événement lorsqu'il s'agit d'une chaîne, et sinon avec l'heure courante au format RFC 3339 en journalisant l'avertissement `Missing _time field in log, using current time`.

#### Scenario: Événement avec _time
- **WHEN** l'événement porte `_time: "2026-01-09T10:00:00Z"`
- **THEN** `log_timestamp` vaut `2026-01-09T10:00:00Z`

#### Scenario: Événement sans _time
- **WHEN** l'événement ne porte pas de champ `_time`
- **THEN** `log_timestamp` vaut l'heure courante en RFC 3339 et un avertissement est journalisé

### Requirement: Format de log_timestamp_formatted et fuseau horaire
Le système SHALL produire `log_timestamp_formatted` au format `JJ/MM/AAAA HH:MM:SS <abréviation du fuseau>` (motif `%d/%m/%Y %H:%M:%S %Z`) dans le fuseau IANA `defaults.timestamp_timezone` (défaut `UTC`), en tronquant les fractions de seconde ; si `log_timestamp` n'est pas un horodatage RFC 3339, la valeur brute est reprise telle quelle.

#### Scenario: Fuseau UTC
- **WHEN** `log_timestamp` vaut `2026-01-15T10:49:35.799Z` et le fuseau est `UTC`
- **THEN** `log_timestamp_formatted` vaut `15/01/2026 10:49:35 UTC`

#### Scenario: Fuseau Europe/Paris en hiver et en été
- **WHEN** le fuseau est `Europe/Paris` et `log_timestamp` vaut `2026-01-15T10:00:00Z` puis `2026-07-15T10:00:00Z`
- **THEN** `log_timestamp_formatted` vaut `15/01/2026 11:00:00 CET` puis `15/07/2026 12:00:00 CEST`

#### Scenario: Horodatage illisible
- **WHEN** `log_timestamp` vaut `not-a-timestamp`
- **THEN** `log_timestamp_formatted` vaut `not-a-timestamp`

### Requirement: Validation du fuseau horaire
Le système MUST rejeter au chargement une valeur de `defaults.timestamp_timezone` qui n'est pas un nom de fuseau IANA, avec le message `defaults.timestamp_timezone '<valeur>' is not a valid timezone`.

#### Scenario: Fuseau invalide
- **WHEN** `defaults.timestamp_timezone` vaut `Mars/Olympus`
- **THEN** la validation échoue avec `defaults.timestamp_timezone 'Mars/Olympus' is not a valid timezone`

### Requirement: Échappement HTML de email_body_html
Le système SHALL échapper automatiquement en HTML les valeurs insérées dans `email_body_html`, tandis que `title` et `body` sont rendus sans aucun échappement.

#### Scenario: Injection de balise dans le corps HTML
- **WHEN** `email_body_html: "<p>Hostname: {{ hostname }}</p>"` est rendu avec `hostname=<script>alert(1)</script>`
- **THEN** le résultat contient `&lt;script&gt;` et ne contient pas `<script>`

#### Scenario: Balise dans le corps texte
- **WHEN** `body: "{{ hostname }}"` est rendu avec la même valeur
- **THEN** le corps contient `<script>alert(1)</script>` tel quel

### Requirement: Couleur d'accent statique
Le système SHALL transmettre `accent_color` tel quel, sans rendu de template, et MUST rejeter au chargement toute valeur ne respectant pas le format `#rrggbb` (hexadécimal, casse indifférente) avec le message `template '<nom>': invalid hex color '<valeur>': must be in format #rrggbb (e.g., #ff0000)`.

#### Scenario: Couleur valide
- **WHEN** un template déclare `accent_color: "#3498db"`
- **THEN** le message rendu porte la couleur `#3498db`

#### Scenario: Couleur invalide
- **WHEN** un template déclare `accent_color: "red"`
- **THEN** la validation échoue avec le message de couleur hexadécimale invalide

### Requirement: Message de repli en cas d'erreur de rendu
Le système SHALL, si le rendu du template d'une alerte échoue (template introuvable ou erreur à l'exécution), journaliser l'avertissement `Template render failed, using fallback` et envoyer quand même l'alerte avec le titre `[<rule_name>] Alert`, le corps `Template render failed: <erreur>` suivi d'une ligne vide et de `Check logs for details.`, sans corps HTML et avec la couleur `#ff0000` ; le message de repli MUST NOT contenir les valeurs des champs de l'événement.

#### Scenario: Filtre inconnu à l'exécution
- **WHEN** le template de la règle `test_rule` contient `{{ host | nonexistent_filter }}` et est rendu avec `host=server-01`
- **THEN** le titre vaut `[test_rule] Alert`, le corps contient `Template render failed` et `Check logs for details.`, la couleur vaut `#ff0000`
- **AND** le corps ne contient pas `server-01`

### Requirement: Validation syntaxique des templates au démarrage
Le système MUST compiler au chargement `title`, `body` et `email_body_html` de chaque template défini, utilisé ou non, et rejeter la configuration en cas d'erreur de syntaxe avec un message de la forme `invalid template in rule 'template:<nom>': <champ>: <détail>`.

#### Scenario: Balise non fermée
- **WHEN** le `body` du template `alert` vaut `{% if x %}oops`
- **THEN** la validation échoue avec une erreur `invalid template in rule 'template:alert': body: ...`

### Requirement: Validation par rendu d'essai
Le système MUST effectuer au chargement un rendu d'essai de `title`, `body` et `email_body_html` de chaque template, afin de détecter les erreurs d'exécution comme les filtres inconnus, et rejeter la configuration avec un message `<champ> render: <détail>`. Ce rendu utilise un contexte fictif où tout accès à un champ (y compris en chaîne pointée) est défini, et il est effectué deux fois : une passe où toute condition est vraie et toute boucle sur un champ itère un élément, puis une passe où toute condition sur un champ est fausse, toute boucle est vide et le test `defined` est faux pour un champ ; une erreur dans l'une des deux passes fait échouer la validation. Seules les erreurs indépendantes des valeurs réelles MUST faire échouer le rendu d'essai : erreur de syntaxe, filtre, test, fonction ou méthode inconnu, et opérateur `/` appliqué à un chemin de champ ; une erreur de type ou d'opération causée par le contexte fictif MUST NOT faire échouer la validation. Un filtre intégré appliqué à un champ fictif (conversion `int`/`float`, `round`, `abs`, `split`, `upper`, `items`…) MUST NOT interrompre le rendu d'essai : la suite du template reste vérifiée. Une opération arithmétique sur un champ brut (`{{ count + 1 }}`) interrompt la passe en cours sans erreur, et le corps d'un `elif` n'est vérifié par aucune des deux passes ; ces limites sont documentées. La même règle s'applique à tout rendu d'essai effectué par valerter (`throttle.key`, `subject_template`, `body_template` des notifiers).

#### Scenario: Filtre inconnu
- **WHEN** le `body` d'un template vaut `{{ _msg | truncate(50) }}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `truncate`

#### Scenario: Champ pointé profond
- **WHEN** un template référence `{{ nginx.http.request_id }}` et `{% if a.b %}{{ a.b }}{% endif %}`
- **THEN** la validation réussit

#### Scenario: Conversion de type sur un champ
- **WHEN** le `title` d'un template vaut `{{ status | int }} {{ (latency | float) > 1.5 }} {{ count + 1 }}`
- **THEN** la validation réussit

#### Scenario: Test inconnu
- **WHEN** le `body` d'un template vaut `{% if host is nosuchtest %}x{% endif %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuchtest`

#### Scenario: Filtre inconnu après une conversion
- **WHEN** le `body` d'un template vaut `{{ status | int }}-{{ host | truncat(10) }}` (ou `{{ x | float | round(2) }} {{ y | nosuch }}`, ou `{{ host | split('.') | first }} {{ host | nosuch }}`)
- **THEN** la validation échoue avec une erreur de template contenant `body render` et le nom du filtre inconnu

#### Scenario: Filtre inconnu dans une branche alternative
- **WHEN** le `body` d'un template vaut `{% if a %}ok{% else %}{{ a | nosuch }}{% endif %}`, `{% if not a %}{{ a | nosuch }}{% endif %}` ou `{% if a is not defined %}{{ a | nosuch }}{% endif %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtre inconnu dans un corps de boucle
- **WHEN** le `body` d'un template vaut `{% for i in items %}{{ i | nosuch }}{% endfor %}` ou `{% for k, v in m | items %}{{ v | nosuch }}{% endfor %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtres intégrés usuels sur des champs
- **WHEN** un template utilise `{{ a | length }} {{ a | join(',') }} {{ a | default('x') | upper }} {{ a | replace('a', 'b') | lower | trim }} {{ a | tojson }} {{ a | dictsort }} {{ count | int + 1 }}`
- **THEN** la validation réussit

### Requirement: Indice pour les noms de champ contenant une barre oblique
Le système SHALL, lorsqu'un rendu d'essai échoue sur l'opérateur `/` et que le template contient, dans une expression `{{ ... }}`, un chemin de champ comportant `/` dont la partie gauche est un chemin pointé (`a.b/c`) ou dont la partie droite contient `.`, `-` ou `/`, ajouter au message d'erreur une ligne `hint:` proposant la réécriture en notation crochets sur l'objet parent (ex. `{{ ocp.annotations.authentication.openshift["io/username"] }}`) ; si le segment contenant `/` est au premier niveau (aucun objet parent), l'indice MUST NOT proposer de syntaxe inexistante et SHALL expliquer que ce champ n'est pas adressable directement et qu'il faut le renommer dans la requête LogsQL (pipe `rename`). Une division entre deux identifiants simples sans espace (`{{ total/count }}`) MUST NOT produire d'indice ni faire échouer la validation.

#### Scenario: Annotation Kubernetes
- **WHEN** un template contient `{{ ocp.annotations.authentication.openshift.io/username }}`
- **THEN** la validation échoue et le message contient un indice suggérant `openshift["io/username"]`

#### Scenario: Champ de premier niveau contenant une barre oblique
- **WHEN** un template contient `{{ io/user-name }}`
- **THEN** la validation échoue et l'indice mentionne le pipe LogsQL `rename` (ex. `| rename "io/user-name" as io_user_name`) sans proposer `fields["io/user-name"]`

#### Scenario: Division entre deux champs
- **WHEN** un template contient `{{ total/count }}`
- **THEN** la validation réussit et aucun indice n'est produit

### Requirement: Corps HTML obligatoire pour les destinations email
Le système MUST refuser de démarrer le démon lorsqu'une règle activée a au moins une destination de type email et que son template ne définit pas `email_body_html`, avec l'erreur `template '<t>' requires email_body_html field when used with email destination '<dest>' (rule '<r>')` puis l'échec `Email template validation failed: <n> errors` ; cette vérification est également effectuée par `--validate`, qui se termine alors avec le code 1.

#### Scenario: Template sans corps HTML vers un email
- **WHEN** la règle activée `r` utilise le template `t` sans `email_body_html` et la destination email `ops-mail`
- **THEN** le démarrage échoue avec `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')`

#### Scenario: Règle désactivée
- **WHEN** la même règle est désactivée
- **THEN** aucune erreur n'est levée pour ce template

#### Scenario: Détection par --validate
- **WHEN** `valerter --validate` est lancé sur la configuration de la règle activée `r` ci-dessus
- **THEN** l'erreur `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')` est journalisée et le code de sortie est 1

### Requirement: Position du rendu dans le pipeline
Le système SHALL rendre le template d'une règle une seule fois par événement ayant passé le throttle, avant la mise en file d'attente, et transmettre le même message rendu à toutes les destinations de la règle.

#### Scenario: Plusieurs destinations
- **WHEN** une alerte autorisée par le throttle cible deux notificateurs
- **THEN** les deux reçoivent le même titre, le même corps et la même couleur d'accent
