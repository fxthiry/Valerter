# message-templating Specification

## Purpose
Le templating transforme les champs d'un événement VictoriaLogs parsé en message d'alerte (titre, corps, corps HTML pour l'email, couleur d'accent) à l'aide de templates nommés au format Jinja2, rendus par minijinja. Il couvre le contexte de rendu, l'échappement HTML, le message de repli en cas d'erreur, les horodatages transmis aux notificateurs et la vérification des templates au démarrage. La validation de structure de la configuration relève de `configuration`, le calcul de la clé de throttle de `throttling`, et les templates propres aux notificateurs (`subject_template`, `body_template`) ainsi que l'envoi relèvent de `notifiers`.

## Requirements

### Requirement: Champs d'un template
Le système SHALL accepter, pour chaque template nommé de `templates` (ou de `templates.d/`), les champs `title` (obligatoire), `body` (obligatoire), `email_body_html` (optionnel), `accent_color` (optionnel) et `body_format` (optionnel, `text` ou `markdown`, défaut `text`), et MUST rejeter tout autre champ ainsi que toute autre valeur de `body_format`.

#### Scenario: Template minimal
- **WHEN** un template ne définit que `title: "{{ rule_name }}"` et `body: "{{ _msg }}"`
- **THEN** le template est accepté et son rendu ne produit ni corps HTML ni couleur d'accent

#### Scenario: Champ inconnu
- **WHEN** un template contient un champ `subject`
- **THEN** le chargement de la configuration échoue

#### Scenario: body_format par défaut
- **WHEN** un template ne définit pas `body_format`
- **THEN** il est traité comme `body_format: text` et son rendu est identique à celui d'un template sans ce champ

#### Scenario: Valeur de body_format inconnue
- **WHEN** un template déclare `body_format: md`
- **THEN** le chargement de la configuration échoue avec un message mentionnant `text` et `markdown`

### Requirement: Moteur minijinja et syntaxe Jinja2
Le système SHALL rendre `title`, `body` et `email_body_html` avec minijinja, en prenant en charge les expressions, conditions (`{% if %}`), boucles (`{% for %}`), les filtres intégrés de minijinja (ex. `default`, `upper`, `lower`, `length`, `tojson`, `urlencode`) et les filtres et fonctions propres à valerter décrits par cette spécification ; aucun autre filtre n'est fourni, si bien que des filtres absents de minijinja comme `truncate` sont inconnus. Les mêmes filtres et fonctions sont disponibles dans `throttle.key` et dans les templates des notifiers.

#### Scenario: Condition
- **WHEN** `title: "{% if severity == \"critical\" %}CRITICAL{% else %}Warning{% endif %}"` est rendu avec `severity=critical`
- **THEN** le titre vaut `CRITICAL`

#### Scenario: Filtre inexistant
- **WHEN** un template utilise `{{ _msg | truncate(50) }}`
- **THEN** le filtre est traité comme inconnu (rejet au démarrage, voir la validation par rendu d'essai)

#### Scenario: Filtre propre à valerter
- **WHEN** `body: "{{ host | md_escape }}"` est rendu avec `host=web_01`
- **THEN** le corps vaut `web\_01`

#### Scenario: Encodage d'une valeur pour une URL
- **WHEN** `body: "q={{ v | urlencode }}"` est rendu dans un template `text` avec `v = a&b c#d?e+f`
- **THEN** le corps vaut `q=a%26b%20c%23d%3Fe%2Bf`
- **AND** `valerter --validate` accepte un template utilisant `urlencode` sur un champ

### Requirement: Contexte de rendu issu de l'événement
Le système SHALL exposer comme variables de premier niveau tous les champs de l'événement parsé, y compris les champs VictoriaLogs présents (`_msg`, `_time`, `_stream`, `_stream_id`) et les champs extraits par le parseur, avec accès aux objets imbriqués par la notation pointée, et MUST préserver les caractères Unicode.

#### Scenario: Champs imbriqués
- **WHEN** `title: "Server: {{ data.server.hostname }}"` est rendu avec `{"data": {"server": {"hostname": "prod-server-01"}}}`
- **THEN** le titre vaut `Server: prod-server-01`

#### Scenario: Message brut et horodatage brut
- **WHEN** `body: "{{ _msg }} @ {{ _time }}"` est rendu sur un événement
- **THEN** le corps contient exactement le `_msg` et le `_time` de l'événement

### Requirement: Dépliage des clés pointées
Le système SHALL exposer chaque champ plat dont le nom contient des points (ex. `nginx.http.request_id`) également sous forme d'objets imbriqués, fusionnés avec les objets existants ; si le premier segment correspond déjà à un champ scalaire, ce scalaire est conservé, le dépliage de cette clé est ignoré et un avertissement est journalisé. Une clé de plus de 32 segments MUST NOT être dépliée : seule la clé plate est exposée et un avertissement est journalisé, sans interrompre le traitement de l'événement.

#### Scenario: Champ plat pointé
- **WHEN** `body: "id={{ nginx.http.request_id }}"` est rendu avec le champ plat `"nginx.http.request_id": "abc"`
- **THEN** le corps vaut `id=abc`

#### Scenario: Collision avec un scalaire
- **WHEN** l'événement contient `"a": "x"` et `"a.b": "y"`
- **THEN** `{{ a }}` vaut `x` et `{{ a.b }}` est rendu vide

#### Scenario: Clé pointée de 32 segments
- **WHEN** l'événement contient une clé formée de 32 segments `a` séparés par des points, valant `1`
- **THEN** la clé est dépliée et le chemin imbriqué de 32 niveaux vaut `1`

#### Scenario: Clé pointée démesurée
- **WHEN** l'événement contient une clé formée de 20 000 segments `a` séparés par des points (40 Ko)
- **THEN** l'alerte est rendue et envoyée, la clé reste accessible en notation crochets sous sa forme plate, aucun objet imbriqué n'est créé pour elle et le processus ne s'arrête pas

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
Le système SHALL échapper automatiquement en HTML les valeurs insérées dans `email_body_html`, tandis que `title` est toujours rendu sans aucun échappement et que `body` est rendu sans aucun échappement lorsque `body_format` vaut `text` (voir « Échappement Markdown automatique du corps » pour `markdown`).

#### Scenario: Injection de balise dans le corps HTML
- **WHEN** `email_body_html: "<p>Hostname: {{ hostname }}</p>"` est rendu avec `hostname=<script>alert(1)</script>`
- **THEN** le résultat contient `&lt;script&gt;` et ne contient pas `<script>`

#### Scenario: Balise dans le corps texte
- **WHEN** `body: "{{ hostname }}"` est rendu avec la même valeur
- **THEN** le corps contient `<script>alert(1)</script>` tel quel

#### Scenario: Titre d'un template Markdown
- **WHEN** un template `body_format: markdown` a `title: "{{ host }} down"` et est rendu avec `host=web_01`
- **THEN** le titre vaut `web_01 down`, sans barre oblique inverse

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
Le système MUST refuser de démarrer le démon lorsqu'une règle activée a au moins une destination de type email et que son template, de `body_format` `text`, ne définit pas `email_body_html`, avec l'erreur `template '<t>' requires email_body_html field when used with email destination '<dest>' (rule '<r>')` puis l'échec `Email template validation failed: <n> errors` ; cette vérification est également effectuée par `--validate`, qui se termine alors avec le code 1. Un template `body_format: markdown` sans `email_body_html` est accepté : son rendu `html` sert de corps.

#### Scenario: Template sans corps HTML vers un email
- **WHEN** la règle activée `r` utilise le template `t` sans `email_body_html` et la destination email `ops-mail`
- **THEN** le démarrage échoue avec `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')`

#### Scenario: Règle désactivée
- **WHEN** la même règle est désactivée
- **THEN** aucune erreur n'est levée pour ce template

#### Scenario: Détection par --validate
- **WHEN** `valerter --validate` est lancé sur la configuration de la règle activée `r` ci-dessus
- **THEN** l'erreur `template 't' requires email_body_html field when used with email destination 'ops-mail' (rule 'r')` est journalisée et le code de sortie est 1

#### Scenario: Template Markdown sans corps HTML
- **WHEN** la règle activée `r` utilise vers `ops-mail` un template `body_format: markdown` sans `email_body_html`
- **THEN** le démarrage et `valerter --validate` réussissent

### Requirement: Position du rendu dans le pipeline
Le système SHALL rendre le template d'une règle une seule fois par événement ayant passé le throttle, avant la mise en file d'attente, et transmettre le même message rendu à toutes les destinations de la règle.

#### Scenario: Plusieurs destinations
- **WHEN** une alerte autorisée par le throttle cible deux notificateurs
- **THEN** les deux reçoivent le même titre, le même corps et la même couleur d'accent

### Requirement: Champs du log dans les templates de notifier
Le système SHALL exposer dans les templates des notifiers (`body_template` webhook, Telegram et email, `subject_template` email) une variable `log` contenant tous les champs de l'événement parsé, dans la même vue que le contexte du template de règle (clés plates conservées et dépliage des clés pointées), sans les variables synthétiques `rule_name` et `vl_source` ; un champ absent MUST être rendu vide sans erreur.

#### Scenario: Champ simple
- **WHEN** un `body_template` vaut `{{ log.host }}: {{ body }}` pour un événement `host=web-01` dont le corps rendu est `disk full`
- **THEN** le texte rendu vaut `web-01: disk full`

#### Scenario: Clé pointée en notation crochets et dépliée
- **WHEN** l'événement porte le champ plat `"k8s.pod": "api-7f"` et le template contient `{{ log["k8s.pod"] }}|{{ log.k8s.pod }}`
- **THEN** le rendu vaut `api-7f|api-7f`

#### Scenario: Champ absent
- **WHEN** un `subject_template` vaut `[{{ log.missing }}] {{ title }}` pour une alerte de titre `T`
- **THEN** le sujet vaut `[] T` et aucune erreur n'est levée

#### Scenario: Variables synthétiques hors de log
- **WHEN** un template de notifier contient `{{ log.rule_name }}` pour un événement sans champ `rule_name`
- **THEN** le rendu est vide, `{{ rule_name }}` restant la seule source du nom de règle

#### Scenario: Valeurs brutes en JSON
- **WHEN** un `body_template` webhook contient `{"details": {{ log | tojson }}}`
- **THEN** le corps envoyé est un JSON valide dont `details` contient les champs de l'événement, y compris `_msg` et `_time`

#### Scenario: Template de règle inchangé
- **WHEN** un template de règle contient `{{ log }}` et que l'événement porte un champ `log` valant `container output`
- **THEN** le rendu vaut `container output` : `log` n'est pas injecté au niveau du template de règle

### Requirement: Filtre md_escape
Le système SHALL fournir le filtre `md_escape`, qui convertit sa valeur en chaîne et préfixe d'une barre oblique inverse chacun des caractères `\`, `` ` ``, `*`, `_`, `{`, `}`, `[`, `]`, `(`, `)`, `#`, `+`, `-`, `.`, `!`, `>`, `|` et `~`, laissant tout autre caractère (dont `<`, `&`, `:` et `/`) inchangé, afin qu'une valeur insérée dans un corps Markdown destiné à Mattermost s'affiche littéralement.

#### Scenario: Ponctuation Markdown
- **WHEN** `{{ v | md_escape }}` est rendu avec `v = *a_b* [x](y)`
- **THEN** le résultat vaut `\*a\_b\* \[x\]\(y\)`

#### Scenario: Caractères conservés
- **WHEN** `{{ v | md_escape }}` est rendu avec `v = https://h:8080/p?a=1&b=<2>`
- **THEN** le résultat vaut `https://h:8080/p?a=1&b=<2\>` : seul `>`, qui appartient au jeu, est échappé

#### Scenario: Caractères multioctets
- **WHEN** `{{ v | md_escape }}` est rendu avec `v = déjà_vu 🔥`
- **THEN** le résultat vaut `déjà\_vu 🔥`

### Requirement: Filtre mdv2_escape
Le système SHALL fournir le filtre `mdv2_escape`, qui convertit sa valeur en chaîne et préfixe d'une barre oblique inverse chacun des 18 caractères réservés de Telegram MarkdownV2 (`_`, `*`, `[`, `]`, `(`, `)`, `~`, `` ` ``, `>`, `#`, `+`, `-`, `=`, `|`, `{`, `}`, `.`, `!`) ainsi que la barre oblique inverse elle-même, pour le texte hors entités `pre` et `code`.

#### Scenario: Caractères réservés
- **WHEN** `{{ v | mdv2_escape }}` est rendu avec `v = a.b-c=d!`
- **THEN** le résultat vaut `a\.b\-c\=d\!`

#### Scenario: Barre oblique inverse
- **WHEN** `{{ v | mdv2_escape }}` est rendu avec `v = C:\temp`
- **THEN** le résultat vaut `C:\\temp`

### Requirement: Rendu d'essai des filtres propres à valerter
Le système MUST traiter les filtres et fonctions propres à valerter dans tout rendu d'essai (templates de règle, `throttle.key`, `subject_template`, `body_template`) comme les filtres intégrés : appliqués à un champ fictif, ils MUST NOT interrompre le rendu d'essai, et la suite du template reste vérifiée.

#### Scenario: Filtre inconnu après md_escape
- **WHEN** le `body` d'un template vaut `{{ host | md_escape }} {{ host | nosuch }}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtres d'échappement valides
- **WHEN** un `body_template` Telegram vaut `{{ log.host | mdv2_escape }} {{ log.msg | md_escape | upper }}`
- **THEN** le notifier est créé sans erreur

### Requirement: Avertissement sur les variables inconnues des templates de notifier
Le système SHALL, à l'instanciation d'un notifier (démarrage du démon et `--validate`), journaliser un avertissement `Notifier template references unknown variable` avec le nom du notifier, le champ (`body_template` ou `subject_template`) et le nom de la variable, pour chaque variable de premier niveau lue par le template qui n'appartient ni au contexte de ce template ni aux fonctions globales ; cet avertissement MUST NOT faire échouer la validation.

#### Scenario: Champ du log référencé sans log
- **WHEN** le notifier webhook `hook` a pour `body_template` `{"host": {{ host | tojson }}}`
- **THEN** l'avertissement est journalisé pour `hook`, `body_template` et `host`, et `valerter --validate` se termine avec le code 0

#### Scenario: Variables connues
- **WHEN** un `body_template` n'utilise que `title`, `body`, `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted`, `log`, des variables de boucle ou de `set` et `range`
- **THEN** aucun avertissement n'est journalisé

### Requirement: Échappement Markdown automatique du corps
Le système SHALL, pour un template `body_format: markdown`, rendre `body` en échappant chaque valeur insérée par `{{ … }}` (y compris via `| e` et `| tojson`) : chaque caractère de ponctuation ASCII est préfixé d'une barre oblique inverse, si bien qu'une valeur du log est toujours lue comme du texte littéral ; le balisage écrit dans la source du template reste interprété. Les caractères U+E000 et U+E001 d'une valeur insérée MUST être remplacés par U+FFFD, afin qu'aucune valeur ne puisse reproduire le résultat d'un filtre Markdown.

#### Scenario: Valeur contenant de la ponctuation Markdown
- **WHEN** `body: "**{{ host }}** down"` est rendu avec `host=a_b*c`
- **THEN** le corps Markdown vaut `**a\_b\*c** down`

#### Scenario: Valeur indéfinie
- **WHEN** `body: "[{{ missing }}]"` est rendu sans le champ `missing`
- **THEN** le corps Markdown vaut `[]`, sans erreur

#### Scenario: Valeur imitant un filtre Markdown
- **WHEN** `body: "{{ v }} {{ w | code }}"` est rendu avec `v` formé de U+E000, `0` et U+E001, et `w=x`
- **THEN** le rendu `plain` vaut U+FFFD, `0`, U+FFFD, une espace puis `x`

### Requirement: Désactivation de l'échappement Markdown
Le système SHALL insérer sans échappement Markdown une valeur marquée sûre par `| safe`, seule échappatoire offerte aux valeurs ; le résultat de `| tojson` MUST être échappé comme toute autre valeur dans un template `markdown`. Les filtres et fonctions Markdown (`code`, `codeblock`, `md_link`) produisent leur élément Markdown (voir « Contenu littéral des filtres Markdown ») ; dans un template `markdown`, `| md_escape` MUST produire le même résultat que l'échappement automatique, sans double échappement.

#### Scenario: Balisage fourni par une valeur de confiance
- **WHEN** `body: "{{ summary | safe }}"` est rendu avec `summary=**OK**`
- **THEN** le corps Markdown vaut `**OK**` et le texte s'affiche en gras

#### Scenario: Pas de double échappement
- **WHEN** `body: "{{ host | md_escape }}"` est rendu avec `host=a_b`
- **THEN** le corps Markdown vaut `a\_b`

#### Scenario: Résultat de tojson échappé
- **WHEN** `body: "{{ v | tojson }}"` est rendu dans un template `markdown` avec `v = **bold** [phish](https://evil.example)`
- **THEN** aucun rendu ne contient `<strong>`, `<b>` ni `href`, et le rendu `plain` vaut `"**bold** [phish](https://evil.example)"`

### Requirement: Filtre code
Le système SHALL fournir le filtre `code`, qui produit un span de code Markdown contenant la valeur littérale : délimiteur de backticks plus long que la plus longue suite de backticks de la valeur, et espace de bordure ajoutée lorsque la valeur commence ou finit par un backtick ; un saut de ligne de la valeur devient une espace. Dans un template `markdown`, le contenu reste littéral quel que soit l'emplacement du filtre (voir « Contenu littéral des filtres Markdown ») ; ailleurs, c'est une chaîne ordinaire, échappée selon le contexte.

#### Scenario: Valeur avec backticks
- **WHEN** `{{ v | code }}` est rendu dans un template `markdown` avec ``v = a`b``
- **THEN** le rendu `markdown` vaut ``` ``a`b`` ``` et le rendu affiche ``a`b`` en code

#### Scenario: Contenu littéral
- **WHEN** `{{ v | code }}` est rendu dans un template `markdown` avec `v = **x**`
- **THEN** le rendu affiche `**x**` en code, sans gras

#### Scenario: Code dans un titre
- **WHEN** `body: "# Host {{ v | code }}"` est rendu dans un template `markdown` avec `v = [a](https://evil.example)`
- **THEN** le rendu `html` vaut `<h1>Host <code>[a](https://evil.example)</code></h1>` et ne contient pas `href`

### Requirement: Filtre codeblock
Le système SHALL fournir le filtre `codeblock(lang)` (langue optionnelle, réduite aux caractères `A-Z`, `a-z`, `0-9`, `_`, `+`, `-`, `.` et `#`), qui produit un bloc de code contenant la valeur littérale, avec, dans le rendu `markdown`, une clôture de backticks plus longue (au moins trois) que la plus longue suite de backticks de la valeur. Dans un template `markdown`, le contenu reste littéral quel que soit l'emplacement du filtre (voir « Contenu littéral des filtres Markdown »), sans qu'il soit nécessaire de le placer seul sur sa ligne ; ailleurs, c'est une chaîne ordinaire.

#### Scenario: Bloc avec langue
- **WHEN** `body: "Log:\n{{ _msg | codeblock('json') }}"` est rendu dans un template `markdown` avec `_msg = {"a": "<b>"}`
- **THEN** le rendu `html` contient `<pre><code class="language-json">{&quot;a&quot;: &quot;&lt;b&gt;&quot;}</code></pre>`

#### Scenario: Valeur contenant une clôture
- **WHEN** `{{ v | codeblock }}` est rendu dans un template `markdown` avec une valeur contenant ```` ``` ````
- **THEN** le bloc du rendu `markdown` est clos par au moins quatre backticks et la valeur s'affiche entière dans le bloc

#### Scenario: Bloc dans un élément de liste
- **WHEN** `body: "- x\n- {{ v | codeblock }}"` est rendu dans un template `markdown` avec `v = a\n# b\n[c](https://evil.example)`
- **THEN** le second élément du rendu `html` contient `<pre><code>a\n# b\n[c](https://evil.example)</code></pre>`
- **AND** aucun rendu ne contient `<h1>`, `href` ni de lien Markdown actif

#### Scenario: Bloc dans une citation
- **WHEN** `body: "> {{ v | codeblock }}"` est rendu dans un template `markdown` avec `v = a\n<b>x</b>`
- **THEN** le rendu `telegram_html` vaut `<blockquote><pre>a\n&lt;b&gt;x&lt;/b&gt;</pre></blockquote>`

#### Scenario: Bloc sur une ligne indentée
- **WHEN** `body: "    {{ v | codeblock }}"` est rendu dans un template `markdown` avec `v = a\n**b**`
- **THEN** le rendu `plain` vaut `a\n**b**` et aucun rendu ne contient de gras

#### Scenario: Bloc au milieu d'une ligne
- **WHEN** `body: "Log: {{ v | codeblock }} end"` est rendu dans un template `markdown` avec `v = a\nb`
- **THEN** le rendu `plain` vaut `Log:\n\na\nb\n\nend` : le paragraphe est coupé autour du bloc

### Requirement: Sous-ensemble Markdown reconnu
Le système SHALL analyser le corps d'un template `markdown` en CommonMark avec le barré (`~~`) et ne reconnaître que : paragraphe, saut de ligne, gras, italique, barré, code, bloc de code, lien, image (traitée comme un lien vers l'image, avec son texte alternatif), citation, liste, titre et filet ; tout HTML brut MUST être rendu comme texte littéral, les tableaux ne sont pas reconnus (texte), et un saut de ligne simple MUST être rendu comme un saut de ligne forcé.

#### Scenario: HTML brut dans la source
- **WHEN** `body: "<b>x</b> {{ v }}"` est rendu dans un template `markdown` avec `v=y`
- **THEN** le rendu `telegram_html` vaut `&lt;b&gt;x&lt;/b&gt; y`

#### Scenario: Saut de ligne simple
- **WHEN** `body: "ligne 1\nligne 2"` est rendu dans un template `markdown`
- **THEN** le rendu `plain` vaut `ligne 1\nligne 2` et le rendu `html` vaut `<p>ligne 1<br>\nligne 2</p>`

#### Scenario: Tableau non reconnu
- **WHEN** le corps contient `| a | b |\n|---|---|`
- **THEN** aucun rendu ne contient de tableau ; les lignes s'affichent comme texte

### Requirement: Rendu plain du corps Markdown
Le système SHALL produire le rendu `plain` d'un corps Markdown sans aucun balisage : texte des emphases et du code sans délimiteurs, lien rendu `texte (url)` (ou l'URL seule si le texte lui est identique), élément de liste préfixé de `- ` (ou de son numéro), titre sur sa propre ligne, citation préfixée de `> `, filet rendu `---`, paragraphes séparés par une ligne vide.

#### Scenario: Valeurs hostiles en texte brut
- **WHEN** `body: "**{{ a }}** {{ b }} {{ c }}"` est rendu avec `a=<nil>`, `b=&amp;` et `c=](x)`
- **THEN** le rendu `plain` vaut `<nil> &amp; ](x)`

#### Scenario: Lien en texte brut
- **WHEN** le corps vaut `[Voir](https://vl.example.com)`
- **THEN** le rendu `plain` vaut `Voir (https://vl.example.com)`

### Requirement: Rendu html du corps Markdown
Le système SHALL produire le rendu `html` d'un corps Markdown avec les seuls éléments `p`, `br`, `strong`, `em`, `del`, `code`, `pre`, `a`, `blockquote`, `ul`, `ol`, `li`, `h1` à `h6` et `hr`, en échappant `&`, `<`, `>`, `"` et `'` dans le texte et les attributs, et en n'émettant `href` que pour les schémas `http`, `https` et `mailto` (sinon le lien est rendu `texte (url)`).

#### Scenario: Valeurs hostiles en HTML
- **WHEN** `body: "**{{ a }}** {{ b }}"` est rendu avec `a=<script>` et `b=&amp;`
- **THEN** le rendu `html` vaut `<p><strong>&lt;script&gt;</strong> &amp;amp;</p>`

#### Scenario: Lien Markdown écrit dans la source avec un schéma refusé
- **WHEN** le corps vaut `[clic](javascript:alert(1))`
- **THEN** le rendu `html` ne contient pas `href` et affiche `clic (javascript:alert(1))`

### Requirement: Rendu telegram_html du corps Markdown
Le système SHALL produire le rendu `telegram_html` d'un corps Markdown avec les seules balises du sous-ensemble HTML de l'API Bot Telegram (`b`, `i`, `s`, `code`, `pre`, `a`, `blockquote`), toujours équilibrées : titre en `<b>`, élément de liste préfixé de `• ` (ou de son numéro), filet rendu `———`, paragraphes séparés par une ligne vide, texte ré-échappé (`&`, `<`, `>`), `href` limité aux schémas `http`, `https` et `mailto`. Le rendu MUST respecter les règles d'imbrication de l'API Bot : `code` et `pre` ne contiennent aucune autre balise et n'ont pour ancêtre que `blockquote` ; `a` ne contient ni `a` ni `blockquote` ; `blockquote` n'est jamais imbriqué ; `b`, `i`, `s` ne sont jamais imbriqués dans une balise de même nom. Un élément qui ne peut pas être imbriqué est rendu par son seul contenu, en texte échappé.

#### Scenario: Gras et valeur à souligné
- **WHEN** `body: "**{{ host }}** down"` est rendu avec `host=a_b*c`
- **THEN** le rendu `telegram_html` vaut `<b>a_b*c</b> down`

#### Scenario: Sortie toujours bien formée
- **WHEN** un corps Markdown quelconque, y compris des emphases non fermées, des backticks orphelins, `](`, `<nil>`, `\` et des caractères multioctets, est rendu en `telegram_html`
- **THEN** le résultat ne contient que des balises de la liste, chacune ouverte et fermée dans le bon ordre, et aucun `<` ou `&` nu hors balise et entité

#### Scenario: Code dans un lien
- **WHEN** le corps vaut ``[`x`](https://h.example)``
- **THEN** le rendu `telegram_html` vaut `<a href="https://h.example">x</a>`

#### Scenario: Code dans du gras ou un titre
- **WHEN** le corps vaut ``**a `x` b**`` puis ``# T `y` ``
- **THEN** les rendus `telegram_html` valent respectivement `<b>a x b</b>` et `<b>T y</b>`

#### Scenario: Gras dans du gras
- **WHEN** le corps vaut `**a __b__ c**`
- **THEN** le rendu `telegram_html` vaut `<b>a b c</b>`

#### Scenario: Imbrications permises conservées
- **WHEN** le corps vaut `> **[t](https://h.example)**` suivi d'une ligne `>` puis d'un bloc de code ```` ``` ```` contenant `x`, dans la même citation
- **THEN** le rendu `telegram_html` contient `<blockquote><b><a href="https://h.example">t</a></b>` et `<pre>x</pre></blockquote>`

#### Scenario: Règles d'imbrication toujours respectées
- **WHEN** un corps Markdown quelconque combinant code, blocs de code, liens, emphases, titres et citations imbriqués est rendu en `telegram_html`
- **THEN** aucune balise `code` ou `pre` ne contient de balise ni n'a d'ancêtre autre que `blockquote` (hors `<pre><code class="language-…">`), aucun `a` ne contient `a` ou `blockquote`, aucun `blockquote` n'est imbriqué et aucun `b`, `i` ou `s` n'est contenu dans une balise de même nom

### Requirement: Rendu markdown du corps Markdown
Le système SHALL produire le rendu `markdown` d'un corps Markdown en resérialisant le sous-ensemble reconnu, en échappant dans le texte `\`, `` ` ``, `*`, `_`, `[`, `]`, `~` et `|` par une barre oblique inverse, `#`, `+`, `-`, `=`, `>` et un nombre suivi de `.` ou `)` uniquement en début de ligne, en encodant `<` en `&lt;` et `&` en `&amp;` lorsqu'il commence une entité, et en laissant les autres caractères (`:`, `/`, `.`, `-` en milieu de ligne) inchangés.

#### Scenario: Valeurs courantes lisibles
- **WHEN** `body: "{{ host }} at {{ ts }}"` est rendu avec `host=web-01.example.com` et `ts=10:49:35`
- **THEN** le rendu `markdown` vaut `web-01.example.com at 10:49:35`

#### Scenario: Ponctuation Markdown neutralisée
- **WHEN** `body: "**{{ a }}** {{ b }}"` est rendu avec `a=a_b*c` et `b=<nil> &amp;`
- **THEN** le rendu `markdown` vaut `**a\_b\*c** &lt;nil> &amp;amp;`

### Requirement: Message de repli d'un template Markdown
Le système SHALL traiter le message de repli d'un template `body_format: markdown` (rendu en échec) comme un message `text` : son corps est transmis tel quel aux notifiers, sans analyse Markdown.

#### Scenario: Repli transmis en texte
- **WHEN** le rendu d'un template `markdown` échoue pour une alerte routée vers Telegram
- **THEN** le texte envoyé contient `Template render failed` échappé par le template Telegram, sans balise issue d'une analyse Markdown

### Requirement: Fonction md_link
Le système SHALL fournir la fonction `md_link(text, url)`, qui produit un lien dont le texte est littéral et dont la destination encode en pourcentage les espaces, caractères de contrôle, `<`, `>`, `(`, `)` et `\` ; si le schéma de `url` n'est pas `http`, `https` ou `mailto`, elle produit le texte suivi de l'URL entre parenthèses, sans lien. Un champ d'événement nommé `link` MUST NOT la masquer.

#### Scenario: Lien vers VictoriaLogs
- **WHEN** `{{ md_link("logs " ~ host, "https://vl.example.com/select?q=host:" ~ host) }}` est rendu dans un template `markdown` avec `host=web_01`
- **THEN** le rendu `html` contient `<a href="https://vl.example.com/select?q=host:web_01">logs web_01</a>`

#### Scenario: Valeur encodée dans l'URL
- **WHEN** `{{ md_link("logs", "https://vl.example.com/select?q=" ~ ("host:" ~ host) | urlencode) }}` est rendu dans un template `markdown` avec `host=a&b #1`
- **THEN** le rendu `html` contient `href="https://vl.example.com/select?q=host%3Aa%26b%20%231"`

#### Scenario: Schéma refusé
- **WHEN** `{{ md_link("x", "javascript:alert(1)") }}` est rendu dans un template `markdown`
- **THEN** aucun rendu ne contient de lien et le texte affiché est `x (javascript:alert(1))`

#### Scenario: Champ d'événement nommé link
- **WHEN** `body: "{{ md_link('x', 'https://a.example') }}"` est rendu dans un template `markdown` pour un événement portant `link=https://y.example`
- **THEN** le rendu `html` contient `<a href="https://a.example">x</a>` et le message n'est pas le message de repli

#### Scenario: Lien dans un lien
- **WHEN** `body: "[voir {{ md_link('x', 'https://a.example') }}](https://b.example)"` est rendu dans un template `markdown`
- **THEN** le rendu `html` vaut `<p><a href="https://b.example">voir x (https://a.example)</a></p>` : un seul `href`, le lien intérieur étant rendu en texte

### Requirement: Contenu littéral des filtres Markdown
Le système SHALL, dans un template `markdown`, rendre le contenu de `code`, `codeblock` et `md_link` littéral quel que soit l'emplacement du filtre : aucune partie de la valeur ne MUST être interprétée comme du Markdown, même lorsque le filtre suit un marqueur de liste, de citation, une indentation ou du texte sur la même ligne. Un bloc de code placé là où un bloc est impossible est rendu en span de code.

#### Scenario: Bloc dans une emphase
- **WHEN** `body: "**{{ v | codeblock }}**"` est rendu dans un template `markdown` avec `v = a\n[b](https://evil.example)`
- **THEN** le rendu `html` vaut `<p><strong><code>a [b](https://evil.example)</code></strong></p>`

#### Scenario: Filtre dans un bloc de code du template
- **WHEN** `body` contient une clôture ```` ``` ````, la ligne `{{ v | code }}` puis la clôture fermante, avec `v = *x*`
- **THEN** le rendu `plain` vaut `*x*`, sans barre oblique inverse

#### Scenario: Résultat converti en chaîne
- **WHEN** `body: "{{ (v | code) ~ '!' }}"` est rendu dans un template `markdown` avec `v=x`
- **THEN** le rendu `plain` vaut `` `x`! `` : le résultat, devenu une chaîne ordinaire, est échappé comme une valeur

### Requirement: Profondeur d'imbrication bornée du corps Markdown
Le système SHALL limiter à 32 la profondeur d'imbrication des éléments reconnus dans un corps Markdown ; un élément plus profond n'est pas reconnu comme tel mais son texte est conservé. Aucun corps, quelle que soit sa taille (jusqu'à la taille maximale d'une ligne de log), ne MUST pouvoir arrêter le processus lors de l'analyse, du rendu ou de la libération du message.

#### Scenario: Emphases imbriquées
- **WHEN** `body: "{{ v | safe }}"` est rendu avec `v` formé de 50 000 `*`, d'un `a` et de 50 000 `*`, sur un fil d'exécution disposant de 2 Mio de pile
- **THEN** les quatre rendus aboutissent et contiennent `a`

#### Scenario: Citations imbriquées
- **WHEN** `body: "{{ v | safe }}"` est rendu avec `v` formé de 50 000 fois `> ` suivis de `a`, sur un fil de 2 Mio de pile
- **THEN** les quatre rendus aboutissent, contiennent `a`, et le rendu `telegram_html` ne contient qu'un seul `<blockquote>`

#### Scenario: Listes imbriquées
- **WHEN** `body: "{{ v | safe }}"` est rendu avec `v` formé de 50 000 fois `- ` suivis de `a` (listes imbriquées sur une ligne), sur un fil de 2 Mio de pile
- **THEN** les quatre rendus aboutissent et contiennent `a`

### Requirement: Sauts de ligne et indentation des valeurs dans un corps Markdown
Le système SHALL, dans un template `markdown`, écrire chaque saut de ligne d'une valeur échappée (LF, CRLF ou CR) comme un saut de ligne, remplacer chaque espace de tête d'une ligne de la valeur par U+00A0 (quatre pour une tabulation) et écrire une ligne vide de la valeur comme un U+00A0 seul, afin qu'une valeur ne puisse ni terminer un paragraphe, une emphase ou un élément, ni ouvrir un bloc de code indenté.

#### Scenario: Ligne vide dans une emphase
- **WHEN** `body: "**{{ v }}**"` est rendu avec `v = a\n\nb`
- **THEN** le rendu `html` vaut `<p><strong>a<br>\n` suivi de U+00A0, `<br>\nb</strong></p>`, sans `**` littéral

#### Scenario: Indentation après une ligne vide
- **WHEN** `body: "{{ v }}"` est rendu avec `v = a\n\n    code`
- **THEN** aucun rendu ne contient de bloc de code et le rendu `plain` vaut `a`, un saut de ligne, U+00A0, un saut de ligne, quatre U+00A0 et `code`

### Requirement: Rendu d'essai des corps Markdown avec échappement actif
Le système MUST effectuer le rendu d'essai du `body` d'un template `body_format: markdown` avec l'échappement Markdown actif, afin qu'aucune erreur liée à l'échappement n'interrompe la passe, et traiter les filtres `code`, `codeblock`, `urlencode`, `tojson` et la fonction `md_link` comme les autres filtres et fonctions (voir « Validation par rendu d'essai »).

#### Scenario: Filtre inconnu après une valeur échappée
- **WHEN** un template `body_format: markdown` a pour `body` `{{ host }} {{ host | nosuch }}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtres Markdown valides
- **WHEN** un template `markdown` a pour `body` `{{ _msg | codeblock('json') }} {{ host | code }} {{ md_link(host, url ~ (host | urlencode)) }} {{ x | safe }} {{ x | tojson }}`
- **THEN** la validation réussit

#### Scenario: Filtre inconnu après md_link
- **WHEN** un `body_template` webhook vaut `{{ md_link(log.a, log.b) }} {{ log.c | nosuch }}`
- **THEN** l'instanciation du notifier échoue avec un message contenant `body_template render` et `nosuch`
