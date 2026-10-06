## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Fonction link
**Reason**: Le nom `link` est masqué par tout champ d'événement nommé `link` (le rendu échoue sur « value of type string is not callable » et l'alerte part en message de repli) ; il n'a jamais été publié.
**Migration**: Remplacer `link(text, url)` par `md_link(text, url)` (voir « Fonction md_link »), mêmes arguments et même résultat.

### Requirement: Rendu d'essai des corps Markdown
**Reason**: Remplacée par « Rendu d'essai des corps Markdown avec échappement actif », qui nomme `md_link` au lieu de `link` et ajoute `urlencode`.
**Migration**: Aucune action côté configuration hormis le renommage de `link` en `md_link`.

## ADDED Requirements

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
