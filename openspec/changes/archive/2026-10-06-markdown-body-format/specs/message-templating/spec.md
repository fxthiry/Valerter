## MODIFIED Requirements

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

## ADDED Requirements

### Requirement: Échappement Markdown automatique du corps
Le système SHALL, pour un template `body_format: markdown`, rendre `body` en échappant chaque valeur insérée par `{{ … }}` (y compris via `| e`) : chaque caractère de ponctuation ASCII est préfixé d'une barre oblique inverse, si bien qu'une valeur du log est toujours lue comme du texte littéral ; le balisage écrit dans la source du template reste interprété.

#### Scenario: Valeur contenant de la ponctuation Markdown
- **WHEN** `body: "**{{ host }}** down"` est rendu avec `host=a_b*c`
- **THEN** le corps Markdown vaut `**a\_b\*c** down`

#### Scenario: Valeur indéfinie
- **WHEN** `body: "[{{ missing }}]"` est rendu sans le champ `missing`
- **THEN** le corps Markdown vaut `[]`, sans erreur

### Requirement: Désactivation de l'échappement Markdown
Le système SHALL insérer sans échappement Markdown une valeur marquée sûre : résultat de `| safe`, de `| tojson` ou des filtres et fonctions Markdown sûrs ; dans un template `markdown`, `| md_escape` MUST produire le même résultat que l'échappement automatique, sans double échappement.

#### Scenario: Balisage fourni par une valeur de confiance
- **WHEN** `body: "{{ summary | safe }}"` est rendu avec `summary=**OK**`
- **THEN** le corps Markdown vaut `**OK**` et le texte s'affiche en gras

#### Scenario: Pas de double échappement
- **WHEN** `body: "{{ host | md_escape }}"` est rendu avec `host=a_b`
- **THEN** le corps Markdown vaut `a\_b`

### Requirement: Filtre code
Le système SHALL fournir le filtre `code`, qui produit un span de code Markdown contenant la valeur littérale : délimiteur de backticks plus long que la plus longue suite de backticks de la valeur, et espace de bordure ajoutée lorsque la valeur commence ou finit par un backtick. Dans un template `markdown`, le résultat est sûr ; ailleurs, c'est une chaîne ordinaire, échappée selon le contexte.

#### Scenario: Valeur avec backticks
- **WHEN** `{{ v | code }}` est rendu dans un template `markdown` avec ``v = a`b``
- **THEN** le corps Markdown vaut ``` ``a`b`` ``` et le rendu affiche ``a`b`` en code

#### Scenario: Contenu littéral
- **WHEN** `{{ v | code }}` est rendu dans un template `markdown` avec `v = **x**`
- **THEN** le rendu affiche `**x**` en code, sans gras

### Requirement: Filtre codeblock
Le système SHALL fournir le filtre `codeblock(lang)` (langue optionnelle, réduite aux caractères `A-Z`, `a-z`, `0-9`, `_`, `+`, `-`, `.` et `#`), qui produit un bloc de code clôturé contenant la valeur littérale, avec une clôture de backticks plus longue (au moins trois) que la plus longue suite de backticks de la valeur. Dans un template `markdown`, le résultat est sûr ; il doit être placé seul sur sa ligne.

#### Scenario: Bloc avec langue
- **WHEN** `body: "Log:\n{{ _msg | codeblock('json') }}"` est rendu dans un template `markdown` avec `_msg = {"a": "<b>"}`
- **THEN** le rendu `html` contient `<pre><code class="language-json">{&quot;a&quot;: &quot;&lt;b&gt;&quot;}</code></pre>`

#### Scenario: Valeur contenant une clôture
- **WHEN** `{{ v | codeblock }}` est rendu dans un template `markdown` avec une valeur contenant ```` ``` ````
- **THEN** le bloc est clos par au moins quatre backticks et la valeur s'affiche entière dans le bloc

### Requirement: Fonction link
Le système SHALL fournir la fonction `link(text, url)`, qui produit un lien Markdown dont le texte est échappé et dont la destination encode en pourcentage les espaces, caractères de contrôle, `<`, `>`, `(`, `)` et `\` ; si le schéma de `url` n'est pas `http`, `https` ou `mailto`, elle produit le texte échappé suivi de l'URL entre parenthèses, sans lien. Dans un template `markdown`, le résultat est sûr.

#### Scenario: Lien vers VictoriaLogs
- **WHEN** `{{ link("logs " ~ host, "https://vl.example.com/select?q=host:" ~ host) }}` est rendu dans un template `markdown` avec `host=web_01`
- **THEN** le rendu `html` contient `<a href="https://vl.example.com/select?q=host:web_01">logs web_01</a>`

#### Scenario: Schéma refusé
- **WHEN** `{{ link("x", "javascript:alert(1)") }}` est rendu dans un template `markdown`
- **THEN** aucun rendu ne contient de lien et le texte affiché est `x (javascript:alert(1))`

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
Le système SHALL produire le rendu `telegram_html` d'un corps Markdown avec les seules balises du sous-ensemble HTML de l'API Bot Telegram (`b`, `i`, `s`, `code`, `pre`, `a`, `blockquote`), toujours équilibrées : titre en `<b>`, élément de liste préfixé de `• ` (ou de son numéro), filet rendu `———`, paragraphes séparés par une ligne vide, texte ré-échappé (`&`, `<`, `>`), `href` limité aux schémas `http`, `https` et `mailto`.

#### Scenario: Gras et valeur à souligné
- **WHEN** `body: "**{{ host }}** down"` est rendu avec `host=a_b*c`
- **THEN** le rendu `telegram_html` vaut `<b>a_b*c</b> down`

#### Scenario: Sortie toujours bien formée
- **WHEN** un corps Markdown quelconque, y compris des emphases non fermées, des backticks orphelins, `](`, `<nil>`, `\` et des caractères multioctets, est rendu en `telegram_html`
- **THEN** le résultat ne contient que des balises de la liste, chacune ouverte et fermée dans le bon ordre, et aucun `<` ou `&` nu hors balise et entité

### Requirement: Rendu markdown du corps Markdown
Le système SHALL produire le rendu `markdown` d'un corps Markdown en resérialisant le sous-ensemble reconnu, en échappant dans le texte `\`, `` ` ``, `*`, `_`, `[`, `]`, `~` et `|` par une barre oblique inverse, `#`, `+`, `-`, `=`, `>` et un nombre suivi de `.` ou `)` uniquement en début de ligne, en encodant `<` en `&lt;` et `&` en `&amp;` lorsqu'il commence une entité, et en laissant les autres caractères (`:`, `/`, `.`, `-` en milieu de ligne) inchangés.

#### Scenario: Valeurs courantes lisibles
- **WHEN** `body: "{{ host }} at {{ ts }}"` est rendu avec `host=web-01.example.com` et `ts=10:49:35`
- **THEN** le rendu `markdown` vaut `web-01.example.com at 10:49:35`

#### Scenario: Ponctuation Markdown neutralisée
- **WHEN** `body: "**{{ a }}** {{ b }}"` est rendu avec `a=a_b*c` et `b=<nil> &amp;`
- **THEN** le rendu `markdown` vaut `**a\_b\*c** &lt;nil> &amp;amp;`

### Requirement: Rendu d'essai des corps Markdown
Le système MUST effectuer le rendu d'essai du `body` d'un template `body_format: markdown` avec l'échappement Markdown actif, afin qu'aucune erreur liée à l'échappement n'interrompe la passe, et traiter les filtres `code`, `codeblock` et la fonction `link` comme les autres filtres et fonctions valerter (voir « Validation par rendu d'essai »).

#### Scenario: Filtre inconnu après une valeur échappée
- **WHEN** un template `body_format: markdown` a pour `body` `{{ host }} {{ host | nosuch }}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtres Markdown valides
- **WHEN** un template `markdown` a pour `body` `{{ _msg | codeblock('json') }} {{ host | code }} {{ link(host, url) }} {{ x | safe }}`
- **THEN** la validation réussit

#### Scenario: Filtre inconnu après link
- **WHEN** un `body_template` webhook vaut `{{ link(log.a, log.b) }} {{ log.c | nosuch }}`
- **THEN** l'instanciation du notifier échoue avec un message contenant `body_template render` et `nosuch`

### Requirement: Message de repli d'un template Markdown
Le système SHALL traiter le message de repli d'un template `body_format: markdown` (rendu en échec) comme un message `text` : son corps est transmis tel quel aux notifiers, sans analyse Markdown.

#### Scenario: Repli transmis en texte
- **WHEN** le rendu d'un template `markdown` échoue pour une alerte routée vers Telegram
- **THEN** le texte envoyé contient `Template render failed` échappé par le template Telegram, sans balise issue d'une analyse Markdown
