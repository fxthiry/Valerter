## MODIFIED Requirements

### Requirement: Moteur minijinja et syntaxe Jinja2
Le système SHALL rendre `title`, `body` et `email_body_html` avec minijinja, en prenant en charge les expressions, conditions (`{% if %}`), boucles (`{% for %}`), les filtres intégrés de minijinja (ex. `default`, `upper`, `lower`, `length`, `tojson`) et les filtres et fonctions propres à valerter décrits par cette spécification ; aucun autre filtre n'est fourni, si bien que des filtres absents de minijinja comme `truncate` sont inconnus. Les mêmes filtres et fonctions sont disponibles dans `throttle.key` et dans les templates des notifiers.

#### Scenario: Condition
- **WHEN** `title: "{% if severity == \"critical\" %}CRITICAL{% else %}Warning{% endif %}"` est rendu avec `severity=critical`
- **THEN** le titre vaut `CRITICAL`

#### Scenario: Filtre inexistant
- **WHEN** un template utilise `{{ _msg | truncate(50) }}`
- **THEN** le filtre est traité comme inconnu (rejet au démarrage, voir la validation par rendu d'essai)

#### Scenario: Filtre propre à valerter
- **WHEN** `body: "{{ host | md_escape }}"` est rendu avec `host=web_01`
- **THEN** le corps vaut `web\_01`

## ADDED Requirements

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
- **THEN** le résultat vaut `https://h:8080/p?a=1&b=<2>`

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
