# notifier-telegram Specification

## Purpose
Le notifier `telegram` envoie chaque alerte à une ou plusieurs discussions Telegram via la méthode `sendMessage` de
l'API Bot, configurée dans `notifiers.<nom>` avec `type: telegram`. Cette capacité couvre la configuration (jeton du
bot, `chat_ids`, `parse_mode`, options de livraison, `body_template`), la validation au démarrage, la construction du
texte (template, garde-fou contre les rendus vides, troncature), l'envoi par discussion, les relances (dont le HTTP 429),
les métriques propres au notifier et la protection du jeton. La file d'envoi, le registre et le routage relèvent de
`notification-dispatch` ; le rendu des templates de message de premier niveau (`title`, `body`) relève de
`message-templating`.

## Requirements

### Requirement: Schéma de configuration Telegram
Le système SHALL accepter un notifier `type: telegram` avec les clés obligatoires `bot_token` (chaîne) et `chat_ids`
(liste de chaînes), et les clés optionnelles `parse_mode` (défaut `HTML`), `disable_notification`,
`disable_web_page_preview` (booléens, non transmis s'ils sont absents), `body_template` et `format` (`telegram_html`
ou `plain`, voir `notification-dispatch`) ; toute clé inconnue MUST être rejetée au chargement.

#### Scenario: Valeurs par défaut
- **WHEN** un notifier déclare seulement `type: telegram`, `bot_token` et `chat_ids`
- **THEN** le notifier est créé avec `parse_mode` `HTML`, sans `disable_notification` ni `disable_web_page_preview`, avec le template de corps par défaut et le format de sortie `telegram_html`

#### Scenario: Clé inconnue rejetée
- **WHEN** le notifier contient une clé non prévue (par exemple `chat_id`)
- **THEN** le chargement de la configuration échoue

### Requirement: Validation des chat_ids
Le système MUST refuser au démarrage un notifier dont `chat_ids` est vide, avec le message
`chat_ids must not be empty`, ou dont un élément est vide ou composé uniquement d'espaces, avec le message
`chat_ids[<index>] must not be empty` (index à partir de 0).

#### Scenario: Liste vide
- **WHEN** `chat_ids: []` est configuré
- **THEN** la création du notifier échoue avec `invalid notifier '<nom>': chat_ids must not be empty`

#### Scenario: Élément vide
- **WHEN** `chat_ids: ["-100123", "  "]` est configuré
- **THEN** la création du notifier échoue avec `invalid notifier '<nom>': chat_ids[1] must not be empty`

### Requirement: Résolution du jeton du bot
Le système SHALL remplacer les motifs `${NOM_VAR}` de `bot_token` par la valeur de la variable d'environnement au
démarrage et MUST refuser la configuration si une variable référencée n'est pas définie (message préfixé par
`bot_token:`) ou si le jeton résolu est vide ou composé uniquement d'espaces (message
`bot_token resolved to an empty value`).

#### Scenario: Variable non définie
- **WHEN** `bot_token: "${TELEGRAM_BOT_TOKEN}"` est configuré et que la variable n'existe pas
- **THEN** la création du notifier échoue avec un message préfixé par `bot_token:` qui contient `undefined environment variable`

#### Scenario: Jeton résolu vide
- **WHEN** la variable référencée par `bot_token` est définie à une chaîne vide
- **THEN** la création du notifier échoue avec `bot_token resolved to an empty value`

### Requirement: Validation du body_template au démarrage
Le système MUST refuser au démarrage un `body_template` qui n'est pas un template Jinja syntaxiquement valide, avec un
message préfixé par `body_template:`.

#### Scenario: Template invalide
- **WHEN** `body_template: "{{ title"` est configuré
- **THEN** la création du notifier échoue avec un message préfixé par `body_template:`

### Requirement: Appel à l'API Bot
Le système SHALL envoyer chaque message par une requête HTTP `POST` vers
`https://api.telegram.org/bot<jeton>/sendMessage` avec un corps JSON contenant `chat_id`, `text` et `parse_mode`, plus
`disable_notification` et `disable_web_page_preview` uniquement lorsqu'ils sont configurés, avec un délai d'attente de
10 s par requête.

#### Scenario: Corps de requête sans options
- **WHEN** une alerte est envoyée par un notifier sans `disable_notification` ni `disable_web_page_preview`
- **THEN** le JSON envoyé contient exactement `chat_id`, `text` et `parse_mode`

#### Scenario: Options transmises
- **WHEN** `disable_notification: true` et `disable_web_page_preview: true` sont configurés
- **THEN** le JSON envoyé contient `"disable_notification": true` et `"disable_web_page_preview": true`

### Requirement: Rendu du texte
Le système SHALL rendre le texte une seule fois par alerte avec `body_template`, ou à défaut avec
`<b>{{ title|e }}</b>\n{{ body|e }}`, dans un contexte exposant `title`, `body` (le corps transmis au notifier, voir
« Corps transmis aux notifiers selon le format » de `notification-dispatch`, jamais `email_body_html`), `rule_name`,
`vl_source`, `log_timestamp`, `log_timestamp_formatted` et `log` (champs de l'événement, voir `message-templating`),
sans échappement automatique : seuls les filtres explicites (`|e`) échappent `<`, `>` et `&`, et ils laissent intact
un corps `telegram_html`, déjà échappé.

#### Scenario: Template par défaut échappé
- **WHEN** aucun `body_template` n'est configuré et que le corps de l'alerte contient `a < b & c`
- **THEN** le texte envoyé contient `a &lt; b &amp; c` après le titre en gras

#### Scenario: Template personnalisé non échappé
- **WHEN** `body_template: "{{ body }}"` est configuré et que le corps contient `<b>gras</b>`
- **THEN** le texte envoyé contient `<b>gras</b>` tel quel

#### Scenario: Échec de rendu à l'envoi
- **WHEN** le rendu du template échoue pour une alerte
- **THEN** aucune requête n'est envoyée et le notifier renvoie une erreur `template error: ...`

#### Scenario: Balisage dans le template et valeurs échappées
- **WHEN** `body_template: "<b>{{ title|e }}</b>\n<code>{{ log.host|e }}</code>"` est configuré, que le titre vaut `Disk` et que l'événement porte `host=<web&01>`
- **THEN** le texte envoyé vaut `<b>Disk</b>\n<code>&lt;web&amp;01&gt;</code>`

#### Scenario: Corps Markdown avec le template par défaut
- **WHEN** aucun `body_template` n'est configuré et qu'une alerte de titre `Disk` d'un template `markdown` a pour corps `**{{ host }}** < 10%` avec `host=a_b`
- **THEN** le texte envoyé vaut `<b>Disk</b>\n<b>a_b</b> &lt; 10%`

### Requirement: Substitution d'un rendu vide
Le système SHALL remplacer le texte rendu lorsqu'il est vide (raison `empty_after_render`), composé uniquement
d'espaces (`whitespace_only`) ou ne contient que des balises sans texte visible (`no_text_content`), par
`<b><titre échappé></b>` si le titre n'est pas vide (titre limité à 4080 points de code avant échappement), sinon par
`Alert: <rule_name échappé>` si le nom de règle n'est pas vide, sinon par `(valerter alert, empty render)`, et MUST
journaliser l'avertissement `Telegram body_template rendered empty, applied fallback` avec la raison.

#### Scenario: Rendu vide avec titre
- **WHEN** le template rend une chaîne vide et que le titre de l'alerte est `Disk & CPU`
- **THEN** le texte envoyé est `<b>Disk &amp; CPU</b>` et un avertissement avec `reason=empty_after_render` est journalisé

#### Scenario: Balises seules
- **WHEN** le template rend `<b></b>`
- **THEN** le texte est remplacé selon la même règle avec la raison `no_text_content`

#### Scenario: Ni titre ni règle
- **WHEN** le rendu est vide et que le titre et le nom de règle sont vides
- **THEN** le texte envoyé est `(valerter alert, empty render)`

### Requirement: Troncature à 4096 points de code
Le système SHALL limiter le texte à 4096 points de code Unicode : un texte plus long MUST être coupé aux 4095 premiers
points de code suivis de `…` (U+2026), une seule fois par alerte avant l'envoi aux discussions, avec l'avertissement
`Telegram message truncated to fit codepoint limit` et l'incrémentation de
`valerter_alerts_truncated_total{notifier_type="telegram", notifier_name}` de 1 par alerte (et non par discussion).
Lorsque `parse_mode` vaut `HTML`, seuls les points de code du texte visible sont comptés (une balise compte zéro, une
entité `&…;` compte un) ; la coupure MUST NOT tomber dans une balise ni dans une entité, `…` est placé après le dernier
caractère conservé et toutes les balises ouvertes à cet endroit sont refermées dans l'ordre inverse. Pour les autres
valeurs de `parse_mode`, le texte brut est compté et coupé tel quel.

#### Scenario: Texte trop long
- **WHEN** le texte rendu, sans balise ni entité, compte 5000 points de code
- **THEN** le texte envoyé compte exactement 4096 points de code et se termine par `…`

#### Scenario: Limite exacte
- **WHEN** le texte rendu compte exactement 4096 points de code
- **THEN** il est envoyé sans modification et la métrique de troncature n'augmente pas

#### Scenario: Caractères multioctets
- **WHEN** le texte contient des caractères multioctets et dépasse la limite
- **THEN** la coupure se fait en points de code, sans produire d'UTF-8 invalide

#### Scenario: Balises refermées après la coupure
- **WHEN** `parse_mode` vaut `HTML` et que le texte vaut `<b>` suivi de 5000 `x` puis `</b>`
- **THEN** le texte envoyé vaut `<b>` suivi de 4095 `x`, de `…` et de `</b>`

#### Scenario: Entité jamais coupée
- **WHEN** `parse_mode` vaut `HTML` et que le texte vaut 4094 `a`, `&amp;&lt;` puis 100 `b`
- **THEN** le texte envoyé vaut 4094 `a`, `&amp;`, `…` : l'entité `&amp;` compte un caractère, `&lt;` n'est ni coupée ni conservée en partie

#### Scenario: Balises et destinations de lien non comptées
- **WHEN** `parse_mode` vaut `HTML` et que le texte vaut `<a href="https://vl.example.com/` suivi de 3000 caractères d'URL, de `">logs</a>` puis de 4000 `x`
- **THEN** le texte est envoyé sans modification (4004 caractères visibles) et la métrique de troncature n'augmente pas

#### Scenario: Troncature brute hors mode HTML
- **WHEN** `parse_mode` vaut `MarkdownV2` et que le texte compte 5000 points de code dont des `*`
- **THEN** le texte envoyé est formé des 4095 premiers points de code du texte suivis de `…`

### Requirement: Envoi séquentiel par discussion
Le système SHALL envoyer le même texte à chaque `chat_id`, séquentiellement dans l'ordre de `chat_ids`, et l'échec
définitif d'une discussion MUST ne pas empêcher l'envoi aux suivantes.

#### Scenario: Échec au milieu de la liste
- **WHEN** trois discussions sont configurées et que la deuxième renvoie une erreur 400
- **THEN** la troisième discussion reçoit quand même le message

### Requirement: Relances sur erreurs serveur et réseau
Le système SHALL effectuer au plus 3 tentatives par discussion en cas de réponse 5xx (ou autre statut non 2xx et non
4xx) ou d'erreur réseau, en attendant 500 ms après la première tentative puis 1 s après la deuxième (base 500 ms,
doublement, plafond 5 s), et MUST renvoyer pour cette discussion l'erreur `max retries exceeded` après la troisième
tentative en échec, avec le journal `Telegram send exhausted retries`.

#### Scenario: Succès après 5xx
- **WHEN** la première réponse est 500 et la deuxième 200
- **THEN** la discussion est comptée comme réussie après 2 requêtes

#### Scenario: 5xx persistant
- **WHEN** les trois réponses sont 502
- **THEN** exactement 3 requêtes sont envoyées et la discussion est en échec avec `max retries exceeded`

### Requirement: Gestion du HTTP 429
Le système SHALL, sur une réponse 429, attendre la durée indiquée par l'en-tête `Retry-After` (entier ou décimal),
à défaut par le champ JSON `parameters.retry_after` du corps, à défaut par le backoff exponentiel standard, en bornant
toute valeur lue à l'intervalle [1 s, 60 s] ; la tentative MUST être décomptée du même plafond de 3 tentatives que les
5xx et erreurs réseau, et aucune attente n'a lieu après la dernière tentative.

#### Scenario: En-tête Retry-After
- **WHEN** Telegram répond 429 avec `Retry-After: 3`
- **THEN** la tentative suivante a lieu après 3 s

#### Scenario: Retry-After dans le corps JSON
- **WHEN** Telegram répond 429 avec un en-tête `Retry-After` illisible et le corps `{"parameters":{"retry_after":2}}`
- **THEN** la tentative suivante a lieu après 2 s

#### Scenario: Valeurs hors bornes
- **WHEN** la durée indiquée vaut 0 ou 3600
- **THEN** l'attente appliquée est respectivement de 1 s ou de 60 s

#### Scenario: Aucune indication exploitable
- **WHEN** la réponse 429 n'a ni en-tête ni champ `retry_after` exploitable
- **THEN** l'attente suit le backoff standard (500 ms à la première tentative, 1 s à la deuxième)

### Requirement: Erreurs client sans relance
Le système MUST abandonner immédiatement, sans relance, l'envoi à une discussion lorsque Telegram répond un statut
4xx autre que 429, journaliser `Telegram returned client error, not retrying` au niveau error et renvoyer pour cette
discussion l'erreur `client error: <statut>`, à la seule exception du renvoi unique en texte brut décrit par « Repli en
texte brut sur rejet HTML » lorsqu'un envoi en `parse_mode` HTML reçoit un 400 dont la description signale une erreur
d'analyse des entités.

#### Scenario: Requête rejetée
- **WHEN** Telegram répond 400 pour une discussion à une requête sans `parse_mode` HTML (ou au renvoi en texte brut)
- **THEN** aucune autre requête n'est envoyée pour cette discussion et elle est comptée en échec

#### Scenario: Discussion introuvable en mode HTML
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 400 avec la description `Bad Request: chat not found`
- **THEN** une seule requête est envoyée pour cette discussion, qui est en échec avec `client error: 400 Bad Request`

### Requirement: Résultat global et métriques par discussion
Le système SHALL considérer l'alerte comme livrée dès qu'au moins une discussion a réussi, en incrémentant une fois
`valerter_alerts_sent_total{rule_name, vl_source, notifier_name, notifier_type="telegram"}` quel que soit le nombre de
discussions réussies ; il SHALL incrémenter `valerter_telegram_chat_errors_total{rule_name, vl_source, notifier_name}`
pour chaque discussion en échec définitif ; si toutes les discussions échouent, il MUST incrémenter une fois
`valerter_notify_errors_total` et `valerter_alerts_failed_total` (mêmes libellés que `valerter_alerts_sent_total`) ;
le notifier MUST renvoyer un succès dès qu'au moins une discussion a réussi et l'erreur `all chat_ids failed` si toutes
ont échoué.

#### Scenario: Succès partiel
- **WHEN** sur deux discussions, l'une réussit et l'autre échoue
- **THEN** le notifier renvoie un succès, `valerter_alerts_sent_total` augmente de 1 et `valerter_telegram_chat_errors_total` augmente de 1
- **AND** `valerter_alerts_failed_total` et `valerter_notify_errors_total` restent inchangés

#### Scenario: Plusieurs discussions réussies
- **WHEN** une alerte est envoyée avec succès à trois discussions
- **THEN** `valerter_alerts_sent_total` augmente de 1, et non de 3

#### Scenario: Échec total
- **WHEN** les deux discussions échouent
- **THEN** le notifier renvoie l'erreur `all chat_ids failed`, `valerter_telegram_chat_errors_total` augmente de 2, et `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent chacun de 1

### Requirement: Protection du jeton du bot
Le système MUST ne jamais exposer le jeton du bot ni l'URL de l'API qui le contient : `bot_token` est rendu
`[REDACTED]` dans la représentation de la configuration, les erreurs réseau sont journalisées sans l'URL de la
requête, et la représentation de débogage du notifier se limite à son nom, au nombre de discussions, au `parse_mode`
et à la présence d'un `body_template`, sans les `chat_ids`.

#### Scenario: Erreur réseau journalisée
- **WHEN** une requête échoue au niveau réseau
- **THEN** l'avertissement `Telegram request failed, retrying` ne contient ni l'URL de l'API ni le jeton

#### Scenario: Débogage du notifier
- **WHEN** un notifier Telegram est formaté pour le débogage
- **THEN** la sortie contient `name`, `chat_count`, `parse_mode` et `has_body_template`, sans jeton, URL ni `chat_ids`

### Requirement: Validation et normalisation de parse_mode
Le système MUST n'accepter pour `parse_mode` que `HTML`, `MarkdownV2` ou `Markdown`, sans tenir compte de la casse, et SHALL transmettre la forme canonique correspondante ; toute autre valeur MUST être refusée à l'instanciation du notifier (démarrage du démon et mode `--validate`), avec `invalid notifier '<nom>': parse_mode '<valeur>' is not supported (expected HTML, MarkdownV2 or Markdown)`. Le défaut reste `HTML`.

#### Scenario: MarkdownV2
- **WHEN** `parse_mode: MarkdownV2` est configuré
- **THEN** chaque requête contient `"parse_mode": "MarkdownV2"`

#### Scenario: Casse normalisée
- **WHEN** `parse_mode: html` est configuré
- **THEN** chaque requête contient `"parse_mode": "HTML"`

#### Scenario: Valeur inconnue
- **WHEN** `parse_mode: Markdown2` est configuré sur le notifier `tg`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': parse_mode 'Markdown2' is not supported (expected HTML, MarkdownV2 or Markdown)` et aucune requête n'est envoyée

### Requirement: Rendu d'essai du body_template
Le système MUST, en plus de la vérification syntaxique, effectuer un rendu d'essai du `body_template` à l'instanciation du notifier (démarrage du démon et mode `--validate`), et refuser un template utilisant un filtre, un test ou une fonction inconnu avec un message `invalid notifier '<nom>': body_template render: <détail>`.

#### Scenario: Filtre inconnu
- **WHEN** `body_template: "<b>{{ title | nosuchfilter }}</b>"` est configuré sur le notifier `tg`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': body_template render: <détail mentionnant nosuchfilter>`

#### Scenario: Template avec échappement
- **WHEN** `body_template: "<b>{{ title | e }}</b>\n{{ body | e }}"` est configuré
- **THEN** le notifier est créé sans erreur

### Requirement: Cohérence entre format et parse_mode
Le système MUST refuser à l'instanciation (démarrage et `--validate`) un notifier Telegram dont `format` vaut `telegram_html` alors que `parse_mode` n'est pas `HTML`, avec `invalid notifier '<nom>': format 'telegram_html' requires parse_mode HTML` ; sans clé `format`, un notifier en `parse_mode` `MarkdownV2` ou `Markdown` reçoit le format `plain`.

#### Scenario: Incohérence refusée
- **WHEN** le notifier `tg` déclare `parse_mode: MarkdownV2` et `format: telegram_html`
- **THEN** le démarrage comme `valerter --validate` échouent avec `invalid notifier 'tg': format 'telegram_html' requires parse_mode HTML`

#### Scenario: Défaut en MarkdownV2
- **WHEN** un notifier déclare `parse_mode: MarkdownV2` sans `format` et reçoit une alerte d'un template `markdown` dont le corps vaut `**{{ v }}**` avec `v=1.5`
- **THEN** la variable `body` de son `body_template` vaut `1.5`, que `{{ body | mdv2_escape }}` transforme en `1\.5`

### Requirement: Renvoi en texte brut après un rejet HTML
Le système SHALL, lorsque `parse_mode` vaut `HTML` (casse ignorée) et que Telegram répond 400 avec une `description` (corps JSON lu dans une limite de taille) contenant `can't parse entities` (casse ignorée), renvoyer une seule fois à cette discussion un texte brut sans `parse_mode`, en journalisant `Telegram rejected HTML message, resending as plain text` avec le notifier et la règle, sans jeton, URL ni texte.

Pour une alerte dont le template est `body_format: markdown`, le texte renvoyé MUST être le titre (s'il n'est pas vide) suivi d'un saut de ligne et du rendu `plain` du corps, tronqué à 4096 points de code selon la troncature brute ; pour toute autre alerte, c'est le même texte que la requête HTML. Ce renvoi MUST suivre la même politique de relance que tout envoi (5xx, 429 et erreurs réseau, au plus 3 tentatives) ; une réponse 4xx au renvoi MUST être traitée comme un échec définitif de la discussion. Aucun repli n'a lieu pour un 400 sans cette description, pour les autres statuts 4xx ni pour les autres valeurs de `parse_mode`.

#### Scenario: Texte rejeté renvoyé en texte brut
- **WHEN** `parse_mode` vaut `HTML`, qu'une alerte d'un template `text` est envoyée et que Telegram répond 400 avec la description `Bad Request: can't parse entities: Unclosed start tag at byte offset 12` puis 200
- **THEN** deux requêtes sont envoyées pour cette discussion, la seconde sans champ `parse_mode` et avec le même `text`, la discussion est comptée comme réussie et l'avertissement est journalisé

#### Scenario: Alerte Markdown renvoyée en rendu plain
- **WHEN** une alerte de titre `Disk` d'un template `markdown` dont le corps vaut `**{{ host }}** < 10%` avec `host=a_b` est envoyée avec le template par défaut, et que Telegram répond 400 `can't parse entities` puis 200
- **THEN** la seconde requête n'a pas de champ `parse_mode` et son `text` vaut `Disk\na_b < 10%`, sans balise ni entité

#### Scenario: Rendu plain trop long
- **WHEN** l'alerte Markdown rejetée a un rendu `plain` de 5000 points de code
- **THEN** le `text` du renvoi compte exactement 4096 points de code et se termine par `…`

#### Scenario: Caractère non échappé dans un template personnalisé
- **WHEN** `body_template: "{{ body }}"` est configuré, que le corps contient `a < b` et que Telegram répond 400 à la requête HTML avec la description `Bad Request: can't parse entities: Unsupported start tag "b" at byte offset 2`
- **THEN** le texte est renvoyé une fois en texte brut à cette discussion

#### Scenario: Renvoi en texte brut également rejeté
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 400 avec une description `can't parse entities` à la requête HTML puis 400 au renvoi
- **THEN** exactement deux requêtes sont envoyées pour cette discussion et elle est en échec avec `client error: 400 Bad Request`

#### Scenario: Pas de repli hors mode HTML
- **WHEN** `parse_mode` vaut `MarkdownV2` et que Telegram répond 400
- **THEN** une seule requête est envoyée pour cette discussion

#### Scenario: Pas de repli sur un autre statut 4xx
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 403
- **THEN** une seule requête est envoyée pour cette discussion

#### Scenario: Pas de repli sur un autre 400
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 400 avec la description `Bad Request: message text is empty`, ou sans corps JSON
- **THEN** une seule requête est envoyée pour cette discussion

#### Scenario: Description en casse différente
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 400 avec la description `Bad Request: Can't Parse Entities: ...` puis 200
- **THEN** deux requêtes sont envoyées pour cette discussion
