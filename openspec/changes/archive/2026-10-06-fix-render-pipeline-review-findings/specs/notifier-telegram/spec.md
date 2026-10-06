## MODIFIED Requirements

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

## REMOVED Requirements

### Requirement: Repli en texte brut sur rejet HTML
**Reason**: Son scénario « Balise coupée par la troncature » décrit un cas que la troncature consciente du HTML rend impossible, et le texte renvoyé change pour une alerte Markdown (rendu `plain` au lieu du HTML brut). Remplacée par « Renvoi en texte brut après un rejet HTML ».
**Migration**: Aucune action côté configuration ; le comportement est repris et précisé par la nouvelle exigence.

## ADDED Requirements

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
