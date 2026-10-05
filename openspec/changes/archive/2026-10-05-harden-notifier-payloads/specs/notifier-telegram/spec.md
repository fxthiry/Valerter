## ADDED Requirements

### Requirement: Repli en texte brut sur rejet HTML
Le système SHALL, lorsque `parse_mode` vaut `HTML` (sans tenir compte de la casse) et que Telegram répond 400 à l'envoi pour une discussion, renvoyer une seule fois à cette discussion le même texte sans le champ `parse_mode` (texte brut), en journalisant l'avertissement `Telegram rejected HTML message, resending as plain text` avec le nom du notifier et de la règle, sans le jeton, l'URL de l'API ni le texte. Ce renvoi MUST suivre la même politique de relance que tout envoi (5xx, 429 et erreurs réseau, au plus 3 tentatives) ; une réponse 4xx au renvoi MUST être traitée comme un échec définitif de la discussion. Aucun repli n'a lieu pour les autres statuts 4xx ni pour les autres valeurs de `parse_mode`.

#### Scenario: Balise coupée par la troncature
- **WHEN** `parse_mode` vaut `HTML`, que le texte tronqué se termine au milieu d'une balise et que Telegram répond 400 puis 200
- **THEN** deux requêtes sont envoyées pour cette discussion, la seconde sans champ `parse_mode` et avec le même `text`, la discussion est comptée comme réussie et l'avertissement est journalisé

#### Scenario: Caractère non échappé dans un template personnalisé
- **WHEN** `body_template: "{{ body }}"` est configuré, que le corps contient `a < b` et que Telegram répond 400 à la requête HTML
- **THEN** le texte est renvoyé une fois en texte brut à cette discussion

#### Scenario: Renvoi en texte brut également rejeté
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 400 à la requête HTML puis 400 au renvoi
- **THEN** exactement deux requêtes sont envoyées pour cette discussion et elle est en échec avec `client error: 400 Bad Request`

#### Scenario: Pas de repli hors mode HTML
- **WHEN** `parse_mode` vaut `MarkdownV2` et que Telegram répond 400
- **THEN** une seule requête est envoyée pour cette discussion

#### Scenario: Pas de repli sur un autre statut 4xx
- **WHEN** `parse_mode` vaut `HTML` et que Telegram répond 403
- **THEN** une seule requête est envoyée pour cette discussion

## MODIFIED Requirements

### Requirement: Erreurs client sans relance
Le système MUST abandonner immédiatement, sans relance, l'envoi à une discussion lorsque Telegram répond un statut
4xx autre que 429, journaliser `Telegram returned client error, not retrying` au niveau error et renvoyer pour cette
discussion l'erreur `client error: <statut>`, à la seule exception du renvoi unique en texte brut décrit par « Repli en
texte brut sur rejet HTML » lorsqu'un envoi en `parse_mode` HTML reçoit un 400.

#### Scenario: Requête rejetée
- **WHEN** Telegram répond 400 pour une discussion à une requête sans `parse_mode` HTML (ou au renvoi en texte brut)
- **THEN** aucune autre requête n'est envoyée pour cette discussion et elle est comptée en échec
