## MODIFIED Requirements

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
