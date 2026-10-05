## ADDED Requirements

### Requirement: Cache de throttle partagé par règle
Le système SHALL maintenir un unique état de throttle par règle, partagé par toutes les tâches (règle, source) de cette règle : deux sources qui rendent la même clé pour une même règle incrémentent le même compteur, tandis que deux règles distinctes ne partagent jamais de compteur, même à clé rendue identique.

#### Scenario: Déduplication entre sources avec la clé rule_name
- **WHEN** la règle `VM_OFF` cible les sources `vlprod` et `vldev` avec `key: "{{ rule_name }}"` et `count: 1`, et que chaque source émet un événement dans la même fenêtre
- **THEN** seul le premier événement reçu passe, le second est bloqué
- **AND** `valerter_alerts_throttled_total` est incrémenté avec le label `vl_source` de la source dont l'événement a été bloqué

#### Scenario: Isolation par source avec la clé par défaut
- **WHEN** la règle `VM_OFF` cible les sources `vlprod` et `vldev` sans `key` et avec `count: 1`, et que chaque source émet un événement
- **THEN** les deux événements passent, les clés `VM_OFF-vlprod:global` et `VM_OFF-vldev:global` étant distinctes

#### Scenario: Clé personnalisée sans vl_source
- **WHEN** la règle cible `vlprod` et `vldev` avec `key: "{{ host }}"`, `count: 1`, et que les deux sources émettent un événement pour `host=SW-01`
- **THEN** seul le premier événement passe

#### Scenario: Clé personnalisée avec vl_source
- **WHEN** la règle cible `vlprod` et `vldev` avec `key: "{{ vl_source }}-{{ host }}"`, `count: 1`, et que les deux sources émettent un événement pour `host=SW-01`
- **THEN** les deux événements passent

#### Scenario: Deux règles à clé identique
- **WHEN** les règles `r1` et `r2` utilisent toutes deux `key: "{{ host }}"`, `count: 1`, et reçoivent chacune un événement pour `host=SW-01`
- **THEN** les deux événements passent

### Requirement: Persistance du cache à la relance d'une tâche
Le système SHALL conserver l'état de throttle d'une règle lorsqu'une de ses tâches (règle, source) est relancée après un panic : la tâche relancée reprend les compteurs existants de la règle.

#### Scenario: Relance après panic
- **WHEN** une clé de la règle `r` a atteint son maximum, puis que la tâche (`r`, `vlprod`) panique et est relancée
- **THEN** le prochain événement de cette clé dans la même fenêtre reste bloqué

### Requirement: Signalement au démarrage d'une clé partagée entre sources
Le système SHALL émettre au démarrage, une fois par règle activée ciblant au moins deux sources effectives, un log de niveau INFO lorsque le throttle effectif de la règle a une clé personnalisée qui ne référence pas la variable `vl_source` ; le log SHALL nommer la règle, indiquer que le compteur de throttle est partagé entre ses sources et indiquer qu'ajouter `{{ vl_source }}` à la clé isole les sources. La détection MUST être statique, fondée sur les variables non déclarées du template minijinja de la clé, sans rendu d'essai. Aucun log n'est émis pour une règle sans clé personnalisée, pour une règle à une seule source effective, ni lors de la relance d'une tâche après panic.

#### Scenario: Règle multi-sources avec clé rule_name
- **WHEN** la règle `VM_OFF` cible les sources `vlprod` et `vldev` avec `key: "{{ rule_name }}"` et que le démon démarre
- **THEN** un unique log INFO nomme `VM_OFF`, indique que le compteur est partagé entre ses sources et suggère d'ajouter `{{ vl_source }}` à la clé

#### Scenario: Clé héritée des valeurs par défaut
- **WHEN** la règle `VM_OFF` cible `vlprod` et `vldev` sans bloc `throttle` et que `defaults.throttle.key` vaut `"{{ host }}"`
- **THEN** le log INFO est émis pour `VM_OFF`

#### Scenario: Clé référençant vl_source
- **WHEN** la règle cible `vlprod` et `vldev` avec `key: "{{ vl_source }}-{{ host }}"`
- **THEN** aucun log de clé partagée n'est émis pour cette règle

#### Scenario: Clé par défaut ou source unique
- **WHEN** une règle cible deux sources sans clé personnalisée, ou qu'une règle à clé `"{{ rule_name }}"` ne cible qu'une seule source
- **THEN** aucun log de clé partagée n'est émis pour ces règles

## MODIFIED Requirements

### Requirement: Cache borné
Le système SHALL limiter le cache de throttle d'une règle à 10 000 clés multipliées par le nombre de sources ciblées par cette règle, valeur non configurable ; au-delà, des clés sont évincées et une clé évincée repart de zéro à son prochain événement.

#### Scenario: Éviction d'une clé
- **WHEN** le cache d'une règle est plein et que de nouvelles clés arrivent, provoquant l'éviction de la clé `key-0` alors à son maximum
- **THEN** le prochain événement de clé `key-0` passe

#### Scenario: Borne d'une règle multi-sources
- **WHEN** une règle cible trois sources
- **THEN** son cache de throttle peut contenir jusqu'à 30 000 clés

### Requirement: Remise à zéro après reconnexion
Le système SHALL, lorsque le flux VictoriaLogs d'une tâche (règle, source) se reconnecte avec succès (réponse HTTP 2xx) après un échec de connexion, une réponse HTTP en erreur ou une erreur de lecture du flux, supprimer du cache de la règle les compteurs alimentés exclusivement par cette source dans leur fenêtre courante, et conserver ceux auxquels au moins une autre source a contribué ; une fin de flux propre (EOF sans erreur) ne déclenche pas cette remise à zéro, pas plus que la connexion initiale.

#### Scenario: Reconnexion après erreur
- **WHEN** une clé alimentée uniquement par la source qui se reconnecte a atteint son maximum, que le flux échoue puis se reconnecte avec succès
- **THEN** l'événement suivant de cette clé passe

#### Scenario: Clé partagée conservée
- **WHEN** la règle utilise `key: "{{ rule_name }}"` et `count: 1`, qu'un événement de `vldev` a ouvert le compteur, puis que le flux de `vlprod` échoue et se reconnecte avec succès
- **THEN** un événement de `vlprod` pour cette clé dans la même fenêtre est bloqué

#### Scenario: Compteur alimenté par plusieurs sources
- **WHEN** une clé a reçu des événements de `vlprod` et de `vldev` dans sa fenêtre courante, puis que le flux de `vlprod` se reconnecte après une erreur
- **THEN** le compteur de cette clé est conservé

#### Scenario: Clés par défaut des autres sources
- **WHEN** la règle n'a pas de `key` et que le flux de `vlprod` se reconnecte après une erreur
- **THEN** le compteur `<règle>-vlprod:global` est supprimé et le compteur `<règle>-vldev:global` est conservé

#### Scenario: Fin de flux propre
- **WHEN** le serveur ferme le flux sans erreur et que la tâche se reconnecte
- **THEN** les compteurs de throttle sont conservés

## REMOVED Requirements

### Requirement: Isolation par couple règle-source
**Reason**: Ce comportement empêchait la déduplication entre sources promise par la documentation (`throttle.key: "{{ rule_name }}"`). Il est remplacé par « Cache de throttle partagé par règle », où l'isolation par source découle de la clé par défaut `<rule_name>-<vl_source>:global` et non plus d'un état séparé par tâche.
**Migration**: Aucune action pour les règles sans `key` ou dont la clé contient déjà `{{ vl_source }}`. Pour conserver un compteur par source avec une clé personnalisée, y ajouter `{{ vl_source }}` (ex. `key: "{{ vl_source }}-{{ host }}"`).
