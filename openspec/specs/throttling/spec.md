# throttling Specification

## Purpose
Le throttling limite le nombre d'alertes envoyées pour un même groupe d'événements sur une durée donnée, afin d'éviter les rafales de notifications. Il s'applique à chaque événement parsé avant le rendu du message, dans chaque tâche (règle, source VictoriaLogs), à l'aide d'une clé calculée par template et d'un cache borné en mémoire. La validation structurelle de la configuration relève de la capacité `configuration`, le rendu des messages de `message-templating` et l'envoi des `notifiers`.

## Requirements

### Requirement: Paramètres de throttle
Le système SHALL accepter un bloc `throttle` composé de `count` (entier non signé 32 bits, obligatoire), `window` (durée au format humantime, ex. `30s`, `5m`, `1h`, obligatoire) et `key` (template minijinja, optionnel), et MUST rejeter toute autre clé dans ce bloc.

#### Scenario: Bloc de throttle complet
- **WHEN** une règle déclare `throttle: { key: "{{ host }}", count: 3, window: 5m }`
- **THEN** au plus 3 alertes par valeur de `host` passent sur une fenêtre de 5 minutes

#### Scenario: Clé inconnue dans le bloc
- **WHEN** le bloc `throttle` contient un champ non prévu (ex. `limit`)
- **THEN** le chargement de la configuration échoue

### Requirement: Throttle par défaut obligatoire
Le système SHALL appliquer `defaults.throttle` (bloc obligatoire) à toute règle qui ne déclare pas son propre bloc `throttle` ; il n'existe aucun mode « sans throttle ».

#### Scenario: Règle sans throttle
- **WHEN** une règle n'a pas de bloc `throttle` et que `defaults.throttle` vaut `{ count: 5, window: 60s }`
- **THEN** la règle est limitée à 5 alertes par fenêtre de 60 s avec la clé par défaut

### Requirement: Remplacement intégral par le throttle de règle
Le système SHALL utiliser le bloc `throttle` d'une règle à la place de `defaults.throttle`, sans fusion champ par champ.

#### Scenario: Throttle de règle partiel
- **WHEN** `defaults.throttle` définit `key: "{{ host }}"` et qu'une règle définit `throttle: { count: 2, window: 1m }` sans `key`
- **THEN** la règle utilise la clé par défaut `<règle>-<source>:global` et non `{{ host }}`

### Requirement: Valeurs de count et window au niveau règle
Le système MUST rejeter au chargement un bloc `throttle` de règle dont `count` vaut 0 ou dont `window` est nulle, avec les messages `rule '<nom>': throttle.count must be >= 1 (0 would suppress every alert)` et `rule '<nom>': throttle.window must be > 0 (0s disables throttling)`.

#### Scenario: count et window à zéro sur une règle
- **WHEN** une règle déclare `throttle: { count: 0, window: 0s }`
- **THEN** la validation échoue avec les deux messages d'erreur

#### Scenario: Valeurs nulles dans defaults.throttle
- **WHEN** `defaults.throttle` déclare `count: 0` ou `window: 0s`
- **THEN** la configuration est refusée au chargement (voir « Valeurs de count et window de defaults.throttle ») au lieu d'être acceptée avec un simple avertissement, et aucune tâche n'est démarrée

### Requirement: Clé de throttle par défaut
Le système SHALL utiliser, en l'absence de `key`, la clé `<rule_name>-<vl_source>:global`, de sorte que tous les événements d'une règle sur une source partagent un même compteur.

#### Scenario: Deux hôtes sans clé configurée
- **WHEN** la règle `my_rule` sur la source `vlprod` a `count: 2` sans `key` et reçoit un événement de `SW-01`, un de `SW-02`, puis un de `SW-01`
- **THEN** les deux premiers passent et le troisième est bloqué (clé commune `my_rule-vlprod:global`)

### Requirement: Rendu de la clé par template
Le système SHALL rendre `throttle.key` avec minijinja sur le contexte des champs parsés de l'événement, où les clés pointées (ex. `nginx.http.status_code`) sont aussi exposées sous forme d'objets imbriqués, et où les variables synthétiques `rule_name` et `vl_source` sont injectées et prennent le pas sur tout champ d'événement de même nom.

#### Scenario: Clé composée
- **WHEN** `key: "{{ host }}-{{ port }}"` et l'événement contient `host=SW-01`, `port=Gi0/1`
- **THEN** la clé rendue est `SW-01-Gi0/1`

#### Scenario: Champ pointé et variables synthétiques
- **WHEN** `key: "{{ rule_name }}-{{ vl_source }}-{{ nginx.http.status_code }}"`, règle `VM_OFF`, source `vlprod`, champ plat `nginx.http.status_code=404`
- **THEN** la clé rendue est `VM_OFF-vlprod-404`

#### Scenario: Collision avec un champ d'événement
- **WHEN** `key: "{{ rule_name }}"` et l'événement contient un champ `rule_name=event-value`
- **THEN** la clé rendue est le nom de la règle et non `event-value`

### Requirement: Champ manquant dans la clé
Le système SHALL rendre une variable absente de l'événement comme une chaîne vide dans la clé, sans erreur.

#### Scenario: Champ absent
- **WHEN** `key: "{{ host }}-{{ missing }}"` et l'événement ne contient que `host=SW-01`
- **THEN** la clé rendue est `SW-01-`

### Requirement: Clé de repli en cas d'erreur de rendu
Le système SHALL, si le rendu de `throttle.key` échoue à l'exécution malgré la validation au chargement (erreur dépendant des valeurs réelles de l'événement, ex. opération arithmétique sur une chaîne), journaliser un avertissement `Failed to render throttle key, using fallback` et utiliser la clé `<rule_name>:error`.

#### Scenario: Filtre inconnu dans la clé
- **WHEN** `key: "{{ host | bad_filter }}"` est déclaré pour la règle `test_rule`
- **THEN** la configuration est refusée au chargement et la clé de repli n'est jamais utilisée pour ce cas

#### Scenario: Erreur de rendu dépendant de l'événement
- **WHEN** `key: "{{ port + 1 }}"` est rendu pour la règle `test_rule` avec un événement où `port` vaut la chaîne `Gi0/1`
- **THEN** la clé utilisée est `test_rule:error` et l'événement est compté dans ce compteur partagé

### Requirement: Limite de comptage par clé
Le système SHALL laisser passer les `count` premières alertes d'une clé dans la fenêtre courante et bloquer toutes les suivantes jusqu'à expiration de la fenêtre ; chaque événement, bloqué ou non, incrémente le compteur.

#### Scenario: Dépassement de count
- **WHEN** `count: 3` et quatre événements de même clé arrivent dans la fenêtre
- **THEN** les trois premiers passent et le quatrième est bloqué

#### Scenario: Événement bloqué
- **WHEN** un événement est bloqué par le throttle
- **THEN** aucun message n'est rendu ni mis en file d'attente pour cet événement

### Requirement: Fenêtre fixe ancrée sur le premier événement
Le système SHALL ouvrir la fenêtre d'une clé à la création de son compteur (premier événement vu) et la clore `window` plus tard, sans la prolonger lors des événements suivants ; à l'expiration, le compteur est supprimé et l'événement suivant repart de zéro.

#### Scenario: Expiration de la fenêtre
- **WHEN** `count: 2`, `window: 100ms`, trois événements de même clé arrivent (le troisième est bloqué), puis un quatrième arrive 150 ms plus tard
- **THEN** le quatrième événement passe

### Requirement: Indépendance des clés
Le système SHALL compter chaque valeur de clé séparément.

#### Scenario: Deux hôtes distincts
- **WHEN** `key: "{{ host }}"`, `count: 2`, et trois événements arrivent pour `SW-01` puis trois pour `SW-02`
- **THEN** pour chaque hôte, les deux premiers passent et le troisième est bloqué

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

### Requirement: Métriques de throttling
Le système SHALL incrémenter `valerter_alerts_passed_total` pour chaque événement autorisé et `valerter_alerts_throttled_total` pour chaque événement bloqué, avec les labels `rule_name` et `vl_source`, et journaliser chaque blocage au niveau DEBUG (`Alert throttled`).

#### Scenario: Événement bloqué
- **WHEN** un événement de la règle `r` sur la source `vlprod` est bloqué
- **THEN** `valerter_alerts_throttled_total{rule_name="r",vl_source="vlprod"}` augmente de 1

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

### Requirement: Valeurs de count et window de defaults.throttle
Le système MUST rejeter au chargement un `defaults.throttle` dont `count` vaut 0 ou dont `window` est nulle, avec les messages `defaults.throttle.count must be >= 1 (0 would suppress every alert)` et `defaults.throttle.window must be > 0 (0s disables throttling)` ; aucune tâche n'est alors démarrée.

#### Scenario: count nul dans defaults.throttle
- **WHEN** `defaults.throttle` déclare `count: 0`
- **THEN** la validation échoue avec `defaults.throttle.count must be >= 1 (0 would suppress every alert)` et le démon ne démarre pas

#### Scenario: window nulle dans defaults.throttle
- **WHEN** `defaults.throttle` déclare `window: 0s`
- **THEN** la validation échoue avec `defaults.throttle.window must be > 0 (0s disables throttling)`

### Requirement: Validation de la clé au chargement
Le système MUST vérifier au chargement la syntaxe Jinja puis effectuer un rendu d'essai de `throttle.key` de chaque règle (activée ou non) et de `defaults.throttle.key`, et rejeter la configuration si la syntaxe est invalide ou si la clé utilise un filtre, un test ou une fonction inconnu.

#### Scenario: Syntaxe invalide
- **WHEN** une règle `r` déclare `key: "{% if host %}{{ host"`
- **THEN** la validation échoue avec `invalid template in rule 'r': throttle.key: <détail>`

#### Scenario: Filtre inconnu détecté au chargement
- **WHEN** une règle `r` déclare `key: "{{ host | bad_filter }}"`
- **THEN** la validation échoue avec `invalid template in rule 'r': throttle.key render: <détail mentionnant bad_filter>`

#### Scenario: Clé avec conversion de type acceptée
- **WHEN** une règle déclare `key: "{{ host }}-{{ status | int }}"`
- **THEN** la validation réussit
