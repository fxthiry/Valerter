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
- **THEN** la configuration est acceptée et seul un avertissement est journalisé à la création de chaque tâche (`Throttle count is 0, all alerts after first will be throttled` ou `Throttle window is 0, entries will expire immediately`)
- **AND** avec `count: 0`, toutes les alertes sont bloquées, y compris la première

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
Le système SHALL, si le rendu de `throttle.key` échoue à l'exécution (ex. filtre inconnu), journaliser un avertissement `Failed to render throttle key, using fallback` et utiliser la clé `<rule_name>:error`.

#### Scenario: Filtre inconnu dans la clé
- **WHEN** `key: "{{ host | bad_filter }}"` est rendu pour la règle `test_rule`
- **THEN** la clé utilisée est `test_rule:error` et l'événement est compté dans ce compteur partagé

### Requirement: Validation syntaxique de la clé au chargement
Le système MUST vérifier la syntaxe Jinja de `throttle.key` de chaque règle (activée ou non) au chargement, et rejeter la configuration avec l'erreur `invalid template in rule '<nom>': throttle.key: <détail>` si la syntaxe est invalide ; aucun rendu d'essai n'est effectué pour cette clé.

#### Scenario: Syntaxe invalide
- **WHEN** une règle déclare `key: "{% if host %}{{ host"`
- **THEN** la validation échoue avec une erreur de template mentionnant `throttle.key`

#### Scenario: Filtre inconnu non détecté
- **WHEN** une règle déclare `key: "{{ host | bad_filter }}"`
- **THEN** la configuration est acceptée et l'erreur ne se manifeste qu'au rendu (clé de repli)

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

### Requirement: Isolation par couple règle-source
Le système SHALL maintenir un état de throttle distinct pour chaque tâche (règle, source VictoriaLogs), de sorte que deux sources ne partagent jamais de compteur, même lorsque leur clé rendue est identique.

#### Scenario: Même règle sur deux sources
- **WHEN** la règle `VM_OFF` cible les sources `vlprod` et `vldev` avec `key: "{{ rule_name }}"` et `count: 1`
- **THEN** le premier événement de chaque source passe, chaque source ayant son propre compteur

### Requirement: Cache borné
Le système SHALL limiter le cache de throttle à 10 000 clés par couple (règle, source), valeur non configurable ; au-delà, des clés sont évincées et une clé évincée repart de zéro à son prochain événement.

#### Scenario: Éviction d'une clé
- **WHEN** le cache d'une tâche est plein et que de nouvelles clés arrivent, provoquant l'éviction de la clé `key-0` alors à son maximum
- **THEN** le prochain événement de clé `key-0` passe

### Requirement: Remise à zéro après reconnexion
Le système SHALL vider l'intégralité du cache de throttle d'une tâche (règle, source) lorsque son flux VictoriaLogs se reconnecte avec succès (réponse HTTP 2xx) après un échec de connexion, une réponse HTTP en erreur ou une erreur de lecture du flux ; une fin de flux propre (EOF sans erreur) ne déclenche pas cette remise à zéro, pas plus que la connexion initiale.

#### Scenario: Reconnexion après erreur
- **WHEN** une clé a atteint son maximum, que le flux échoue puis se reconnecte avec succès
- **THEN** l'événement suivant de cette clé passe

#### Scenario: Fin de flux propre
- **WHEN** le serveur ferme le flux sans erreur et que la tâche se reconnecte
- **THEN** les compteurs de throttle sont conservés

### Requirement: Métriques de throttling
Le système SHALL incrémenter `valerter_alerts_passed_total` pour chaque événement autorisé et `valerter_alerts_throttled_total` pour chaque événement bloqué, avec les labels `rule_name` et `vl_source`, et journaliser chaque blocage au niveau DEBUG (`Alert throttled`).

#### Scenario: Événement bloqué
- **WHEN** un événement de la règle `r` sur la source `vlprod` est bloqué
- **THEN** `valerter_alerts_throttled_total{rule_name="r",vl_source="vlprod"}` augmente de 1
