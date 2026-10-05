## MODIFIED Requirements

### Requirement: Valeurs de count et window au niveau règle
Le système MUST rejeter au chargement un bloc `throttle` de règle dont `count` vaut 0 ou dont `window` est nulle, avec les messages `rule '<nom>': throttle.count must be >= 1 (0 would suppress every alert)` et `rule '<nom>': throttle.window must be > 0 (0s disables throttling)`.

#### Scenario: count et window à zéro sur une règle
- **WHEN** une règle déclare `throttle: { count: 0, window: 0s }`
- **THEN** la validation échoue avec les deux messages d'erreur

#### Scenario: Valeurs nulles dans defaults.throttle
- **WHEN** `defaults.throttle` déclare `count: 0` ou `window: 0s`
- **THEN** la configuration est refusée au chargement (voir « Valeurs de count et window de defaults.throttle ») au lieu d'être acceptée avec un simple avertissement, et aucune tâche n'est démarrée

### Requirement: Clé de repli en cas d'erreur de rendu
Le système SHALL, si le rendu de `throttle.key` échoue à l'exécution malgré la validation au chargement (erreur dépendant des valeurs réelles de l'événement, ex. opération arithmétique sur une chaîne), journaliser un avertissement `Failed to render throttle key, using fallback` et utiliser la clé `<rule_name>:error`.

#### Scenario: Filtre inconnu dans la clé
- **WHEN** `key: "{{ host | bad_filter }}"` est déclaré pour la règle `test_rule`
- **THEN** la configuration est refusée au chargement et la clé de repli n'est jamais utilisée pour ce cas

#### Scenario: Erreur de rendu dépendant de l'événement
- **WHEN** `key: "{{ port + 1 }}"` est rendu pour la règle `test_rule` avec un événement où `port` vaut la chaîne `Gi0/1`
- **THEN** la clé utilisée est `test_rule:error` et l'événement est compté dans ce compteur partagé

## ADDED Requirements

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

## REMOVED Requirements

### Requirement: Validation syntaxique de la clé au chargement
**Reason**: La clé de throttle n'était vérifiée que syntaxiquement ; un filtre inconnu passait la validation et regroupait à l'exécution tous les événements de la règle sous la clé de repli `<règle>:error`. Remplacé par « Validation de la clé au chargement », qui ajoute un rendu d'essai et couvre `defaults.throttle.key`.
**Migration**: Corriger ou retirer tout filtre inconnu de `throttle.key` (règles et `defaults`) ; `valerter --validate` signale désormais ces clés avec `throttle.key render:`.
