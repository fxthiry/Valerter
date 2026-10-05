## MODIFIED Requirements

### Requirement: Validation de la clé au chargement
Le système MUST vérifier au chargement la syntaxe Jinja puis effectuer un rendu d'essai de `throttle.key` de chaque règle (activée ou non) et de `defaults.throttle.key`, et rejeter la configuration si la syntaxe est invalide ou si la clé utilise un filtre, un test ou une fonction inconnu, y compris lorsque ce filtre suit une conversion de type ou figure dans une branche alternative.

#### Scenario: Syntaxe invalide
- **WHEN** une règle `r` déclare `key: "{% if host %}{{ host"`
- **THEN** la validation échoue avec `invalid template in rule 'r': throttle.key: <détail>`

#### Scenario: Filtre inconnu détecté au chargement
- **WHEN** une règle `r` déclare `key: "{{ host | bad_filter }}"`
- **THEN** la validation échoue avec `invalid template in rule 'r': throttle.key render: <détail mentionnant bad_filter>`

#### Scenario: Clé avec conversion de type acceptée
- **WHEN** une règle déclare `key: "{{ host }}-{{ status | int }}"`
- **THEN** la validation réussit

#### Scenario: Filtre inconnu après une conversion
- **WHEN** `defaults.throttle.key` vaut `"{{ status | int }}-{{ host | truncat(10) }}"`
- **THEN** la validation échoue avec `defaults.throttle.key render: <détail mentionnant truncat>`, au lieu d'accepter une clé qui retomberait sur `<rule>:error` pour chaque événement
