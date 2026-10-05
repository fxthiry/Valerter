## MODIFIED Requirements

### Requirement: Substitution des variables d'environnement dans les secrets des notifiers
Le système SHALL remplacer, à l'instanciation des notifiers, chaque motif `${NOM}` (NOM conforme à `[A-Za-z_][A-Za-z0-9_]*`) des champs secrets par la valeur de la variable d'environnement correspondante, et MUST échouer si une variable est absente avec un message listant toutes les variables manquantes (`undefined environment variable: A` ou `undefined environment variables: A, B`) préfixé par `invalid notifier '<nom>': <champ>: invalid configuration: `.

#### Scenario: Variable définie
- **WHEN** `webhook_url: "${MM_URL}"` et `MM_URL=https://mm.example.com/hooks/x`
- **THEN** le notifier envoie vers `https://mm.example.com/hooks/x`

#### Scenario: Variables manquantes
- **WHEN** un champ secret vaut `${UNDEFINED_A} and ${UNDEFINED_B}` et aucune des deux n'est définie
- **THEN** l'erreur mentionne `invalid configuration: undefined environment variables: UNDEFINED_A, UNDEFINED_B`

### Requirement: Destination absente du registre à l'exécution
Le système MUST, si une destination d'une alerte n'existe pas dans le registre au moment de la mise en file, ignorer cette destination, journaliser l'erreur `Notifier not found in registry (validation should have caught this)` et compter l'alerte comme un échec définitif pour cette destination : `valerter_notify_errors_total` et `valerter_alerts_failed_total` sont incrémentés une fois, avec les labels `rule_name`, `vl_source`, `notifier_name` (le nom introuvable) et `notifier_type="unknown"`, sans empêcher la mise en file pour les autres destinations.

#### Scenario: Nom introuvable
- **WHEN** une alerte référence une destination inconnue du registre
- **THEN** seules les destinations connues reçoivent l'alerte et l'erreur est comptée

#### Scenario: Compteurs de l'échec
- **WHEN** une alerte de la règle `r` issue de la source `s` référence la destination introuvable `ghost`
- **THEN** `valerter_notify_errors_total{rule_name="r",vl_source="s",notifier_name="ghost",notifier_type="unknown"}` et `valerter_alerts_failed_total` avec les mêmes labels valent 1
