## MODIFIED Requirements

### Requirement: Validation par rendu d'essai
Le système MUST effectuer au chargement un rendu d'essai de `title`, `body` et `email_body_html` de chaque template, afin de détecter les erreurs d'exécution comme les filtres inconnus, et rejeter la configuration avec un message `<champ> render: <détail>` ; ce rendu utilise un contexte fictif où tout accès à un champ (y compris en chaîne pointée) est défini, toute condition est vraie et toute boucle est vide. Seules les erreurs indépendantes des valeurs réelles MUST faire échouer le rendu d'essai : erreur de syntaxe, filtre, test, fonction ou méthode inconnu, et opérateur `/` appliqué à un chemin de champ ; une erreur de type ou d'opération causée par le contexte fictif (conversion `int`/`float`, `round`, `abs`, arithmétique, `split`…) MUST NOT faire échouer la validation. La même règle s'applique à tout rendu d'essai effectué par valerter (`throttle.key`, `subject_template`, `body_template` des notifiers).

#### Scenario: Filtre inconnu
- **WHEN** le `body` d'un template vaut `{{ _msg | truncate(50) }}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `truncate`

#### Scenario: Champ pointé profond
- **WHEN** un template référence `{{ nginx.http.request_id }}` et `{% if a.b %}{{ a.b }}{% endif %}`
- **THEN** la validation réussit

#### Scenario: Conversion de type sur un champ
- **WHEN** le `title` d'un template vaut `{{ status | int }} {{ (latency | float) > 1.5 }} {{ count + 1 }}`
- **THEN** la validation réussit

#### Scenario: Test inconnu
- **WHEN** le `body` d'un template vaut `{% if host is nosuchtest %}x{% endif %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuchtest`

### Requirement: Indice pour les noms de champ contenant une barre oblique
Le système SHALL, lorsqu'un rendu d'essai échoue sur l'opérateur `/` et que le template contient un chemin de champ comportant `/` dans une expression `{{ ... }}`, ajouter au message d'erreur une ligne `hint:` proposant la réécriture en notation crochets sur l'objet parent (ex. `{{ ocp.annotations.authentication.openshift["io/username"] }}`) ; si le segment contenant `/` est au premier niveau (aucun objet parent), l'indice MUST NOT proposer de syntaxe inexistante et SHALL expliquer que ce champ n'est pas adressable directement et qu'il faut le renommer dans la requête LogsQL (pipe `rename`).

#### Scenario: Annotation Kubernetes
- **WHEN** un template contient `{{ ocp.annotations.authentication.openshift.io/username }}`
- **THEN** la validation échoue et le message contient un indice suggérant `openshift["io/username"]`

#### Scenario: Champ de premier niveau contenant une barre oblique
- **WHEN** un template contient `{{ io/username }}`
- **THEN** la validation échoue et l'indice mentionne le pipe LogsQL `rename` (ex. `| rename "io/username" as io_username`) sans proposer `fields["io/username"]`
