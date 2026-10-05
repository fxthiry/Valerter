## MODIFIED Requirements

### Requirement: Validation par rendu d'essai
Le système MUST effectuer au chargement un rendu d'essai de `title`, `body` et `email_body_html` de chaque template, afin de détecter les erreurs d'exécution comme les filtres inconnus, et rejeter la configuration avec un message `<champ> render: <détail>`. Ce rendu utilise un contexte fictif où tout accès à un champ (y compris en chaîne pointée) est défini, et il est effectué deux fois : une passe où toute condition est vraie et toute boucle sur un champ itère un élément, puis une passe où toute condition sur un champ est fausse, toute boucle est vide et le test `defined` est faux pour un champ ; une erreur dans l'une des deux passes fait échouer la validation. Seules les erreurs indépendantes des valeurs réelles MUST faire échouer le rendu d'essai : erreur de syntaxe, filtre, test, fonction ou méthode inconnu, et opérateur `/` appliqué à un chemin de champ ; une erreur de type ou d'opération causée par le contexte fictif MUST NOT faire échouer la validation. Un filtre intégré appliqué à un champ fictif (conversion `int`/`float`, `round`, `abs`, `split`, `upper`, `items`…) MUST NOT interrompre le rendu d'essai : la suite du template reste vérifiée. Une opération arithmétique sur un champ brut (`{{ count + 1 }}`) interrompt la passe en cours sans erreur, et le corps d'un `elif` n'est vérifié par aucune des deux passes ; ces limites sont documentées. La même règle s'applique à tout rendu d'essai effectué par valerter (`throttle.key`, `subject_template`, `body_template` des notifiers).

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

#### Scenario: Filtre inconnu après une conversion
- **WHEN** le `body` d'un template vaut `{{ status | int }}-{{ host | truncat(10) }}` (ou `{{ x | float | round(2) }} {{ y | nosuch }}`, ou `{{ host | split('.') | first }} {{ host | nosuch }}`)
- **THEN** la validation échoue avec une erreur de template contenant `body render` et le nom du filtre inconnu

#### Scenario: Filtre inconnu dans une branche alternative
- **WHEN** le `body` d'un template vaut `{% if a %}ok{% else %}{{ a | nosuch }}{% endif %}`, `{% if not a %}{{ a | nosuch }}{% endif %}` ou `{% if a is not defined %}{{ a | nosuch }}{% endif %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtre inconnu dans un corps de boucle
- **WHEN** le `body` d'un template vaut `{% for i in items %}{{ i | nosuch }}{% endfor %}` ou `{% for k, v in m | items %}{{ v | nosuch }}{% endfor %}`
- **THEN** la validation échoue avec une erreur de template contenant `body render` et `nosuch`

#### Scenario: Filtres intégrés usuels sur des champs
- **WHEN** un template utilise `{{ a | length }} {{ a | join(',') }} {{ a | default('x') | upper }} {{ a | replace('a', 'b') | lower | trim }} {{ a | tojson }} {{ a | dictsort }} {{ count | int + 1 }}`
- **THEN** la validation réussit

### Requirement: Indice pour les noms de champ contenant une barre oblique
Le système SHALL, lorsqu'un rendu d'essai échoue sur l'opérateur `/` et que le template contient, dans une expression `{{ ... }}`, un chemin de champ comportant `/` dont la partie gauche est un chemin pointé (`a.b/c`) ou dont la partie droite contient `.`, `-` ou `/`, ajouter au message d'erreur une ligne `hint:` proposant la réécriture en notation crochets sur l'objet parent (ex. `{{ ocp.annotations.authentication.openshift["io/username"] }}`) ; si le segment contenant `/` est au premier niveau (aucun objet parent), l'indice MUST NOT proposer de syntaxe inexistante et SHALL expliquer que ce champ n'est pas adressable directement et qu'il faut le renommer dans la requête LogsQL (pipe `rename`). Une division entre deux identifiants simples sans espace (`{{ total/count }}`) MUST NOT produire d'indice ni faire échouer la validation.

#### Scenario: Annotation Kubernetes
- **WHEN** un template contient `{{ ocp.annotations.authentication.openshift.io/username }}`
- **THEN** la validation échoue et le message contient un indice suggérant `openshift["io/username"]`

#### Scenario: Champ de premier niveau contenant une barre oblique
- **WHEN** un template contient `{{ io/user-name }}`
- **THEN** la validation échoue et l'indice mentionne le pipe LogsQL `rename` (ex. `| rename "io/user-name" as io_user_name`) sans proposer `fields["io/user-name"]`

#### Scenario: Division entre deux champs
- **WHEN** un template contient `{{ total/count }}`
- **THEN** la validation réussit et aucun indice n'est produit
