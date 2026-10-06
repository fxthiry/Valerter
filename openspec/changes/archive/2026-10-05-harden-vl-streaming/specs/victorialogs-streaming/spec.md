## MODIFIED Requirements

### Requirement: Requête vers l'endpoint tail
Le système SHALL ouvrir pour chaque flux une requête HTTP `GET` vers `<url>/select/logsql/tail?query=<requête>`, où `<url>` est la valeur `victorialogs.<source>.url` dont les barres obliques finales (`/`) sont retirées, et `<requête>` est la `query` de la règle encodée en pourcentage (URL-encoding). Un éventuel chemin préfixe de l'URL est conservé. Aucun paramètre `start` n'est envoyé : le flux suit les logs en temps réel à partir de la connexion.

#### Scenario: Requête avec espaces et caractères spéciaux
- **WHEN** une règle a `query: 'level:error AND host:"srv 01"'` et la source a `url: http://vl:9428`
- **THEN** la requête est `GET http://vl:9428/select/logsql/tail?query=level%3Aerror%20AND%20host%3A%22srv%2001%22`
- **AND** aucun paramètre `start` n'est présent dans l'URL

#### Scenario: URL de source terminée par une barre oblique
- **WHEN** la source a `url: http://vl:9428/`
- **THEN** le chemin demandé est `http://vl:9428/select/logsql/tail?...` (une seule barre oblique avant `select`)

#### Scenario: URL avec chemin préfixe et plusieurs barres finales
- **WHEN** la source a `url: https://proxy.example.com/vl//`
- **THEN** le chemin demandé est `https://proxy.example.com/vl/select/logsql/tail?...`

### Requirement: En-têtes personnalisés par source
Le système SHALL appliquer à chaque requête vers une source les en-têtes déclarés dans `victorialogs.<source>.headers` (nom → valeur) en dernier : un en-tête personnalisé dont le nom (comparé sans tenir compte de la casse) coïncide avec un en-tête standard ou avec l'en-tête `Authorization` de la Basic Auth le remplace, de sorte que chaque nom n'est envoyé qu'une fois. Le système MUST ne jamais écrire ces valeurs ni le mot de passe Basic Auth dans les journaux. À titre de garde défensive (un en-tête invalide étant normalement refusé dès le chargement de la configuration), si un nom ou une valeur d'en-tête invalide parvient malgré tout au démarrage d'une tâche (règle, source), la tâche MUST échouer avec une erreur qui nomme l'en-tête sans en afficher la valeur, plutôt que de boucler en reconnexion.

#### Scenario: Jeton Bearer et Basic Auth combinés
- **WHEN** la source définit `basic_auth` et `headers: { X-Tenant: "t1", Authorization-Token: "Bearer abc" }`
- **THEN** la requête porte l'en-tête Basic `Authorization` ainsi que `X-Tenant: t1` et `Authorization-Token: Bearer abc`

#### Scenario: En-tête standard remplacé
- **WHEN** la source définit `headers: { accept: "application/json" }`
- **THEN** la requête porte un seul en-tête `Accept`, de valeur `application/json`

#### Scenario: Authorization personnalisé et Basic Auth
- **WHEN** la source définit `basic_auth` et `headers: { Authorization: "Bearer abc" }`
- **THEN** la requête porte un seul en-tête `Authorization`, de valeur `Bearer abc`
- **AND** un avertissement indiquant que l'en-tête personnalisé masque `basic_auth` est journalisé au démarrage de la tâche, sans aucune valeur d'en-tête ni identifiant

#### Scenario: Garde défensive contre un en-tête invalide
- **WHEN** un nom ou une valeur de `headers` qui n'est pas un en-tête HTTP valide (par exemple une valeur contenant un saut de ligne) parvient malgré tout au démarrage de la tâche du couple règle/source, sans avoir été refusé au chargement de la configuration
- **THEN** la tâche échoue à son démarrage avec une erreur qui nomme la source et l'en-tête concerné, sans en afficher la valeur
- **AND** aucune requête n'est envoyée vers VictoriaLogs pour ce couple

### Requirement: Journalisation et comptage des tentatives de reconnexion
Le système SHALL, à chaque échec suivi d'une attente, journaliser d'abord la cause de l'échec, puis un avertissement `Connection failed, retrying` portant `rule_name`, `vl_source`, le numéro de tentative et le délai d'attente en millisecondes (`delay_ms`), et incrémenter `valerter_reconnections_total{rule_name, vl_source}`, le tout avant de commencer l'attente. La cause est un avertissement `Connection failed` pour une erreur de connexion, `Stream read error` pour une erreur en cours de flux (chacun avec le message d'erreur), ou `HTTP error from VictoriaLogs` pour une réponse non-2xx.

#### Scenario: Connexion refusée
- **WHEN** la connexion TCP est refusée
- **THEN** `valerter_reconnections_total` est incrémenté pour le couple règle/source
- **AND** les avertissements `Connection failed` puis `Connection failed, retrying` sont journalisés, dans cet ordre, avant l'attente du backoff

#### Scenario: Délai inférieur à une seconde
- **WHEN** le délai calculé pour la première tentative est de 930 ms
- **THEN** l'avertissement `Connection failed, retrying` porte `delay_ms=930`

#### Scenario: Attente longue
- **WHEN** le délai calculé est d'environ 60 s
- **THEN** la cause de l'échec est déjà présente dans les journaux pendant l'attente, et non à son terme

### Requirement: Fin de flux propre avec backoff
Le système SHALL, lorsque le serveur termine proprement la réponse (EOF sans erreur), rouvrir une connexion sans considérer cet événement comme un échec, après un délai calculé avec la même formule de backoff et de gigue : environ 1 s si au moins un fragment de données a été reçu sur cette connexion, et sinon un délai croissant avec le nombre de fins de flux vides consécutives (environ 1 s pour la première, puis 2 s, 4 s, 8 s… jusqu'à 60 s), ce compteur revenant à zéro dès qu'une connexion reçoit des données. Chaque reconnexion après EOF MUST incrémenter `valerter_reconnections_total{rule_name, vl_source}` et être journalisée en debug (`Stream ended, reconnecting`).

#### Scenario: Serveur fermant immédiatement le flux
- **WHEN** VictoriaLogs (ou un proxy) répond 200 avec un corps vide puis ferme la connexion, de façon répétée
- **THEN** les reconnexions sont espacées d'environ 1 s, 2 s, 4 s, 8 s…, sans boucle serrée (au plus 3 requêtes en 1,2 s)

#### Scenario: Fin de flux après réception de données
- **WHEN** le serveur envoie des lignes puis ferme proprement la connexion
- **THEN** une nouvelle connexion est ouverte après environ 1 s (±10 %)

#### Scenario: Données après des fins de flux vides
- **WHEN** trois fins de flux vides consécutives sont suivies d'une connexion qui reçoit des données puis se termine proprement, à nouveau vide la fois suivante
- **THEN** le délai après la connexion avec données est d'environ 1 s et celui après la fin de flux vide suivante est aussi d'environ 1 s

### Requirement: UTF-8 invalide non fatal
Le système SHALL décoder chaque ligne complète indépendamment ; lorsqu'une ligne contient une séquence UTF-8 invalide, seule cette ligne est abandonnée et `valerter_lines_discarded_total{rule_name, vl_source, reason="invalid_utf8"}` est incrémenté d'une unité par ligne abandonnée. Les autres lignes du même fragment et le fragment non terminé MUST être conservés et traités normalement. Un avertissement `Discarding log data with invalid UTF-8` portant le nombre de lignes abandonnées est journalisé au plus une fois par fragment réseau reçu. Le système MUST poursuivre la lecture du flux sans interrompre la tâche ni introduire de caractère de remplacement.

#### Scenario: Octet 0xFF dans le flux
- **WHEN** la réponse contient `{"_msg":"before"}\n{"_msg":"bad \xff\xfe"}\n{"_msg":"after"}\n` dans un seul fragment
- **THEN** les lignes `{"_msg":"before"}` et `{"_msg":"after"}` sont transmises au traitement, dans cet ordre
- **AND** seule la ligne invalide est abandonnée et `valerter_lines_discarded_total{reason="invalid_utf8"}` augmente de 1
- **AND** le flux continue (ou se reconnecte) sans que la tâche se termine en erreur

#### Scenario: Plusieurs lignes invalides dans un fragment
- **WHEN** un fragment contient deux lignes invalides et une ligne valide
- **THEN** la ligne valide est transmise, le compteur `reason="invalid_utf8"` augmente de 2 et un seul avertissement est journalisé pour ce fragment

#### Scenario: Fragment non terminé conservé
- **WHEN** un fragment contient une ligne invalide complète suivie du début `Caf` + `C3` d'une ligne, et le fragment suivant `A9 0A`
- **THEN** la ligne `Café` est transmise intacte à l'arrivée du second fragment

### Requirement: Lignes trop longues
Le système SHALL limiter la longueur d'une ligne (octets avant le `\n` terminal) à 1 048 576 octets (1 Mio) : dès qu'une ligne en cours dépasse cette taille, ses octets reçus sont abandonnés, puis tous les octets suivants jusqu'au prochain `\n` inclus le sont aussi, sans jamais émettre de fragment de cette ligne. L'avertissement `Discarding oversized log line, buffer cleared` est journalisé avec la taille observée et la limite, et `valerter_lines_discarded_total{rule_name, vl_source, reason="oversized"}` est incrémenté une fois par ligne. Les lignes précédant ou suivant la ligne trop longue, y compris dans le même fragment, MUST être traitées normalement, la mémoire retenue pour une ligne MUST ne pas dépasser la limite, et la lecture du flux MUST continuer.

#### Scenario: Ligne dépassant 1 Mio
- **WHEN** une ligne sans `\n` s'accumule au-delà de 1 048 576 octets
- **THEN** les données accumulées sont abandonnées et le compteur `reason="oversized"` est incrémenté une fois
- **AND** la connexion reste ouverte et les fragments suivants sont traités

#### Scenario: Fin de la ligne trop longue ignorée
- **WHEN** après le dépassement, un fragment contient `...fin de la ligne"}\n{"_msg":"next"}\n`
- **THEN** la fin de la ligne trop longue n'est transmise ni au parsing ni comptée comme `invalid_json`
- **AND** la ligne `{"_msg":"next"}` est transmise au traitement
- **AND** le compteur `reason="oversized"` n'est pas incrémenté une seconde fois

#### Scenario: Lignes valides dans le fragment du dépassement
- **WHEN** un fragment contient `{"_msg":"a"}\n` suivi d'octets qui font dépasser la limite à la ligne suivante
- **THEN** la ligne `{"_msg":"a"}` est transmise au traitement

#### Scenario: Taille exactement à la limite
- **WHEN** une ligne fait exactement 1 048 576 octets avant son `\n`
- **THEN** elle est conservée et transmise au traitement

#### Scenario: Reconnexion pendant l'abandon
- **WHEN** la connexion se termine alors que la fin d'une ligne trop longue n'est pas encore arrivée
- **THEN** la connexion suivante traite normalement ses premiers octets (aucun abandon hérité de l'ancienne connexion)
