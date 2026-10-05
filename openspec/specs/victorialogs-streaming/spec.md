# victorialogs-streaming Specification

## Purpose
Cette capacité décrit la connexion en streaming de valerter à l'endpoint `/select/logsql/tail` de VictoriaLogs : construction de la requête, options de connexion par source (Basic Auth, en-têtes, TLS, timeouts, keepalive TCP), une connexion par couple règle/source, reconnexion avec backoff exponentiel (y compris après une fin de flux propre), découpage NDJSON sûr en UTF-8 et signalement de la reconnexion au throttling. Le chargement et la validation de la configuration (clés `victorialogs.*`, résolution des `${VAR}`, restrictions de requête LogsQL) relèvent de la capacité configuration ; l'orchestration des tâches, leur redémarrage après panic et l'arrêt relèvent de rule-engine ; la définition des métriques relève d'observability ; l'interprétation des lignes reçues relève de log-parsing.

## Requirements

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

### Requirement: En-têtes HTTP standard
Le système SHALL envoyer sur chaque requête tail les en-têtes `Accept: application/x-ndjson` et `Connection: keep-alive`.

#### Scenario: En-têtes présents sans configuration particulière
- **WHEN** une source n'a ni `basic_auth` ni `headers`
- **THEN** la requête porte `Accept: application/x-ndjson` et `Connection: keep-alive`
- **AND** aucun en-tête `Authorization` n'est envoyé

### Requirement: Authentification Basic par source
Le système SHALL, lorsque `victorialogs.<source>.basic_auth` (champs `username` et `password` obligatoires) est défini, envoyer un en-tête `Authorization: Basic <base64(username:password)>` sur chaque requête vers cette source, et uniquement vers cette source.

#### Scenario: Identifiants envoyés
- **WHEN** la source a `basic_auth: { username: "u", password: "p" }`
- **THEN** chaque requête tail vers cette source porte `Authorization: Basic dTpw`

#### Scenario: Identifiants refusés
- **WHEN** VictoriaLogs répond `401 Unauthorized`
- **THEN** la tentative est traitée comme une erreur HTTP (journalisée puis réessayée avec backoff)

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

### Requirement: Vérification TLS
Le système SHALL vérifier les certificats TLS du serveur VictoriaLogs par défaut, et MUST accepter les certificats invalides (auto-signés, nom non concordant, expirés) uniquement lorsque `victorialogs.<source>.tls.verify: false` est défini pour cette source.

#### Scenario: Vérification par défaut
- **WHEN** la source n'a pas de bloc `tls`, ou a `tls: {}`
- **THEN** la vérification des certificats est active (`verify` vaut `true` par défaut)

#### Scenario: Vérification désactivée
- **WHEN** la source a `tls: { verify: false }` et présente un certificat auto-signé
- **THEN** la connexion HTTPS est établie malgré le certificat invalide

### Requirement: Timeouts et keepalive TCP
Le système SHALL appliquer un timeout d'établissement de connexion TCP de 10 s et activer le keepalive TCP avec un intervalle de 60 s sur chaque connexion tail, et MUST NOT appliquer de timeout de lecture ni de timeout global de requête, le flux tail étant de durée illimitée.

#### Scenario: Hôte injoignable (trou noir réseau)
- **WHEN** l'hôte VictoriaLogs ne répond pas au SYN
- **THEN** la tentative échoue au bout de 10 s puis suit le backoff de reconnexion

#### Scenario: Flux silencieux
- **WHEN** la connexion est établie mais aucune donnée n'arrive pendant plusieurs minutes
- **THEN** la connexion reste ouverte (pas de coupure par timeout de lecture)

### Requirement: Une connexion par couple règle/source
Le système SHALL ouvrir une connexion tail indépendante pour chaque couple (règle activée, source ciblée) : une règle sans `vl_sources` (ou avec une liste vide) cible toutes les sources déclarées, une règle avec `vl_sources` ne cible que les sources listées. Chaque connexion utilise l'URL, la Basic Auth, les en-têtes et la configuration TLS de sa propre source, et l'état (tampon, backoff, compteurs d'échecs) d'une connexion n'affecte aucune autre.

#### Scenario: Diffusion vers toutes les sources
- **WHEN** deux sources `vldev` et `vlprod` sont déclarées et une règle n'a pas de `vl_sources`
- **THEN** deux connexions tail sont ouvertes pour cette règle, une par source
- **AND** chaque événement reçu est associé au nom de la source qui l'a fourni

#### Scenario: Ciblage d'une seule source
- **WHEN** une règle a `vl_sources: [vlprod]`
- **THEN** une seule connexion tail est ouverte pour cette règle, vers `vlprod`

#### Scenario: Source en panne isolée
- **WHEN** la source `vldev` est injoignable et `vlprod` fonctionne
- **THEN** les connexions vers `vlprod` continuent de recevoir et de traiter des événements pendant que celles vers `vldev` se reconnectent

### Requirement: Réponse HTTP non-2xx
Le système SHALL traiter toute réponse dont le statut n'est pas 2xx comme un échec de tentative : il lit le corps de la réponse, le ramène sur une seule ligne (espaces consécutifs fusionnés), le tronque à 512 caractères suivis de `…` s'il est plus long (ou le remplace par `<empty body>` s'il est vide), journalise un avertissement `HTTP error from VictoriaLogs` avec le statut et ce corps, puis attend le délai de backoff avant de réessayer.

#### Scenario: Requête refusée par VictoriaLogs
- **WHEN** VictoriaLogs répond `400` avec le corps `unsupported pipe "stats" in /tail`
- **THEN** un avertissement est journalisé avec `status=400` et `response=unsupported pipe "stats" in /tail`
- **AND** une nouvelle tentative a lieu après le délai de backoff

#### Scenario: Erreur serveur sans corps
- **WHEN** VictoriaLogs répond `503` avec un corps vide
- **THEN** l'avertissement porte `response=<empty body>`

### Requirement: Backoff exponentiel avec gigue
Le système SHALL espacer les tentatives après échec (erreur de connexion, réponse non-2xx, erreur en cours de flux) selon un délai de base de 1 s doublé à chaque échec consécutif et plafonné à 60 s (1 s, 2 s, 4 s, 8 s, 16 s, 32 s, 60 s, 60 s…), multiplié par une gigue uniforme dans [-10 %, +10 %] tirée à chaque tentative, avec un plancher de 100 ms. Le compteur d'échecs consécutifs MUST revenir à zéro dès qu'une connexion obtient une réponse 2xx. Les tentatives sont illimitées.

#### Scenario: Échecs répétés
- **WHEN** quatre tentatives consécutives échouent
- **THEN** les délais d'attente sont d'environ 1 s, 2 s, 4 s puis 8 s, chacun à ±10 % près

#### Scenario: Plafond
- **WHEN** la source reste injoignable après sept échecs consécutifs ou plus
- **THEN** chaque nouveau délai est compris entre 54 s et 66 s

#### Scenario: Remise à zéro après succès
- **WHEN** une connexion réussit après plusieurs échecs puis échoue à nouveau
- **THEN** le délai repart d'environ 1 s

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

### Requirement: Disponibilité de la source avec anti-rebond
Le système SHALL positionner la jauge `valerter_vl_source_up{vl_source}` à 1 à chaque connexion réussie (réponse 2xx), et MUST ne la passer à 0 qu'après 3 échecs consécutifs (erreurs de connexion, réponses non-2xx ou erreurs en cours de flux) observés par une même connexion règle/source ; une fin de flux propre n'est pas comptée comme un échec.

#### Scenario: Échecs transitoires
- **WHEN** une connexion subit deux échecs consécutifs puis réussit
- **THEN** `valerter_vl_source_up` n'est jamais passée à 0

#### Scenario: Panne durable
- **WHEN** une connexion subit un troisième échec consécutif
- **THEN** `valerter_vl_source_up` passe à 0 pour cette source

### Requirement: Erreur en cours de flux
Le système SHALL, lorsqu'une erreur de lecture survient après l'établissement du flux (connexion réinitialisée, coupure réseau, corps tronqué), considérer la tentative comme un échec, attendre le délai de backoff puis rouvrir une nouvelle connexion.

#### Scenario: Coupure réseau pendant le flux
- **WHEN** la connexion est coupée brutalement au milieu du flux
- **THEN** une nouvelle connexion est ouverte après le délai de backoff
- **AND** la reconnexion réussie est signalée au throttling

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

### Requirement: Signalement de la reconnexion au throttling
Le système SHALL, lorsqu'une connexion obtient une réponse 2xx après au moins un échec (erreur de connexion, réponse non-2xx ou erreur en cours de flux), journaliser `Connection restored, throttle cache reset signal sent` et signaler la reconnexion au throttling du même couple règle/source, et MUST NOT émettre ce signal après une simple fin de flux propre ni lors de la toute première connexion.

#### Scenario: Reprise après panne
- **WHEN** la source répond 500 puis, à la tentative suivante, 200
- **THEN** le signal de reconnexion est émis une fois pour ce couple règle/source

#### Scenario: EOF propre
- **WHEN** le serveur ferme proprement le flux puis la reconnexion réussit
- **THEN** aucun signal de reconnexion n'est émis (le cache de throttling est conservé)

### Requirement: Découpage NDJSON en lignes
Le système SHALL découper le flux reçu en lignes terminées par `\n` (un `\r` final éventuel est retiré), transmettre chaque ligne complète non vide au traitement dans l'ordre de réception, ignorer les lignes vides, conserver en tampon le fragment de ligne non terminé jusqu'à l'arrivée de la suite, et MUST vider ce tampon à chaque nouvelle connexion afin qu'un fragment de l'ancienne connexion ne soit jamais recollé aux premiers octets de la nouvelle.

#### Scenario: Plusieurs lignes dans un même fragment réseau
- **WHEN** un fragment contient `L1\nL2\nL3\n`
- **THEN** les lignes `L1`, `L2` et `L3` sont traitées dans cet ordre

#### Scenario: Ligne répartie sur plusieurs fragments
- **WHEN** un fragment contient `Line1\nIncompl` puis le suivant `ete\n`
- **THEN** `Line1` est traitée immédiatement et `Incomplete` à l'arrivée du second fragment

#### Scenario: Fragment orphelin à la reconnexion
- **WHEN** une connexion se termine avec un fragment non terminé en tampon
- **THEN** ce fragment est abandonné et n'apparaît dans aucune ligne de la connexion suivante

### Requirement: Caractères UTF-8 coupés entre fragments
Le système SHALL reconstituer correctement les caractères UTF-8 multi-octets (2, 3 ou 4 octets) coupés entre plusieurs fragments réseau, sans caractère de remplacement ni perte.

#### Scenario: Emoji coupé en quatre fragments
- **WHEN** l'emoji 🚨 (`F0 9F 9A A8`) arrive octet par octet, suivi de `\n`
- **THEN** la ligne `🚨` est transmise intacte

#### Scenario: Accent coupé en deux fragments
- **WHEN** un fragment contient `Caf` + `C3` et le suivant `A9 0A`
- **THEN** la ligne `Café` est transmise intacte

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

### Requirement: Mesures de flux
Le système SHALL, sur chaque connexion réussie, enregistrer dans `valerter_query_duration_seconds{rule_name, vl_source}` le temps écoulé entre l'envoi de la requête et la réception du premier fragment de données, et mettre à jour `valerter_last_query_timestamp{rule_name, vl_source}` avec l'heure Unix courante (en secondes) à chaque fragment reçu.

#### Scenario: Premier fragment reçu
- **WHEN** le premier fragment de données arrive 120 ms après l'envoi de la requête
- **THEN** une observation d'environ 0,12 s est enregistrée dans `valerter_query_duration_seconds`
- **AND** les fragments suivants mettent à jour `valerter_last_query_timestamp` sans nouvelle observation de durée
