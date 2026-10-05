# notifier-email Specification

## Purpose
Le notifier `email` envoie chaque alerte par SMTP, en HTML, à une liste de destinataires définie dans
`notifiers.<nom>` avec `type: email`. Cette capacité couvre la configuration SMTP (hôte, port, TLS, authentification,
expéditeur, destinataires), la validation au démarrage, la construction du message (sujet, corps HTML), l'envoi par
destinataire, les relances, les métriques propres au notifier et la protection des secrets. La file d'envoi, le
registre et le routage des alertes relèvent de `notification-dispatch` ; le rendu des templates de message de premier
niveau (`title`, `body`, `email_body_html`) relève de `message-templating`.

## Requirements

### Requirement: Schéma de configuration email
Le système SHALL accepter un notifier `type: email` avec les clés obligatoires `smtp.host` (chaîne), `smtp.port`
(entier 16 bits), `from`, `to` (liste) et `subject_template`, et les clés optionnelles `smtp.username`,
`smtp.password`, `smtp.tls` (défaut `starttls`), `smtp.tls_verify` (défaut `true`), `body_template` et
`body_template_file` ; toute clé inconnue dans le notifier ou dans `smtp` MUST être rejetée au chargement.

#### Scenario: Configuration minimale acceptée
- **WHEN** un notifier déclare `type: email`, `smtp.host`, `smtp.port`, `from`, `to` et `subject_template` seulement
- **THEN** le notifier est créé avec `tls: starttls`, `tls_verify: true`, sans authentification et avec le template de corps intégré

#### Scenario: Clé inconnue rejetée
- **WHEN** la section `smtp` contient une clé non prévue (par exemple `timeout`)
- **THEN** le chargement de la configuration échoue

#### Scenario: Clé obligatoire manquante
- **WHEN** `subject_template` est absent
- **THEN** le chargement de la configuration échoue

### Requirement: Modes TLS
Le système SHALL accepter pour `smtp.tls` exactement les valeurs `none`, `starttls` et `tls` (en minuscules) : `none`
établit une connexion SMTP en clair sans aucun chiffrement, `starttls` exige la montée en TLS par STARTTLS (échec si le
serveur ne la propose pas) et `tls` ouvre directement une connexion TLS (TLS implicite).

#### Scenario: Mode none sans chiffrement
- **WHEN** `smtp.tls: none` est configuré
- **THEN** le message est transmis en clair sur le port configuré, sans tentative de STARTTLS

#### Scenario: STARTTLS obligatoire
- **WHEN** `smtp.tls: starttls` est configuré et que le serveur ne propose pas STARTTLS
- **THEN** l'envoi échoue au lieu de se replier sur une connexion en clair

#### Scenario: Valeur invalide
- **WHEN** `smtp.tls: ssl` est configuré
- **THEN** le chargement de la configuration échoue

### Requirement: Vérification des certificats TLS
Le système SHALL vérifier le certificat du serveur SMTP par rapport à `smtp.host` lorsque `smtp.tls` vaut `starttls`
ou `tls` et que `smtp.tls_verify` vaut `true` ; avec `smtp.tls_verify: false`, les certificats invalides ou
auto-signés MUST être acceptés ; avec `smtp.tls: none`, `smtp.tls_verify` MUST être ignoré.

#### Scenario: Certificat auto-signé accepté
- **WHEN** `smtp.tls: tls` et `smtp.tls_verify: false` sont configurés face à un serveur au certificat auto-signé
- **THEN** la connexion TLS est établie et l'envoi peut aboutir

#### Scenario: tls_verify ignoré sans TLS
- **WHEN** `smtp.tls: none` et `smtp.tls_verify: false` sont configurés
- **THEN** le notifier est créé sans erreur et aucun paramètre TLS n'est utilisé

### Requirement: Authentification SMTP appariée
Le système SHALL authentifier la session SMTP avec `smtp.username` et `smtp.password` lorsque les deux sont fournis,
n'utiliser aucune authentification lorsque les deux sont absents, et MUST refuser au démarrage une configuration qui
n'en fournit qu'un seul, avec le message `smtp.password required when smtp.username is set` ou
`smtp.username required when smtp.password is set`.

#### Scenario: Nom d'utilisateur sans mot de passe
- **WHEN** `smtp.username` est défini et `smtp.password` est absent
- **THEN** la création du notifier échoue avec `invalid notifier '<nom>': smtp.password required when smtp.username is set`

#### Scenario: Mot de passe sans nom d'utilisateur
- **WHEN** `smtp.password` est défini et `smtp.username` est absent
- **THEN** la création du notifier échoue avec `invalid notifier '<nom>': smtp.username required when smtp.password is set`

### Requirement: Substitution des variables d'environnement dans les identifiants
Le système SHALL remplacer les motifs `${NOM_VAR}` (nom conforme à `[A-Za-z_][A-Za-z0-9_]*`) par la valeur de la
variable d'environnement dans `smtp.username` et `smtp.password` au démarrage, et MUST faire échouer la création du
notifier si une variable référencée n'est pas définie ; les autres champs (`smtp.host`, `from`, `to`, templates) ne
sont pas substitués.

#### Scenario: Identifiants résolus depuis l'environnement
- **WHEN** `smtp.username: "${SMTP_USER}"` et `smtp.password: "${SMTP_PASSWORD}"` sont configurés et que les deux variables existent
- **THEN** la session SMTP s'authentifie avec leurs valeurs

#### Scenario: Variable non définie
- **WHEN** `smtp.password` référence une variable absente de l'environnement
- **THEN** la création du notifier échoue avec un message préfixé par `smtp.password:` qui contient `undefined environment variable` et le nom de la variable

### Requirement: Validation des adresses
Le système SHALL analyser `from` et chaque entrée de `to` comme des boîtes aux lettres RFC 5322 (adresse seule ou
forme `Nom <adresse>`) au démarrage, et MUST refuser la configuration si une adresse est invalide ou si `to` est vide.

#### Scenario: Expéditeur invalide
- **WHEN** `from: "not-an-email"` est configuré
- **THEN** la création du notifier échoue avec `invalid 'from' address 'not-an-email': <détail>`

#### Scenario: Destinataire invalide
- **WHEN** une entrée de `to` n'est pas une adresse valide
- **THEN** la création du notifier échoue avec `invalid 'to' address '<adresse>': <détail>`

#### Scenario: Liste de destinataires vide
- **WHEN** `to: []` est configuré
- **THEN** la création du notifier échoue avec `'to' must contain at least one email address`

### Requirement: Validation du template de sujet au démarrage
Le système SHALL vérifier au démarrage que `subject_template` est un template Jinja syntaxiquement valide puis qu'il
se rend sans erreur (détection des filtres inconnus), et MUST refuser la configuration sinon, avec un message préfixé
par `subject_template:` ou `subject_template render:`.

#### Scenario: Syntaxe invalide
- **WHEN** `subject_template: "{{ title"` est configuré
- **THEN** la création du notifier échoue avec un message préfixé par `subject_template:`

#### Scenario: Filtre inconnu
- **WHEN** `subject_template` utilise un filtre qui n'existe pas
- **THEN** la création du notifier échoue avec un message préfixé par `subject_template render:`

#### Scenario: Filtres intégrés acceptés
- **WHEN** `subject_template: "[{{ rule_name | upper }}] {{ title }}"` est configuré
- **THEN** le notifier est créé sans erreur

### Requirement: Résolution du template de corps
Le système SHALL choisir le template de corps selon la priorité `body_template_file` > `body_template` > template
HTML intégré (`templates/default-email.html.j2`), résoudre un chemin relatif de `body_template_file` par rapport au
répertoire du fichier de configuration, et MUST refuser au démarrage un fichier absent, illisible, de plus de 1 Mo
(1 048 576 octets), non UTF-8, ou un template syntaxiquement invalide.

#### Scenario: Les deux sources définies
- **WHEN** `body_template` et `body_template_file` sont tous deux définis
- **THEN** le contenu de `body_template_file` est utilisé et un avertissement `both body_template and body_template_file defined, using body_template_file` est journalisé

#### Scenario: Fichier introuvable
- **WHEN** `body_template_file` désigne un fichier inexistant
- **THEN** le démarrage échoue avec `body_template_file not found: <chemin>`

#### Scenario: Fichier trop volumineux
- **WHEN** `body_template_file` désigne un fichier de plus de 1 Mo
- **THEN** le démarrage échoue avec un message indiquant `exceeds maximum size of 1MB`

#### Scenario: Template par défaut
- **WHEN** ni `body_template` ni `body_template_file` n'est défini
- **THEN** le corps est rendu avec le template HTML intégré, qui affiche le titre, le corps, la règle et l'horodatage du log

### Requirement: Exigence de email_body_html au démarrage
Le système MUST refuser de démarrer lorsqu'une règle activée a au moins une destination de type `email` et que son
template de message (s'il existe) ne définit pas `email_body_html`, en journalisant pour chaque cas
`template '<template>' requires email_body_html field when used with email destination(s) '<nom>' (rule '<règle>')`
puis en échouant avec `Email template validation failed: <n> errors`.

#### Scenario: Template sans email_body_html
- **WHEN** une règle activée route vers un notifier email et que son template ne définit que `title` et `body`
- **THEN** le démarrage échoue avec `Email template validation failed: 1 errors`

#### Scenario: Règle désactivée ignorée
- **WHEN** la règle concernée a `enabled: false`
- **THEN** cette vérification ne produit pas d'erreur pour elle

### Requirement: Rendu du sujet et du corps
Le système SHALL rendre, une seule fois par alerte, le sujet avec `subject_template` et le corps avec le template de
corps, dans un contexte exposant `title`, `body`, `rule_name`, `vl_source`, `accent_color`, `log_timestamp` et
`log_timestamp_formatted` ; dans le corps, `body` MUST valoir le `email_body_html` rendu (à défaut le `body` du
message), inséré tel quel sans échappement, tandis que les autres variables sont échappées en HTML automatiquement.

#### Scenario: Corps HTML inséré sans échappement
- **WHEN** l'alerte a `email_body_html` égal à `<p>Erreur</p>` et le template de corps contient `{{ body }}`
- **THEN** le corps de l'email contient `<p>Erreur</p>` non échappé, sans qu'un filtre `| safe` soit nécessaire

#### Scenario: Titre échappé dans le corps
- **WHEN** le titre de l'alerte contient `<script>` et le template de corps contient `{{ title }}`
- **THEN** le corps de l'email contient `&lt;script&gt;`

#### Scenario: Échec de rendu à l'envoi
- **WHEN** le rendu du sujet ou du corps échoue pour une alerte
- **THEN** aucun email n'est envoyé et le notifier renvoie une erreur `template error: ...`

### Requirement: Format du message
Le système SHALL construire chaque email avec l'en-tête `From` égal à `from`, un unique destinataire dans `To`, le
sujet rendu dans `Subject` et un corps unique de type `text/html` ; aucune partie texte alternative (multipart) n'est
produite.

#### Scenario: Email HTML mono-partie
- **WHEN** une alerte est envoyée
- **THEN** l'email reçu a un en-tête `Content-Type` `text/html` et contient le corps HTML rendu

### Requirement: Envoi séparé par destinataire
Le système SHALL envoyer un email distinct à chaque adresse de `to`, séquentiellement dans l'ordre de la liste, de
sorte que l'échec d'un destinataire n'empêche pas l'envoi aux suivants.

#### Scenario: Plusieurs destinataires
- **WHEN** `to` contient trois adresses et que toutes acceptent le message
- **THEN** trois emails distincts sont transmis, chacun avec un seul destinataire dans `To`

#### Scenario: Rejet d'un destinataire
- **WHEN** le serveur rejette définitivement le premier destinataire
- **THEN** l'envoi se poursuit vers les destinataires suivants et un avertissement `Failed to send email to recipient, continuing to next` est journalisé

### Requirement: Relances avec backoff exponentiel
Le système SHALL effectuer au plus 3 tentatives d'envoi par destinataire pour les erreurs non permanentes, en attendant
1 s après la première tentative puis 2 s après la deuxième (base 1 s, doublement, plafond 30 s), et MUST renvoyer
pour ce destinataire l'erreur `max retries exceeded` après la troisième tentative en échec.

#### Scenario: Succès après erreurs transitoires
- **WHEN** les deux premières tentatives échouent avec `connection timeout` et que la troisième réussit
- **THEN** le destinataire est compté comme réussi après 3 tentatives

#### Scenario: Tentatives épuisées
- **WHEN** les trois tentatives échouent avec une erreur transitoire
- **THEN** le destinataire est compté en échec avec `max retries exceeded`

### Requirement: Erreurs SMTP permanentes sans relance
Le système MUST abandonner immédiatement, sans relance, l'envoi à un destinataire lorsque le serveur SMTP répond par un
code de réponse de classe 5xx (échec permanent, y compris `535` pour l'authentification), et SHALL renvoyer pour ce
destinataire l'erreur `permanent error for <destinataire>: <erreur>`. Une réponse de classe 4xx, une erreur réseau, TLS,
de délai ou toute erreur sans code de réponse MUST être traitée comme transitoire ; le texte du message d'erreur MUST NOT
intervenir dans cette classification.

#### Scenario: Échec d'authentification
- **WHEN** le serveur répond `535 5.7.8 authentication failed`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Boîte inexistante
- **WHEN** le serveur répond `550 mailbox unavailable`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Autre code permanent
- **WHEN** le serveur répond `503 bad sequence of commands`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Réponse transitoire mentionnant l'authentification
- **WHEN** le serveur répond `454 4.7.0 temporary authentication failure`
- **THEN** l'erreur est traitée comme transitoire et relancée

#### Scenario: Code inclus dans un nombre plus long
- **WHEN** le serveur répond par un code 4xx dont le message contient `15501`
- **THEN** l'erreur est traitée comme transitoire et relancée

#### Scenario: Erreur réseau contenant un code
- **WHEN** la connexion échoue sans réponse SMTP avec un message contenant `550`
- **THEN** l'erreur est traitée comme transitoire et relancée

### Requirement: Résultat global et métriques
Le système SHALL considérer l'alerte comme livrée dès qu'au moins un destinataire a réussi, en incrémentant une fois
`valerter_alerts_sent_total{rule_name, vl_source, notifier_name, notifier_type="email"}` ; il SHALL incrémenter
`valerter_email_recipient_errors_total{rule_name, vl_source, notifier_name}` pour chaque destinataire en échec ; si
tous les destinataires échouent, il MUST incrémenter une fois `valerter_notify_errors_total` et
`valerter_alerts_failed_total` (mêmes libellés que `valerter_alerts_sent_total`), journaliser
`Email delivery failed to all recipients` au niveau error et renvoyer l'erreur `all <n> recipients failed`.

#### Scenario: Succès partiel
- **WHEN** sur deux destinataires, l'un réussit et l'autre échoue définitivement
- **THEN** le notifier renvoie un succès, `valerter_alerts_sent_total` augmente de 1 et `valerter_email_recipient_errors_total` augmente de 1

#### Scenario: Échec total
- **WHEN** les deux destinataires échouent
- **THEN** le notifier renvoie l'erreur `all 2 recipients failed`, `valerter_email_recipient_errors_total` augmente de 2, et `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent chacun de 1

### Requirement: Délais réseau SMTP
Le système SHALL utiliser le délai d'attente par défaut de la bibliothèque SMTP pour chaque connexion et ne MUST
exposer aucune clé de configuration de timeout SMTP ; chaque tentative ouvre une nouvelle connexion (pas de pool).

#### Scenario: Aucune clé de timeout
- **WHEN** l'opérateur ajoute `smtp.timeout` à la configuration
- **THEN** le chargement échoue car la clé est inconnue

### Requirement: Protection des secrets
Le système MUST ne jamais exposer `smtp.password` ni les identifiants résolus dans les journaux ou les sorties de
débogage : le mot de passe est rendu `[REDACTED]` dans la représentation de la configuration, et la représentation du
notifier se limite à son nom, à l'adresse `from` et au nombre de destinataires.

#### Scenario: Débogage de la configuration
- **WHEN** la configuration d'un notifier email avec mot de passe est formatée pour le débogage
- **THEN** la sortie contient `[REDACTED]` et pas la valeur du mot de passe

#### Scenario: Débogage du notifier
- **WHEN** un notifier email authentifié est formaté pour le débogage
- **THEN** la sortie contient `name`, `from` et `to_count`, sans nom d'utilisateur, mot de passe ni détail du transport
