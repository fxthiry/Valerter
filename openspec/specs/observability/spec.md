# observability Specification

## Purpose
Cette capacité décrit ce que valerter expose pour être supervisé : le serveur de métriques Prometheus (activation, adresse, endpoint), la liste des métriques avec leurs types et labels, leur initialisation au démarrage, l'auto-monitoring (uptime, informations de build, joignabilité des sources), ainsi que les logs structurés (formats, niveaux, variables d'environnement) et les garanties de non-fuite des secrets dans les logs. Les conditions métier qui font évoluer chaque compteur sont détaillées dans les capacités qui les émettent (`victorialogs-streaming`, parsing, `throttling`, notifiers) ; le cycle de vie du démon relève de `rule-engine`.

## Requirements

### Requirement: Activation et port du serveur de métriques
Le démon SHALL exposer les métriques Prometheus lorsque `metrics.enabled` vaut `true` (valeur par défaut), sur le port `metrics.port` (9090 par défaut), en écoutant sur toutes les interfaces IPv4 (`0.0.0.0`), adresse non configurable.

#### Scenario: Section metrics absente
- **WHEN** la configuration ne contient pas de section `metrics`
- **THEN** le serveur de métriques est démarré sur `0.0.0.0:9090`
- **AND** les logs « Starting metrics server » puis « Metrics server started on /metrics » sont émis avec le champ `port`

#### Scenario: Métriques désactivées
- **WHEN** `metrics.enabled: false`
- **THEN** aucun port n'est ouvert, aucune série n'est initialisée et le log « Metrics server disabled » est émis

#### Scenario: Clé inconnue dans la section metrics
- **WHEN** la section `metrics` contient une clé autre que `enabled` ou `port`
- **THEN** la configuration est rejetée au chargement

### Requirement: Endpoint d'exposition
Le serveur de métriques SHALL répondre en HTTP 200 sur `GET /metrics` avec le format texte d'exposition Prometheus, chaque métrique décrite étant accompagnée de son texte d'aide (`# HELP`).

#### Scenario: Scrape de /metrics
- **WHEN** un client effectue `GET http://<hôte>:<port>/metrics`
- **THEN** la réponse a le statut 200 et chaque ligne non vide est soit un commentaire commençant par `#`, soit une série `nom{labels} valeur`

### Requirement: Échec de démarrage du serveur de métriques
Le démon MUST refuser de démarrer si l'exporteur Prometheus ne peut pas être installé, notamment si le port est déjà utilisé.

#### Scenario: Port occupé
- **WHEN** `metrics.port` est déjà utilisé par un autre processus
- **THEN** « Metrics server error » puis « Metrics recorder failed to initialize » sont journalisés au niveau ERROR
- **AND** le processus se termine avec le code 1

### Requirement: Compteurs du pipeline par règle et par source
Le démon SHALL exposer les compteurs suivants, chacun portant les labels `rule_name` et `vl_source` : `valerter_logs_matched_total` (lignes parsées avec succès, avant throttling), `valerter_alerts_passed_total` (alertes ayant passé le throttling), `valerter_alerts_throttled_total` (alertes bloquées par le throttling), `valerter_reconnections_total` (reconnexions à VictoriaLogs), `valerter_rule_panics_total` (panics de tâche) et `valerter_rule_errors_total` (erreurs fatales de tâche).

#### Scenario: Ligne parsée puis limitée
- **WHEN** une ligne de la règle `r` sur la source `s` est parsée puis bloquée par le throttling
- **THEN** `valerter_logs_matched_total{rule_name="r",vl_source="s"}` et `valerter_alerts_throttled_total{rule_name="r",vl_source="s"}` augmentent de 1

#### Scenario: Ancienne jauge par règle supprimée
- **WHEN** `/metrics` est scrapé
- **THEN** aucune série nommée `valerter_victorialogs_up` n'est présente

### Requirement: Compteurs d'erreurs de parsing et de lignes écartées
Le démon SHALL exposer `valerter_parse_errors_total` avec les labels `rule_name`, `vl_source` et `error_type` (valeurs `regex_no_match` ou `invalid_json`), et `valerter_lines_discarded_total` avec les labels `rule_name`, `vl_source` et `reason` (valeurs `oversized` pour une ligne dépassant 1 Mio, `invalid_utf8` pour une ligne non UTF-8).

#### Scenario: JSON invalide
- **WHEN** une ligne d'une règle à parser JSON n'est pas du JSON valide
- **THEN** `valerter_parse_errors_total{rule_name, vl_source, error_type="invalid_json"}` augmente de 1

#### Scenario: Ligne trop longue
- **WHEN** une ligne reçue dépasse 1 048 576 octets
- **THEN** `valerter_lines_discarded_total{reason="oversized"}` augmente de 1 pour le couple (règle, source)

### Requirement: Compteurs de notification
Le démon SHALL exposer `valerter_alerts_sent_total`, `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec les labels `rule_name`, `vl_source`, `notifier_name` et `notifier_type` (`mattermost`, `webhook`, `email`, `telegram`, ou `unknown` pour une destination introuvable dans le registre), `valerter_email_recipient_errors_total` avec les labels `rule_name`, `vl_source` et `notifier_name`, et `valerter_alerts_truncated_total` avec les labels `notifier_type` et `notifier_name`.

#### Scenario: Envoi réussi
- **WHEN** une alerte de la règle `r` issue de la source `s` est envoyée avec succès par le notifier `ops` de type mattermost
- **THEN** `valerter_alerts_sent_total{rule_name="r",vl_source="s",notifier_name="ops",notifier_type="mattermost"}` augmente de 1

#### Scenario: Échec définitif
- **WHEN** l'envoi vers un notifier échoue définitivement après épuisement des tentatives
- **THEN** `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent de 1 avec les mêmes quatre labels

#### Scenario: Message tronqué
- **WHEN** un message Telegram est tronqué pour respecter la limite de longueur
- **THEN** `valerter_alerts_truncated_total{notifier_type="telegram", notifier_name}` augmente de 1

### Requirement: Métriques de la file de notifications
Le démon SHALL exposer la jauge `valerter_queue_size` (nombre d'alertes en attente dans la file partagée, sans label) et le compteur global `valerter_alerts_dropped_total` (sans label), incrémenté du nombre d'alertes les plus anciennes écrasées lorsque la file de capacité 100 déborde.

#### Scenario: Débordement de la file
- **WHEN** le worker constate que N alertes ont été écrasées faute de place
- **THEN** `valerter_alerts_dropped_total` augmente de N et un log WARN « Queue full, dropping N oldest alerts » est émis avec le champ `dropped_count`

### Requirement: Métriques de connexion à VictoriaLogs
Le démon SHALL exposer la jauge `valerter_last_query_timestamp{rule_name, vl_source}` (horodatage Unix en secondes du dernier fragment reçu), l'histogramme `valerter_query_duration_seconds{rule_name, vl_source}` (délai entre l'envoi de la requête et le premier fragment reçu, exposé au format summary avec le label `quantile` et les séries `_sum` et `_count`), et la jauge par source `valerter_vl_source_up{vl_source}`.

#### Scenario: Premier fragment reçu
- **WHEN** une tâche reçoit le premier fragment d'une connexion
- **THEN** une observation est ajoutée à `valerter_query_duration_seconds` pour son couple (règle, source)
- **AND** `valerter_last_query_timestamp` est mis à jour à chaque fragment reçu

### Requirement: Joignabilité des sources avec anti-rebond
La jauge `valerter_vl_source_up{vl_source}` SHALL valoir 0 au démarrage pour chaque source déclarée, passer à 1 dès qu'une connexion réussit vers cette source, et ne repasser à 0 qu'après 3 échecs consécutifs (erreur de connexion, réponse HTTP d'erreur ou fin de flux) observés par une même tâche, cette valeur n'étant pas configurable.

#### Scenario: Source jamais joignable
- **WHEN** une source déclarée n'a encore accepté aucune connexion
- **THEN** `valerter_vl_source_up{vl_source="<source>"}` vaut 0

#### Scenario: Échec transitoire
- **WHEN** une tâche connectée subit 1 ou 2 échecs consécutifs puis se reconnecte
- **THEN** `valerter_vl_source_up` reste à 1

#### Scenario: Panne durable
- **WHEN** une tâche subit 3 échecs consécutifs vers sa source
- **THEN** `valerter_vl_source_up` pour cette source passe à 0

### Requirement: Auto-monitoring du processus
Le démon SHALL exposer la jauge `valerter_build_info{version}` valant toujours 1 avec la version du binaire, et la jauge `valerter_uptime_seconds` égale au nombre de secondes écoulées depuis le démarrage, mise à jour toutes les 15 secondes.

#### Scenario: Version exposée
- **WHEN** valerter 2.0.3 est démarré avec les métriques activées
- **THEN** `/metrics` contient `valerter_build_info{version="2.0.3"} 1`

#### Scenario: Uptime
- **WHEN** le démon tourne depuis plus de 15 secondes
- **THEN** `valerter_uptime_seconds` est positive et sa valeur est réactualisée toutes les 15 secondes

### Requirement: Initialisation des séries au démarrage
Lorsque les métriques sont activées, le démon SHALL, avant de lancer les tâches de règles, initialiser à zéro : `valerter_build_info`, `valerter_uptime_seconds`, `valerter_queue_size`, `valerter_alerts_dropped_total`, `valerter_vl_source_up` pour chaque source déclarée, et, pour chaque couple (règle activée, source résolue), `valerter_logs_matched_total`, `valerter_alerts_sent_total`, `valerter_alerts_throttled_total`, `valerter_alerts_passed_total`, `valerter_parse_errors_total`, `valerter_rule_panics_total`, `valerter_rule_errors_total`, `valerter_reconnections_total` (labels `rule_name`, `vl_source`), `valerter_lines_discarded_total` (avec `reason="oversized"`), `valerter_query_duration_seconds` et `valerter_last_query_timestamp`, ainsi que, pour chaque notifier, `valerter_alerts_failed_total{notifier}` et `valerter_notify_errors_total{notifier}`.

#### Scenario: Séries visibles avant tout événement
- **WHEN** valerter démarre avec une règle activée sur deux sources et un notifier, puis `/metrics` est scrapé avant tout événement
- **THEN** les séries listées ci-dessus sont présentes pour chacun des deux couples (règle, source) avec la valeur 0
- **AND** le log « Metrics initialized to zero » est émis avec `rule_source_pair_count`, `source_count` et `notifier_count`

#### Scenario: Jeux de labels distincts entre initialisation et émission
- **WHEN** un compteur initialisé avec un jeu de labels réduit (par exemple `valerter_alerts_sent_total{rule_name, vl_source}` ou `valerter_alerts_failed_total{notifier}`) est ensuite émis par le pipeline
- **THEN** l'émission crée une série distincte avec le jeu de labels complet, et la série initialisée reste exposée à 0

### Requirement: Métriques émises avant l'installation de l'exporteur
Les métriques émises avant l'installation de l'exporteur Prometheus SHALL être perdues ; en particulier `valerter_notifier_config_errors_total{notifier, error_type="env_var_resolution"}`, incrémenté lors de la création des notifiers, n'est jamais observable puisque cette création précède le démarrage du serveur de métriques et qu'une telle erreur interrompt le démarrage.

#### Scenario: Variable d'environnement manquante dans un notifier
- **WHEN** l'URL d'un notifier référence une variable d'environnement non définie
- **THEN** le démarrage échoue avec le code 1 avant l'ouverture du port de métriques et aucune série `valerter_notifier_config_errors_total` n'est exposée

### Requirement: Logs structurés sur la sortie d'erreur
Le démon SHALL écrire tous ses logs sur la sortie d'erreur standard, au format texte lisible par défaut ou au format JSON lorsque `--log-format json` ou la variable d'environnement `LOG_FORMAT=json` est fourni, l'option en ligne de commande l'emportant sur la variable.

#### Scenario: Format texte par défaut
- **WHEN** valerter est lancé sans `--log-format` ni `LOG_FORMAT`
- **THEN** les logs sont écrits en texte lisible sur la sortie d'erreur

#### Scenario: Format JSON
- **WHEN** valerter est lancé avec `LOG_FORMAT=json`
- **THEN** chaque log est un objet JSON sur une ligne dont les champs de l'événement (dont le message) sont placés au premier niveau, accompagnés du span courant (par exemple `rule_name` et `vl_source` d'une tâche de règle) sans la liste des spans parents

#### Scenario: Format inconnu
- **WHEN** `--log-format` ou `LOG_FORMAT` a une valeur autre que `text` ou `json`
- **THEN** valerter refuse les arguments et se termine sans démarrer

#### Scenario: Sortie standard réservée
- **WHEN** valerter tourne en mode démon
- **THEN** rien n'est écrit sur la sortie standard, celle-ci n'étant utilisée que par le rapport de `--validate`

### Requirement: Niveaux de log configurables par RUST_LOG
Le démon SHALL filtrer les logs selon la variable d'environnement `RUST_LOG` (syntaxe de filtre `tracing`, par exemple `debug` ou `valerter=trace`) et appliquer le niveau `info` lorsque cette variable est absente ou invalide ; le niveau n'est pas configurable dans le fichier de configuration.

#### Scenario: Niveau par défaut
- **WHEN** `RUST_LOG` n'est pas défini
- **THEN** les logs de niveau INFO, WARN et ERROR sont émis et les logs DEBUG et TRACE ne le sont pas

#### Scenario: Niveau debug
- **WHEN** `RUST_LOG=debug`
- **THEN** les logs DEBUG sont également émis (par exemple « Rule disabled, skipping » ou « Regex did not match, skipping log »)

#### Scenario: Logs de démarrage avant chargement de la configuration
- **WHEN** le fichier de configuration est introuvable ou invalide
- **THEN** l'erreur est déjà journalisée selon le format et le niveau choisis, l'initialisation des logs précédant le chargement de la configuration

### Requirement: Champs contextuels des logs
Les logs émis dans le contexte d'une tâche de règle SHALL porter les champs `rule_name` et `vl_source`, et les logs d'erreur SHALL porter le détail dans un champ `error`.

#### Scenario: Log d'une tâche
- **WHEN** une tâche de la règle `r` sur la source `s` journalise un événement
- **THEN** le log contient `rule_name=r` et `vl_source=s`

### Requirement: Non-fuite des secrets dans les logs
Le démon MUST ne jamais écrire dans ses logs la valeur des secrets de configuration : les valeurs protégées (mot de passe `basic_auth`, valeurs des `headers` des sources VictoriaLogs, URL de webhook et autres champs secrets des notifiers) s'affichent `[REDACTED]` dans toute représentation de débogage ou d'affichage, la représentation de débogage des notifiers n'expose ni URL, ni en-têtes, ni jeton, ni identifiants de chat, et les erreurs HTTP des notifiers Mattermost, webhook et Telegram sont journalisées sans l'URL appelée.

#### Scenario: Représentation d'une configuration avec secrets
- **WHEN** une configuration contenant un mot de passe `basic_auth` et des en-têtes secrets est formatée pour le débogage
- **THEN** le résultat contient `[REDACTED]` à la place de chaque valeur secrète et ne contient aucune de ces valeurs

#### Scenario: Erreur réseau vers un webhook
- **WHEN** l'envoi vers un webhook Mattermost ou générique échoue sur une erreur de transport
- **THEN** le log d'erreur contient la cause de l'erreur mais pas l'URL du webhook

#### Scenario: Erreur réseau vers Telegram
- **WHEN** l'envoi vers l'API Telegram échoue sur une erreur de transport
- **THEN** le log d'erreur ne contient pas l'URL de l'API, qui inclut le jeton du bot
