# rule-engine Specification

## Purpose
Cette capacité décrit le cycle de vie du démon valerter : séquence de démarrage et ordre de lancement des composants, supervision d'une tâche par couple (règle, source VictoriaLogs), isolation des erreurs, relance après panic, pipeline de traitement d'une ligne de log et arrêt gracieux, ainsi que l'intégration systemd et Debian livrée avec le projet. Le détail du streaming et des reconnexions relève de `victorialogs-streaming`, le mode `--validate` de `cli`, le parsing, le throttling, le rendu des templates et l'envoi des notifications relèvent de leurs capacités respectives, et les métriques et logs de `observability`.

## Requirements

### Requirement: Séquence de démarrage
Le démon SHALL exécuter le démarrage dans cet ordre : lecture des arguments, initialisation des logs, chargement de la configuration, validation de la configuration, compilation de la configuration, création du runtime asynchrone, création du client HTTP partagé (timeout 10 s), création du registre de notifiers, validation des destinations des règles, validation des templates e-mail, avertissement sur les `mattermost_channel` inutilisés, création de la file de notifications à partir du registre (une file de capacité 100 par notifier), démarrage du serveur de métriques (s'il est activé), démarrage de la mise à jour de l'uptime, création du moteur de règles, installation du gestionnaire de signaux, lancement du worker de notifications (une tâche de livraison par notifier), puis lancement du moteur de règles.

#### Scenario: Démarrage nominal
- **WHEN** valerter est lancé avec une configuration valide
- **THEN** les logs « Loading configuration », « Validating configuration » puis « valerter starting » sont émis dans cet ordre
- **AND** le moteur de règles ne démarre qu'après le serveur de métriques, le gestionnaire de signaux et le worker de notifications

#### Scenario: Métriques prêtes avant toute émission
- **WHEN** les métriques sont activées
- **THEN** le démarrage attend que l'exporteur Prometheus soit installé et que les séries connues soient initialisées avant de lancer le moteur de règles

### Requirement: Échec de démarrage avec code de sortie non nul
Le démon MUST se terminer avec le code de sortie 1, sans lancer aucune tâche de règle, si une étape de démarrage échoue : chargement ou validation de la configuration, compilation, création des notifiers, validation des destinations, validation des templates e-mail ou installation de l'exporteur de métriques.

#### Scenario: Configuration invalide
- **WHEN** la validation de la configuration renvoie des erreurs
- **THEN** chaque erreur est journalisée au niveau ERROR avec le message « Configuration validation error », suivie de « Configuration validation failed » avec le champ `error_count`
- **AND** le processus se termine avec le code 1

#### Scenario: Destination inconnue
- **WHEN** une règle référence une destination absente du registre de notifiers
- **THEN** chaque erreur est journalisée avec le message « Destination validation error »
- **AND** le processus se termine en erreur avec « Destination validation failed: N errors » et le code 1

#### Scenario: Template e-mail incomplet
- **WHEN** une règle activée envoie vers un notifier de type email et que son template n'a pas de `email_body_html`
- **THEN** l'erreur « template '<nom>' requires email_body_html field when used with email destination '<dest>' (rule '<règle>') » est journalisée
- **AND** le processus se termine en erreur avec « Email template validation failed: N errors » et le code 1

#### Scenario: Port de métriques indisponible
- **WHEN** l'exporteur Prometheus ne peut pas être installé (par exemple port déjà occupé)
- **THEN** le message « Metrics recorder failed to initialize » est journalisé
- **AND** le processus se termine avec le code 1

### Requirement: Une tâche par couple (règle, source)
Le moteur SHALL lancer une tâche indépendante pour chaque couple (règle activée, source résolue), où une règle sans `vl_sources` (ou avec une liste vide) cible toutes les sources déclarées et une règle avec `vl_sources` ne cible que les sources nommées, dans l'ordre alphabétique des noms de sources.

#### Scenario: Règle sans vl_sources
- **WHEN** la configuration déclare les sources `vldev` et `vlprod` et une règle activée sans `vl_sources`
- **THEN** deux tâches sont lancées, une pour `vldev` et une pour `vlprod`
- **AND** chaque alerte produite porte le nom de la source qui l'a émise dans le champ `vl_source`

#### Scenario: Règle restreinte à une source
- **WHEN** une règle activée déclare `vl_sources: [vlprod]` alors que `vldev` et `vlprod` sont déclarées
- **THEN** une seule tâche est lancée, pour `vlprod`

#### Scenario: Journal de démarrage du moteur
- **WHEN** au moins une tâche a été lancée
- **THEN** le message « Rule engine started, supervising rule-source tasks » est journalisé avec le champ `task_count` égal au nombre de couples

### Requirement: Règles désactivées
Le moteur SHALL ignorer les règles dont `enabled` vaut `false` : aucune tâche n'est lancée, aucune série de métrique par règle n'est initialisée et elles ne participent pas aux validations de destinations e-mail ni au calcul de `defaults.max_streams`.

#### Scenario: Règle désactivée
- **WHEN** une règle a `enabled: false`
- **THEN** aucune tâche n'est lancée pour elle et un log DEBUG « Rule disabled, skipping » est émis
- **AND** ses séries `rule_name` n'apparaissent pas dans `/metrics` au démarrage

#### Scenario: Valeur par défaut
- **WHEN** une règle ne précise pas `enabled`
- **THEN** elle est considérée comme activée

### Requirement: Aucune règle activée
Une configuration dont toutes les règles sont désactivées MUST être refusée par la validation de la configuration (requirement « Présence minimale de notifiers, templates et règles » de `configuration`), si bien que le démon ne démarre pas et se termine avec le code 1. Le moteur SHALL conserver une garde défensive : lancé sans aucune tâche, il MUST se terminer immédiatement en erreur et le démon SHALL alors s'arrêter avec le code 1, sans attendre l'expiration des délais d'attente du worker et du serveur de métriques.

#### Scenario: Toutes les règles désactivées
- **WHEN** la configuration ne contient que des règles désactivées
- **THEN** la validation de la configuration échoue avec `all rules are disabled: enable at least one rule in config.yaml or rules.d/`
- **AND** le processus se termine avec le code 1 sans lancer le moteur

#### Scenario: Moteur lancé sans tâche
- **WHEN** le moteur est lancé avec une configuration d'exécution qui ne donne lieu à aucune tâche
- **THEN** le message ERROR « No enabled rules found, engine will exit » est journalisé
- **AND** le moteur rend une erreur et le processus se termine avec le code 1, en moins d'une seconde après ce message

#### Scenario: Relance par systemd
- **WHEN** le démon tourne sous l'unité systemd fournie et se termine parce qu'aucune règle n'est activée
- **THEN** l'unité passe à l'état `failed` et systemd la relance conformément à `Restart=on-failure`

### Requirement: Isolation des erreurs entre tâches
Le moteur SHALL confiner toute erreur fatale d'une tâche au seul couple (règle, source) concerné : cette tâche n'est pas relancée, le compteur `valerter_rule_errors_total{rule_name, vl_source}` est incrémenté et les autres tâches continuent de fonctionner.

#### Scenario: Erreur fatale d'une tâche
- **WHEN** une tâche se termine avec une erreur
- **THEN** le message ERROR « Rule task failed fatally » est journalisé avec `rule_name`, `vl_source` et `error`
- **AND** les tâches des autres sources de la même règle et des autres règles continuent sans interruption

#### Scenario: Erreur récupérable sur une ligne
- **WHEN** le traitement d'une ligne échoue (erreur de parsing ou d'envoi dans la file)
- **THEN** la ligne est abandonnée, un log DEBUG « Failed to process log line, continuing » est émis et la tâche poursuit avec la ligne suivante

### Requirement: Relance après panic
Le moteur SHALL, lorsqu'une tâche panique, journaliser l'incident, incrémenter `valerter_rule_panics_total{rule_name, vl_source}` puis relancer la tâche du même couple (règle, source) avec la même configuration après un délai fixe de 5 secondes, sans limite du nombre de relances, sauf si l'arrêt a été demandé.

#### Scenario: Panic puis relance
- **WHEN** une tâche panique alors qu'aucun arrêt n'est en cours
- **THEN** le message ERROR « Rule task panicked - CRITICAL » est journalisé avec `rule_name` et `vl_source`
- **AND** le message « Respawning rule-source task after panic delay » est journalisé avec `delay_secs = 5`
- **AND** après 5 secondes la tâche est relancée et « Rule-source task respawned after panic » est journalisé

#### Scenario: Panic pendant l'arrêt
- **WHEN** une tâche panique et que l'arrêt est demandé avant ou pendant le délai de 5 secondes
- **THEN** la tâche n'est pas relancée

#### Scenario: Panic d'une tâche inconnue
- **WHEN** une tâche panique sans que son couple (règle, source) puisse être retrouvé
- **THEN** « Rule task panicked but context not found - CRITICAL » est journalisé et `valerter_rule_panics_total{rule_name="unknown", vl_source="unknown"}` est incrémenté, sans relance

#### Scenario: Supervision suspendue pendant le délai
- **WHEN** le moteur attend les 5 secondes avant une relance
- **THEN** la supervision des autres tâches et la prise en compte de l'arrêt sont différées jusqu'à la fin de ce délai

### Requirement: Fin inattendue de toutes les tâches
Le moteur SHALL se terminer en erreur lorsque toutes les tâches se sont arrêtées sans qu'un arrêt ait été demandé ; le démon SHALL alors annuler le jeton d'arrêt et s'arrêter avec le code 1, sans attendre l'expiration des délais d'attente du worker et du serveur de métriques.

#### Scenario: Plus aucune tâche active
- **WHEN** la dernière tâche active se termine (normalement ou en erreur fatale) hors arrêt demandé
- **THEN** le message ERROR « All rule tasks completed unexpectedly » est journalisé
- **AND** le processus se termine avec le code 1, en moins d'une seconde après ce message

#### Scenario: Relance par systemd
- **WHEN** le démon tourne sous l'unité systemd fournie et se termine parce que toutes ses tâches se sont arrêtées
- **THEN** l'unité passe à l'état `failed` et systemd la relance conformément à `Restart=on-failure`

### Requirement: Pipeline de traitement d'une ligne
Chaque tâche SHALL traiter chaque ligne non vide reçue du flux dans l'ordre suivant : parsing, comptage de la correspondance, throttling, rendu du template, détermination de l'horodatage, puis dépôt de l'alerte dans la file de notifications.

#### Scenario: Ligne valide non limitée
- **WHEN** une ligne est parsée avec succès et passe le throttling
- **THEN** `valerter_logs_matched_total` est incrémenté avant le contrôle de throttling
- **AND** une alerte contenant le message rendu, `rule_name`, `vl_source`, la liste des destinations de la règle, `log_timestamp` et `log_timestamp_formatted` est déposée dans la file

#### Scenario: Échec du parsing
- **WHEN** le parsing d'une ligne échoue
- **THEN** l'erreur est comptabilisée dans `valerter_parse_errors_total` et la ligne est abandonnée sans atteindre le throttling

#### Scenario: Ligne limitée par le throttling
- **WHEN** une ligne parsée est bloquée par le throttling
- **THEN** aucun template n'est rendu et aucune alerte n'est déposée dans la file

#### Scenario: Champ _time absent
- **WHEN** les champs parsés ne contiennent pas `_time`
- **THEN** l'heure courante au format RFC 3339 est utilisée comme `log_timestamp` et un log WARN « Missing _time field in log, using current time » est émis

#### Scenario: Échec de dépôt dans la file
- **WHEN** l'alerte ne peut pas être déposée dans la file de notifications
- **THEN** un log WARN « Failed to send to notification queue » est émis et la ligne est abandonnée

### Requirement: État isolé par tâche
Chaque tâche (règle, source) SHALL posséder son propre parser et sa propre connexion au flux ; l'état de throttling est en revanche partagé par toutes les tâches d'une même règle (voir la capacité `throttling`), l'isolation entre sources étant assurée par la clé de throttling par défaut, qui contient le nom de la source.

#### Scenario: Événements identiques sur deux sources
- **WHEN** deux sources émettent le même événement pour une même règle utilisant la clé de throttling par défaut
- **THEN** les deux événements passent le throttling à leur première occurrence et produisent chacun une alerte

#### Scenario: Événements identiques avec une clé commune aux sources
- **WHEN** deux sources émettent le même événement pour une même règle dont `throttle.key` vaut `{{ rule_name }}` avec `count: 1`
- **THEN** une seule alerte est produite

#### Scenario: Défaillance de connexion d'une source
- **WHEN** la connexion de la tâche (règle, `vlprod`) échoue
- **THEN** la tâche (règle, `vldev`) continue de recevoir et de traiter ses lignes avec son propre parser

### Requirement: Arrêt gracieux sur signal
Le démon SHALL déclencher l'arrêt gracieux à la réception de SIGTERM ou SIGINT (sous Unix ; Ctrl+C uniquement sur les autres plateformes), en annulant toutes les tâches de règles, puis en laissant au worker de notifications au plus 5 secondes et au serveur de métriques au plus 2 secondes pour se terminer, avant de quitter avec le code 0.

#### Scenario: Réception de SIGTERM
- **WHEN** le démon reçoit SIGTERM
- **THEN** les logs « Received SIGTERM », « Initiating graceful shutdown », « Shutdown signal received, aborting all rules », « All rule tasks stopped », « Waiting for notification worker to drain queue... » puis « valerter shutdown complete » sont émis
- **AND** le processus se termine avec le code 0

#### Scenario: Réception de SIGINT
- **WHEN** le démon reçoit SIGINT
- **THEN** le log « Received SIGINT (Ctrl+C) » est émis et la même séquence d'arrêt est suivie

#### Scenario: Alertes en file à l'arrêt
- **WHEN** l'arrêt est demandé alors que des alertes attendent dans la file
- **THEN** le worker termine au plus l'alerte en cours d'envoi, dans la limite de 5 secondes, et les alertes restantes dans la file ne sont pas envoyées

#### Scenario: Second signal
- **WHEN** un second SIGTERM ou SIGINT est reçu pendant l'arrêt
- **THEN** il n'a aucun effet supplémentaire sur la séquence d'arrêt en cours

### Requirement: Unité systemd fournie
Le projet SHALL fournir l'unité `systemd/valerter.service`, installée dans `/lib/systemd/system/`, qui lance `/usr/bin/valerter -c /etc/valerter/config.yaml` en service `Type=simple` sous l'utilisateur et le groupe `valerter`, avec `Restart=on-failure`, `RestartSec=5`, `KillMode=mixed`, `KillSignal=SIGTERM`, `TimeoutStopSec=30`, les durcissements `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, un démarrage après `network.target` et une installation dans `multi-user.target`.

#### Scenario: Arrêt par systemd
- **WHEN** `systemctl stop valerter` est exécuté
- **THEN** systemd envoie SIGTERM et le démon effectue son arrêt gracieux, systemd n'escaladant qu'après 30 secondes

#### Scenario: Relance après échec
- **WHEN** le processus se termine avec un code non nul (échec de démarrage, notamment configuration invalide ou dont toutes les règles sont désactivées, ou fin inattendue de toutes les tâches) hors arrêt demandé par systemd
- **THEN** systemd le relance après 5 secondes, en boucle tant que la cause persiste

#### Scenario: Sortie avec code 0
- **WHEN** le processus se termine avec le code 0, ce qui n'arrive qu'après un arrêt demandé par signal
- **THEN** systemd ne le relance pas

#### Scenario: Logs vers journald
- **WHEN** le service tourne sous systemd
- **THEN** ses logs, écrits sur la sortie d'erreur, sont consultables via `journalctl -u valerter`

### Requirement: Paquet Debian
Le paquet Debian SHALL installer le binaire dans `/usr/bin/valerter`, la configuration d'exemple dans `/etc/valerter/config.yaml` (déclarée comme conffile, donc préservée lors des mises à jour) et le template `default-email.html.j2` dans `/etc/valerter/templates/`, et ses scripts de maintenance SHALL gérer l'utilisateur système, les permissions et le service comme décrit ci-dessous.

#### Scenario: Installation (configure)
- **WHEN** le paquet est configuré
- **THEN** le groupe système `valerter` et l'utilisateur système `valerter` (sans home, shell `/usr/sbin/nologin`) sont créés s'ils n'existent pas
- **AND** `/etc/valerter` est attribué à `root:valerter` en mode 750 et `/etc/valerter/config.yaml` à `root:valerter` en mode 640
- **AND** les répertoires `rules.d`, `templates.d` et `notifiers.d` sont créés s'ils sont absents, en `root:valerter` mode 750
- **AND** `/etc/valerter/templates` est attribué à `valerter:valerter` en mode 755, ses fichiers en mode 644, puis `systemctl daemon-reload` est exécuté

#### Scenario: Première installation
- **WHEN** le paquet est installé pour la première fois
- **THEN** le service n'est ni activé ni démarré automatiquement

#### Scenario: Mise à jour
- **WHEN** le paquet est mis à jour alors que le service est actif ou activé (`enabled`)
- **THEN** le script prerm n'arrête pas le service lors d'une mise à jour (`upgrade`)
- **AND** le script postinst exécute `systemctl daemon-reload` puis redémarre le service, qui tourne alors avec le nouveau binaire sans intervention manuelle
- **AND** le script postinst n'exécute pas `valerter --validate`

#### Scenario: Mise à jour depuis une version dont le prerm arrête le service
- **WHEN** le paquet est mis à jour depuis une version antérieure dont le script prerm a arrêté le service, et que ce service est activé (`enabled`)
- **THEN** le script postinst redémarre le service

#### Scenario: Échec du redémarrage après mise à jour
- **WHEN** le script postinst a redémarré le service et que celui-ci n'est pas actif 2 secondes plus tard (par exemple à cause d'une configuration invalide)
- **THEN** un avertissement bien visible est écrit sur la sortie d'erreur, indiquant la commande `journalctl -u valerter` pour consulter les logs
- **AND** le script se termine avec succès, sans faire échouer `dpkg`

#### Scenario: Mise à jour d'un service arrêté et désactivé
- **WHEN** le paquet est mis à jour alors que le service n'est ni actif ni activé
- **THEN** le service reste arrêté

#### Scenario: Suppression
- **WHEN** le paquet est supprimé (remove)
- **THEN** le service est arrêté s'il est actif, désactivé, et `systemctl daemon-reload` est exécuté, l'utilisateur `valerter` et la configuration étant conservés

#### Scenario: Purge
- **WHEN** le paquet est purgé
- **THEN** l'utilisateur et le groupe `valerter` sont supprimés, le répertoire `/etc/valerter` est supprimé et `systemctl daemon-reload` est exécuté
