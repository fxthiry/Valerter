## MODIFIED Requirements

### Requirement: Échec de démarrage avec code de sortie non nul
Le démon MUST se terminer avec le code de sortie 1, sans lancer aucune tâche de règle, si une étape de démarrage échoue : chargement ou validation de la configuration, compilation, création des notifiers, validation des destinations, validation des templates e-mail ou installation de l'exporteur de métriques. Toute erreur fatale, au démarrage comme à l'exécution et en mode `--validate`, MUST être journalisée une seule fois au niveau ERROR par le système de logs, dans le format choisi (`--log-format`), et le processus MUST NOT écrire de ligne non structurée `Error: ...` sur la sortie d'erreur.

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

#### Scenario: Erreur fatale au format JSON
- **WHEN** valerter est lancé avec `--log-format json` (démon ou `--validate`) sur une configuration dont un notifier référence une variable d'environnement non définie
- **THEN** chaque ligne de la sortie d'erreur est un objet JSON, dont une ligne de niveau ERROR contenant `Failed to create notifiers: 1 errors`
- **AND** aucune ligne ne commence par `Error:` et le code de sortie est 1

### Requirement: Fin inattendue de toutes les tâches
Le moteur SHALL se terminer en erreur lorsque toutes les tâches se sont arrêtées sans qu'un arrêt ait été demandé ; le démon SHALL alors annuler le jeton d'arrêt, laisser le worker de notifications vider les files dans la limite du délai de vidage (20 secondes au plus, sans attente si les files sont vides), puis s'arrêter avec le code 1.

#### Scenario: Plus aucune tâche active
- **WHEN** la dernière tâche active se termine (normalement ou en erreur fatale) hors arrêt demandé
- **THEN** le message ERROR « All rule tasks completed unexpectedly » est journalisé
- **AND** le processus se termine avec le code 1, sans attente supplémentaire si les files sont vides et au plus 20 secondes après ce message sinon (plus l'arrêt borné du runtime)

#### Scenario: Relance par systemd
- **WHEN** le démon tourne sous l'unité systemd fournie et se termine parce que toutes ses tâches se sont arrêtées
- **THEN** l'unité passe à l'état `failed` et systemd la relance conformément à `Restart=on-failure`

### Requirement: Arrêt gracieux sur signal
Le démon SHALL déclencher l'arrêt gracieux à la réception de SIGTERM ou SIGINT (sous Unix ; Ctrl+C uniquement sur les autres plateformes), en annulant toutes les tâches de règles, puis, une fois toutes ces tâches arrêtées, en laissant au worker de notifications au plus 20 secondes pour vider la file et au serveur de métriques au plus 2 secondes pour se terminer, avant de quitter avec le code 0. Un second SIGTERM ou SIGINT reçu pendant l'arrêt MUST provoquer la sortie immédiate du processus avec le code 1. La destruction du runtime asynchrone en fin de processus (arrêt gracieux ou erreur) MUST NOT attendre plus de 2 secondes les tâches bloquantes encore en cours, comme une résolution DNS bloquée.

#### Scenario: Réception de SIGTERM
- **WHEN** le démon reçoit SIGTERM
- **THEN** les logs « Received SIGTERM », « Initiating graceful shutdown », « Shutdown signal received, aborting all rules », « All rule tasks stopped », « Waiting for notification worker to drain queue... » puis « valerter shutdown complete » sont émis
- **AND** le processus se termine avec le code 0

#### Scenario: Réception de SIGINT
- **WHEN** le démon reçoit SIGINT
- **THEN** le log « Received SIGINT (Ctrl+C) » est émis et la même séquence d'arrêt est suivie

#### Scenario: Alertes en file à l'arrêt
- **WHEN** l'arrêt est demandé alors que des alertes attendent dans la file
- **THEN** le vidage de la file ne commence qu'après « All rule tasks stopped »
- **AND** le worker termine l'alerte en cours et envoie les alertes restantes dans la limite de 20 secondes, et le processus se termine avec le code 0 même si ce délai expire

#### Scenario: Second signal
- **WHEN** un second SIGTERM ou SIGINT est reçu pendant l'arrêt, quelle qu'en soit la phase (arrêt des tâches, vidage de la file ou attente du serveur de métriques)
- **THEN** le log WARN « Second shutdown signal received, forcing immediate exit » est émis
- **AND** le processus se termine immédiatement avec le code 1, sans attendre la fin des envois en cours ni le vidage de la file

#### Scenario: Résolution DNS bloquée à l'arrêt
- **WHEN** l'arrêt est demandé alors qu'une résolution DNS d'une tâche est bloquée dans le pool de tâches bloquantes
- **THEN** le processus se termine au plus 2 secondes après la fin de la séquence d'arrêt, dans le `TimeoutStopSec=30` de l'unité fournie

### Requirement: Paquet Debian
Le paquet Debian SHALL installer le binaire dans `/usr/bin/valerter`, la configuration d'exemple dans `/etc/valerter/config.yaml` (déclarée comme conffile, donc préservée lors des mises à jour) et le template `default-email.html.j2` dans `/etc/valerter/templates/`, et ses scripts de maintenance SHALL gérer l'utilisateur système, les permissions et le service comme décrit ci-dessous. Les actions sur le service MUST n'être exécutées que si systemd est le gestionnaire actif du système (répertoire `/run/systemd/system` présent).

#### Scenario: Installation (configure)
- **WHEN** le paquet est configuré
- **THEN** le groupe système `valerter` et l'utilisateur système `valerter` (sans home, shell `/usr/sbin/nologin`) sont créés s'ils n'existent pas
- **AND** `/etc/valerter` est attribué à `root:valerter` en mode 750 et `/etc/valerter/config.yaml` à `root:valerter` en mode 640
- **AND** les répertoires `rules.d`, `templates.d` et `notifiers.d` sont créés s'ils sont absents, en `root:valerter` mode 750
- **AND** `/etc/valerter/templates` est attribué à `valerter:valerter` en mode 755, ses fichiers en mode 644, puis `systemctl daemon-reload` est exécuté si systemd est actif

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
- **THEN** le script prerm arrête le service sans condition sur son état (y compris un service en `activating (auto-restart)` entre deux relances) et le désactive, avant la suppression des fichiers du paquet
- **AND** le script postrm exécute `systemctl daemon-reload`, l'utilisateur `valerter` et la configuration étant conservés

#### Scenario: Purge
- **WHEN** le paquet est purgé
- **THEN** l'utilisateur et le groupe `valerter` sont supprimés, le répertoire `/etc/valerter` est supprimé et `systemctl daemon-reload` est exécuté

#### Scenario: Installation sans systemd actif
- **WHEN** le paquet est installé ou mis à jour dans un conteneur ou un chroot où systemd n'est pas le gestionnaire actif
- **THEN** postinst n'exécute aucune commande `systemctl` et n'écrit pas l'avertissement « valerter failed to start after upgrade »
