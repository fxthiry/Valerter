## MODIFIED Requirements

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

### Requirement: Fin inattendue de toutes les tâches
Le moteur SHALL se terminer en erreur lorsque toutes les tâches se sont arrêtées sans qu'un arrêt ait été demandé ; le démon SHALL alors annuler le jeton d'arrêt et s'arrêter avec le code 1, sans attendre l'expiration des délais d'attente du worker et du serveur de métriques.

#### Scenario: Plus aucune tâche active
- **WHEN** la dernière tâche active se termine (normalement ou en erreur fatale) hors arrêt demandé
- **THEN** le message ERROR « All rule tasks completed unexpectedly » est journalisé
- **AND** le processus se termine avec le code 1, en moins d'une seconde après ce message

#### Scenario: Relance par systemd
- **WHEN** le démon tourne sous l'unité systemd fournie et se termine parce que toutes ses tâches se sont arrêtées
- **THEN** l'unité passe à l'état `failed` et systemd la relance conformément à `Restart=on-failure`

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
