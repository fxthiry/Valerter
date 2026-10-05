# cli Specification

## Purpose
Cette capacité décrit l'interface en ligne de commande du binaire `valerter` : options acceptées, variables d'environnement lues directement par le processus, mode de validation `--validate`, messages et codes de sortie liés au chargement et à la validation de la configuration. La séquence de démarrage, les échecs de démarrage du démon et l'arrêt sur signal relèvent de `rule-engine`. Le contenu de la configuration, sa fusion multi-fichiers et ses règles de validation sont décrits dans `configuration` ; le comportement du démon une fois démarré (streaming, throttling, notifications, métriques) relève des capacités correspondantes.

## Requirements

### Requirement: Options de la ligne de commande
Le binaire `valerter` SHALL accepter exactement les options `-c`/`--config <PATH>`, `--validate`, `--log-format <text|json>`, `-h`/`--help` et `-V`/`--version`, et MUST refuser tout argument inconnu.

#### Scenario: Option inconnue
- **WHEN** l'utilisateur lance `valerter --bogus`
- **THEN** le processus affiche `error: unexpected argument '--bogus' found` suivi de `Usage: valerter [OPTIONS]` sur la sortie d'erreur et se termine avec le code 2

#### Scenario: Aide et version
- **WHEN** l'utilisateur lance `valerter --help` ou `valerter --version`
- **THEN** le processus affiche respectivement l'aide (description `Real-time alerting from VictoriaLogs to Mattermost`) ou la version du paquet, puis se termine avec le code 0 sans charger de configuration

### Requirement: Chemin du fichier de configuration
Le système SHALL utiliser le chemin passé via `-c` ou `--config`, et `/etc/valerter/config.yaml` lorsque l'option est absente ; les répertoires `rules.d/`, `templates.d/` et `notifiers.d/` MUST être recherchés dans le répertoire parent de ce chemin.

#### Scenario: Chemin par défaut
- **WHEN** `valerter` est lancé sans `-c`
- **THEN** la configuration est lue depuis `/etc/valerter/config.yaml`

#### Scenario: Chemin personnalisé
- **WHEN** `valerter -c /custom/path.yaml` ou `valerter --config /custom/path.yaml` est lancé
- **THEN** la configuration est lue depuis `/custom/path.yaml`

### Requirement: Format des journaux
Le système SHALL écrire ses journaux sur la sortie d'erreur standard, au format texte lisible par défaut ou au format JSON (un objet par ligne, champs de l'événement aplatis) avec `--log-format json` ; la valeur MUST pouvoir venir de la variable d'environnement `LOG_FORMAT`, l'option explicite ayant priorité, et toute autre valeur que `text` ou `json` MUST être refusée.

#### Scenario: Format par défaut
- **WHEN** ni `--log-format` ni `LOG_FORMAT` ne sont fournis
- **THEN** les journaux sont émis au format texte

#### Scenario: Format depuis l'environnement
- **WHEN** `LOG_FORMAT=json` est défini et l'option n'est pas passée
- **THEN** les journaux sont émis au format JSON

#### Scenario: Option prioritaire
- **WHEN** `LOG_FORMAT=json` est défini et `--log-format text` est passé
- **THEN** les journaux sont émis au format texte

#### Scenario: Valeur invalide
- **WHEN** `--log-format invalid` est passé
- **THEN** l'analyse des arguments échoue et le processus se termine avec le code 2

### Requirement: Niveau de journalisation
Le système SHALL déterminer le filtre de journalisation à partir de la variable d'environnement `RUST_LOG` et MUST utiliser le niveau `info` lorsque `RUST_LOG` est absente ou invalide.

#### Scenario: Niveau par défaut
- **WHEN** `RUST_LOG` n'est pas définie
- **THEN** les messages de niveau `info` et supérieurs sont journalisés

#### Scenario: Niveau personnalisé
- **WHEN** `RUST_LOG=debug` est défini
- **THEN** les messages de niveau `debug` sont également journalisés

### Requirement: Échec de chargement
Le système SHALL, si la configuration ne peut pas être chargée, journaliser l'erreur avec le message `Failed to load configuration` (champs `error` et `path`) et MUST se terminer avec le code 1 sans tenter de validation, que le mode `--validate` soit actif ou non.

#### Scenario: Fichier absent
- **WHEN** `valerter -c /nonexistent.yaml` est lancé
- **THEN** l'erreur `Failed to load configuration` avec `error=failed to load config file: /nonexistent.yaml: ...` est journalisée et le code de sortie est 1

#### Scenario: Collision multi-fichiers
- **WHEN** la configuration contient une collision de noms entre `config.yaml` et un répertoire `.d/`
- **THEN** l'erreur `duplicate ... name ...` est journalisée sous `Failed to load configuration` et le code de sortie est 1

### Requirement: Échec de validation
Le système SHALL, si la validation échoue, journaliser chaque erreur avec le message `Configuration validation error`, puis un récapitulatif `Configuration validation failed` portant le champ `error_count`, et MUST se terminer avec le code 1, que le mode `--validate` soit actif ou non.

#### Scenario: Regex invalide
- **WHEN** `valerter --validate -c config_invalid_regex.yaml` est lancé
- **THEN** la sortie d'erreur mentionne la règle fautive et le code de sortie est 1

#### Scenario: Erreurs multiples
- **WHEN** la configuration comporte trois erreurs de validation
- **THEN** trois lignes `Configuration validation error` puis une ligne `Configuration validation failed` avec `error_count=3` sont journalisées

### Requirement: Mode validation
Le système SHALL, avec `--validate`, charger et valider la configuration, exécuter tous les contrôles bloquants du démarrage du démon puis, en cas de succès, afficher un récapitulatif sur la sortie standard et se terminer avec le code 0 sans démarrer le démon, sans démarrer le serveur de métriques ni effectuer d'appel réseau.

#### Scenario: Configuration valide
- **WHEN** `valerter --validate -c config.yaml` est lancé sur une configuration valide
- **THEN** la sortie standard contient, dans cet ordre, `Configuration is valid: <chemin>`, `  VictoriaLogs sources: <n> [<nom>=<url>, ...]` (sources triées par nom, URL après résolution des variables d'environnement puis masquage des parties sensibles), `  Rules: <total> (<activées> enabled)`, `  Templates: <n>`, `  Notifiers: <n> [<nom>=<type>, ...]` (notifiers triés par nom) et `  Metrics: enabled|disabled (port <port>)`
- **AND** le code de sortie est 0

#### Scenario: Exemples livrés
- **WHEN** `valerter --validate` est lancé sur `config/config.example.yaml` ou sur chaque `examples/<nom>/config.yaml` (avec les variables d'environnement factices requises)
- **THEN** le code de sortie est 0

#### Scenario: Aucun appel réseau
- **WHEN** `valerter --validate` est lancé sur une configuration valide dont les sources VictoriaLogs et les notifiers pointent vers des hôtes injoignables
- **THEN** la validation réussit avec le code 0 sans tentative de connexion vers ces hôtes

### Requirement: Parité des contrôles entre validation et démarrage
Le mode `--validate` SHALL exécuter les mêmes contrôles bloquants que le démarrage du démon, avec les mêmes messages d'erreur : construction de tous les notifiers (dont résolution de leurs variables d'environnement et lecture de `body_template_file`), existence des destinations des règles et présence d'`email_body_html` pour les destinations email. Toute configuration refusée au démarrage pour ces motifs MUST être refusée par `--validate` (code 1, sans récapitulatif).

#### Scenario: Destination inconnue détectée
- **WHEN** `valerter --validate` est lancé sur une configuration dont une règle `r` cible un notifier inexistant `nope`
- **THEN** l'erreur `rule 'r': unknown notifier 'nope'` est journalisée sous `Destination validation error`
- **AND** le code de sortie est 1 et la sortie standard ne contient pas `Configuration is valid`

#### Scenario: Variable de notifier indéfinie détectée
- **WHEN** `valerter --validate` est lancé sur une configuration dont le notifier `mattermost-ops` déclare `webhook_url: "${UNSET_VAR}"` et `UNSET_VAR` n'est pas définie
- **THEN** l'erreur `invalid notifier 'mattermost-ops': webhook_url: invalid configuration: undefined environment variable: UNSET_VAR` est journalisée sous `Notifier configuration error`
- **AND** le code de sortie est 1

#### Scenario: Fichier de corps e-mail absent
- **WHEN** `valerter --validate` est lancé sur une configuration dont un notifier email déclare un `body_template_file` inexistant
- **THEN** une erreur `Notifier configuration error` contenant `body_template_file not found` est journalisée et le code de sortie est 1

#### Scenario: Template e-mail sans corps HTML détecté
- **WHEN** `valerter --validate` est lancé sur une configuration dont une règle activée `r` envoie vers la destination email `email-ops` avec le template `t` dépourvu d'`email_body_html`
- **THEN** l'erreur `template 't' requires email_body_html field when used with email destination 'email-ops' (rule 'r')` est journalisée sous `Email template validation error`
- **AND** le code de sortie est 1

#### Scenario: Erreurs de plusieurs étapes rapportées ensemble
- **WHEN** une configuration combine un notifier dont une variable d'environnement est indéfinie et une règle ciblant un notifier inexistant
- **THEN** `--validate` comme le démarrage du démon journalisent les deux erreurs avant de se terminer avec le code 1
- **AND** une règle dont la destination désigne le notifier en échec n'est pas signalée comme ciblant un notifier inconnu

#### Scenario: Avertissement mattermost_channel
- **WHEN** `valerter --validate` est lancé sur une configuration valide dont une règle activée définit `notify.mattermost_channel` sans destination de type Mattermost
- **THEN** l'avertissement `mattermost_channel ignored - no mattermost notifier in destinations` est journalisé et le code de sortie reste 0

### Requirement: Masquage des URL de sources dans le récapitulatif
Le récapitulatif de `--validate` MUST NOT afficher les identifiants, la chaîne de requête ni le fragment d'une URL de source VictoriaLogs : les identifiants (`userinfo`) SHALL être remplacés par `***`, la chaîne de requête par `***` et le fragment supprimé. Une URL sans aucune de ces parties SHALL être affichée telle quelle.

#### Scenario: Identifiants et jeton dans l'URL
- **WHEN** une source `prod` déclare `url: "http://${VL_USER}:${VL_PASS}@vl.example.com:9428?token=${VL_TOKEN}"` avec ces variables définies
- **THEN** le récapitulatif affiche `prod=http://***@vl.example.com:9428/?***`
- **AND** ni les valeurs de `VL_USER`, `VL_PASS`, `VL_TOKEN` ni le texte `token=` n'apparaissent sur la sortie standard ou d'erreur

#### Scenario: URL sans partie sensible
- **WHEN** une source `default` déclare `url: "http://localhost:9428"`
- **THEN** le récapitulatif affiche `default=http://localhost:9428`
