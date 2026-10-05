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
Le système SHALL, avec `--validate`, charger et valider la configuration puis, en cas de succès, afficher un récapitulatif sur la sortie standard et se terminer avec le code 0 sans démarrer le démon, sans construire les notifiers ni effectuer d'appel réseau.

#### Scenario: Configuration valide
- **WHEN** `valerter --validate -c config.yaml` est lancé sur une configuration valide
- **THEN** la sortie standard contient, dans cet ordre, `Configuration is valid: <chemin>`, `  VictoriaLogs sources: <n> [<nom>=<url>, ...]` (sources triées par nom, URL après résolution des variables d'environnement), `  Rules: <total> (<activées> enabled)`, `  Templates: <n>` et `  Metrics: enabled|disabled (port <port>)`
- **AND** le code de sortie est 0

#### Scenario: Exemples livrés
- **WHEN** `valerter --validate` est lancé sur `config/config.example.yaml` ou sur chaque `examples/<nom>/config.yaml` (avec les variables d'environnement factices requises)
- **THEN** le code de sortie est 0

### Requirement: Périmètre limité du mode validation
Le mode `--validate` SHALL se limiter aux contrôles de chargement et de validation de la configuration et MUST NOT exécuter les contrôles réalisés à la construction des notifiers : résolution des variables d'environnement des notifiers, lecture de `body_template_file`, existence des destinations des règles parmi les notifiers et présence d'`email_body_html` pour les destinations email.

#### Scenario: Destination inconnue non détectée
- **WHEN** `valerter --validate` est lancé sur une configuration dont une règle cible un notifier inexistant
- **THEN** la validation réussit avec le code 0

#### Scenario: Variable de notifier indéfinie non détectée
- **WHEN** `valerter --validate` est lancé sur une configuration dont un notifier référence `${VAR}` non définie
- **THEN** la validation réussit avec le code 0

#### Scenario: Détection au démarrage réel
- **WHEN** la même configuration est lancée sans `--validate`
- **THEN** le démarrage échoue avec le code 1
