## MODIFIED Requirements

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

## ADDED Requirements

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

## REMOVED Requirements

### Requirement: Périmètre limité du mode validation
**Reason**: Le mode `--validate` exécute désormais tous les contrôles bloquants du démarrage (voir « Parité des contrôles entre validation et démarrage ») ; l'ancien périmètre laissait passer des configurations refusées au démarrage réel.
**Migration**: Définir, au moment de lancer `--validate` (y compris en CI), toutes les variables d'environnement référencées par les notifiers et rendre accessibles les fichiers `body_template_file` ; corriger les destinations inconnues et les templates e-mail sans `email_body_html` que `--validate` signale désormais.
