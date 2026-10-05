## MODIFIED Requirements

### Requirement: Construction du registre au démarrage avec collecte des erreurs
Le système SHALL instancier tous les notifiers au démarrage du démon comme en mode `--validate` (après la validation de la configuration), MUST collecter toutes les erreurs d'instanciation plutôt que s'arrêter à la première, journaliser chacune sous `Notifier configuration error`, puis refuser de démarrer avec l'erreur `Failed to create notifiers: <N> errors` ; l'instanciation MUST NOT effectuer d'appel réseau.

#### Scenario: Deux notifiers invalides
- **WHEN** deux notifiers référencent chacun une variable d'environnement non définie
- **THEN** deux erreurs `Notifier configuration error` sont journalisées
- **AND** le démon s'arrête en erreur avec `Failed to create notifiers: 2 errors` sans traiter aucune règle

#### Scenario: Mode validation
- **WHEN** le binaire est lancé avec `--validate` sur une configuration dont un notifier référence une variable d'environnement non définie
- **THEN** l'erreur est journalisée sous `Notifier configuration error` et le processus se termine avec le code 1 sans afficher de récapitulatif

#### Scenario: Instanciation sans réseau
- **WHEN** les notifiers sont instanciés (démarrage ou `--validate`) alors que leurs serveurs SMTP, webhooks ou API sont injoignables
- **THEN** l'instanciation réussit ; les erreurs de connexion n'apparaissent qu'à l'envoi d'une alerte
