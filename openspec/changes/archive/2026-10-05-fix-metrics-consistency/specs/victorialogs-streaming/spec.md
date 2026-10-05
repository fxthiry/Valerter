## MODIFIED Requirements

### Requirement: Fin de flux propre avec backoff
Le système SHALL, lorsque le serveur termine proprement la réponse (EOF sans erreur), rouvrir une connexion sans considérer cet événement comme un échec, après un délai calculé avec la même formule de backoff et de gigue : environ 1 s si au moins un fragment de données a été reçu sur cette connexion, et sinon un délai croissant avec le nombre de fins de flux vides consécutives (environ 1 s pour la première, puis 2 s, 4 s, 8 s… jusqu'à 60 s), ce compteur revenant à zéro dès qu'une connexion reçoit des données. Chaque fin de flux propre MUST incrémenter `valerter_stream_ends_total{rule_name, vl_source}`, MUST NOT incrémenter `valerter_reconnections_total` (réservé aux reconnexions après échec) et MUST être journalisée en debug (`Stream ended, reconnecting`).

#### Scenario: Serveur fermant immédiatement le flux
- **WHEN** VictoriaLogs (ou un proxy) répond 200 avec un corps vide puis ferme la connexion, de façon répétée
- **THEN** les reconnexions sont espacées d'environ 1 s, 2 s, 4 s, 8 s…, sans boucle serrée (au plus 3 requêtes en 1,2 s)

#### Scenario: Fin de flux après réception de données
- **WHEN** le serveur envoie des lignes puis ferme proprement la connexion
- **THEN** une nouvelle connexion est ouverte après environ 1 s (±10 %)

#### Scenario: Données après des fins de flux vides
- **WHEN** trois fins de flux vides consécutives sont suivies d'une connexion qui reçoit des données puis se termine proprement, à nouveau vide la fois suivante
- **THEN** le délai après la connexion avec données est d'environ 1 s et celui après la fin de flux vide suivante est aussi d'environ 1 s

#### Scenario: Comptage d'une fin de flux propre
- **WHEN** le serveur ferme proprement la connexion de la règle `r` sur la source `s` sans aucune erreur de connexion ni de flux
- **THEN** `valerter_stream_ends_total{rule_name="r",vl_source="s"}` augmente de 1
- **AND** `valerter_reconnections_total{rule_name="r",vl_source="s"}` reste inchangé
