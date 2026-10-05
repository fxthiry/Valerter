## MODIFIED Requirements

### Requirement: Réponse HTTP non-2xx
Le système SHALL traiter toute réponse dont le statut n'est pas 2xx comme un échec de tentative : il lit au plus les 4 premiers Kio du corps de la réponse pendant au plus 5 secondes (la lecture s'arrête sur la première de ces limites, en gardant ce qui a été reçu), le ramène sur une seule ligne (espaces consécutifs fusionnés), le tronque à 512 caractères suivis de `…` s'il est plus long (ou le remplace par `<empty body>` s'il est vide), journalise un avertissement `HTTP error from VictoriaLogs` avec le statut et ce corps, puis attend le délai de backoff avant de réessayer.

#### Scenario: Requête refusée par VictoriaLogs
- **WHEN** VictoriaLogs répond `400` avec le corps `unsupported pipe "stats" in /tail`
- **THEN** un avertissement est journalisé avec `status=400` et `response=unsupported pipe "stats" in /tail`
- **AND** une nouvelle tentative a lieu après le délai de backoff

#### Scenario: Erreur serveur sans corps
- **WHEN** VictoriaLogs répond `503` avec un corps vide
- **THEN** l'avertissement porte `response=<empty body>`

#### Scenario: Corps d'erreur sans fin
- **WHEN** un proxy répond `502` avec un corps en transfert `chunked` qui n'est jamais terminé
- **THEN** l'avertissement `HTTP error from VictoriaLogs` est journalisé au plus 5 secondes après la réception du statut, avec ce qui a été reçu du corps
- **AND** une nouvelle tentative a lieu après le délai de backoff, la tâche n'étant pas bloquée
