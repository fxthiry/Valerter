## MODIFIED Requirements

### Requirement: Erreurs SMTP permanentes sans relance
Le système MUST abandonner immédiatement, sans relance, l'envoi à un destinataire lorsque le serveur SMTP répond par un
code de réponse de classe 5xx (échec permanent, y compris `535` pour l'authentification), et SHALL renvoyer pour ce
destinataire l'erreur `permanent error for <destinataire>: <erreur>`. Une réponse de classe 4xx, une erreur réseau, TLS,
de délai ou toute erreur sans code de réponse MUST être traitée comme transitoire ; le texte du message d'erreur MUST NOT
intervenir dans cette classification.

#### Scenario: Échec d'authentification
- **WHEN** le serveur répond `535 5.7.8 authentication failed`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Boîte inexistante
- **WHEN** le serveur répond `550 mailbox unavailable`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Autre code permanent
- **WHEN** le serveur répond `503 bad sequence of commands`
- **THEN** une seule tentative est effectuée pour ce destinataire

#### Scenario: Réponse transitoire mentionnant l'authentification
- **WHEN** le serveur répond `454 4.7.0 temporary authentication failure`
- **THEN** l'erreur est traitée comme transitoire et relancée

#### Scenario: Code inclus dans un nombre plus long
- **WHEN** le serveur répond par un code 4xx dont le message contient `15501`
- **THEN** l'erreur est traitée comme transitoire et relancée

#### Scenario: Erreur réseau contenant un code
- **WHEN** la connexion échoue sans réponse SMTP avec un message contenant `550`
- **THEN** l'erreur est traitée comme transitoire et relancée
