## MODIFIED Requirements

### Requirement: Échec de rendu à l'envoi
Le système MUST, si le rendu du `body_template` échoue au moment de l'envoi, abandonner l'alerte pour ce notifier sans émettre de requête ni de retry, avec l'erreur `failed to send notification: template render error: <détail>`, et MUST compter cet échec définitif en incrémentant une fois `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec les labels `rule_name`, `vl_source`, `notifier_name` et `notifier_type="webhook"`.

#### Scenario: Erreur de rendu
- **WHEN** le rendu du template échoue pour une alerte
- **THEN** aucune requête HTTP n'est émise et l'échec est journalisé par le worker

#### Scenario: Erreur de rendu comptée
- **WHEN** le rendu du `body_template` du notifier `hook` échoue pour une alerte de la règle `r` issue de la source `s`
- **THEN** `valerter_notify_errors_total{rule_name="r",vl_source="s",notifier_name="hook",notifier_type="webhook"}` et `valerter_alerts_failed_total` avec les mêmes labels augmentent chacun de 1
- **AND** `valerter_alerts_sent_total` reste inchangé
