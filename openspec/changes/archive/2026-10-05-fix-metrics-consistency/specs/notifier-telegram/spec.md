## MODIFIED Requirements

### Requirement: Résultat global et métriques par discussion
Le système SHALL considérer l'alerte comme livrée dès qu'au moins une discussion a réussi, en incrémentant une fois
`valerter_alerts_sent_total{rule_name, vl_source, notifier_name, notifier_type="telegram"}` quel que soit le nombre de
discussions réussies ; il SHALL incrémenter `valerter_telegram_chat_errors_total{rule_name, vl_source, notifier_name}`
pour chaque discussion en échec définitif ; si toutes les discussions échouent, il MUST incrémenter une fois
`valerter_notify_errors_total` et `valerter_alerts_failed_total` (mêmes libellés que `valerter_alerts_sent_total`) ;
le notifier MUST renvoyer un succès dès qu'au moins une discussion a réussi et l'erreur `all chat_ids failed` si toutes
ont échoué.

#### Scenario: Succès partiel
- **WHEN** sur deux discussions, l'une réussit et l'autre échoue
- **THEN** le notifier renvoie un succès, `valerter_alerts_sent_total` augmente de 1 et `valerter_telegram_chat_errors_total` augmente de 1
- **AND** `valerter_alerts_failed_total` et `valerter_notify_errors_total` restent inchangés

#### Scenario: Plusieurs discussions réussies
- **WHEN** une alerte est envoyée avec succès à trois discussions
- **THEN** `valerter_alerts_sent_total` augmente de 1, et non de 3

#### Scenario: Échec total
- **WHEN** les deux discussions échouent
- **THEN** le notifier renvoie l'erreur `all chat_ids failed`, `valerter_telegram_chat_errors_total` augmente de 2, et `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent chacun de 1
