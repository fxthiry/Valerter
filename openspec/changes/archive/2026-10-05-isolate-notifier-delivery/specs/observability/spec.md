# Spec Delta

## MODIFIED Requirements

### Requirement: Métriques de la file de notifications
Le démon SHALL exposer la jauge `valerter_queue_size` (nombre total d'alertes en attente dans l'ensemble des files de destination, sans label), le compteur global `valerter_alerts_dropped_total` (sans label), incrémenté de chaque alerte la plus ancienne écrasée lorsque la file d'une destination, de capacité 100, déborde, ainsi que leurs déclinaisons par destination `valerter_destination_queue_size` et `valerter_destination_alerts_dropped_total` (labels `notifier_name`, `notifier_type`), initialisées à zéro pour chaque notifier lorsque les métriques sont activées.

#### Scenario: Débordement de la file
- **WHEN** le worker d'une destination constate que N alertes de sa file ont été écrasées faute de place
- **THEN** `valerter_alerts_dropped_total` et `valerter_destination_alerts_dropped_total` de cette destination ont augmenté de N et un log WARN « Queue full, dropping N oldest alerts » est émis avec les champs `dropped_count` et `notifier`

#### Scenario: Séries par destination au démarrage
- **WHEN** le démon démarre avec les métriques activées et les notifiers `mm-ops` (mattermost) et `mail-oncall` (email)
- **THEN** `valerter_destination_queue_size` et `valerter_destination_alerts_dropped_total` sont exposées à 0 pour `notifier_name="mm-ops",notifier_type="mattermost"` et pour `notifier_name="mail-oncall",notifier_type="email"`
