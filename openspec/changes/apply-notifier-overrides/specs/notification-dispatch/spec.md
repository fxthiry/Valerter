## MODIFIED Requirements

### Requirement: Contenu du payload d'alerte
Le système SHALL transmettre à chaque notifier, pour chaque alerte, le message rendu (`title`, `body`, `email_body_html` optionnel, `accent_color` optionnel), le nom de la règle, le nom de la source VictoriaLogs (`vl_source`), la liste des destinations de la règle, le canal Mattermost optionnel de la règle (`notify.mattermost_channel`), l'horodatage brut du log (`log_timestamp`, champ `_time` de l'événement) et sa version lisible (`log_timestamp_formatted`, format `DD/MM/YYYY HH:MM:SS TZ` dans le fuseau `timestamp_timezone`, secondes tronquées).

#### Scenario: Horodatage formaté
- **WHEN** l'événement a `_time = 2026-01-15T10:00:00Z` et `timestamp_timezone: Europe/Paris`
- **THEN** `log_timestamp` vaut `2026-01-15T10:00:00Z` et `log_timestamp_formatted` vaut `15/01/2026 11:00:00 CET`

#### Scenario: Champ _time absent
- **WHEN** l'événement ne contient pas de champ `_time`
- **THEN** un avertissement `Missing _time field in log, using current time` est journalisé et l'heure courante RFC 3339 est utilisée comme `log_timestamp`

#### Scenario: Horodatage non analysable
- **WHEN** `_time` n'est pas un horodatage RFC 3339 valide
- **THEN** `log_timestamp_formatted` reprend la valeur brute inchangée

#### Scenario: Canal Mattermost de la règle transmis
- **WHEN** une règle définit `notify.mattermost_channel: alerts`
- **THEN** chaque alerte de cette règle transporte le canal `alerts`, et une règle sans cette clé transporte un canal absent
