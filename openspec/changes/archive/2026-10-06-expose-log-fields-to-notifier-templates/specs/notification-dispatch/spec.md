## MODIFIED Requirements

### Requirement: Contenu du payload d'alerte
Le système SHALL transmettre à chaque notifier, pour chaque alerte, le message rendu (`title`, `body`, `email_body_html` optionnel, `accent_color` optionnel), le nom de la règle, le nom de la source VictoriaLogs (`vl_source`), la liste des destinations de la règle, le canal Mattermost optionnel de la règle (`notify.mattermost_channel`), l'horodatage brut du log (`log_timestamp`, champ `_time` de l'événement), sa version lisible (`log_timestamp_formatted`, format `DD/MM/YYYY HH:MM:SS TZ` dans le fuseau `timestamp_timezone`, secondes tronquées) et les champs de l'événement parsé (vue dépliée, identique au contexte du template de règle, sans `rule_name` ni `vl_source` injectés), partagés entre toutes les destinations de l'alerte sans copie par destination.

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

#### Scenario: Champs de l'événement transmis
- **WHEN** une règle produit une alerte pour l'événement `{"host": "web-01", "nginx.status": "502", "_msg": "upstream error"}`
- **THEN** le payload transporte les champs `host`, `nginx.status`, `nginx` (objet contenant `status`) et `_msg` de cet événement

#### Scenario: Champs transmis malgré un repli de rendu
- **WHEN** le rendu du template de la règle échoue et que le message de repli est utilisé
- **THEN** le payload transporte quand même les champs de l'événement, que seuls les templates de notifier peuvent afficher

## ADDED Requirements

### Requirement: Champs du log jamais journalisés
Le système MUST NOT écrire dans ses logs les champs de l'événement transportés par le payload d'alerte : la représentation de débogage du payload n'en expose que le nombre, et aucun log de la file, des workers ou des notifiers ne contient leurs valeurs.

#### Scenario: Débogage du payload
- **WHEN** un payload dont l'événement contient `password=hunter2` est formaté pour le débogage
- **THEN** la sortie contient le nombre de champs mais pas `hunter2`

#### Scenario: Échec d'envoi journalisé
- **WHEN** l'envoi d'une alerte dont l'événement contient `token=s3cr3t` échoue définitivement
- **THEN** le log `Failed to send notification after all retries` ne contient pas `s3cr3t`
