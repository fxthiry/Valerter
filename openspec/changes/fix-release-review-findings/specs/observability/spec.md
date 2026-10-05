## MODIFIED Requirements

### Requirement: Joignabilité des sources avec anti-rebond
La jauge `valerter_vl_source_up{vl_source}` SHALL valoir 0 au démarrage pour chaque source ciblée par au moins une règle activée, passer à 1 dès qu'une connexion réussit vers cette source, et ne repasser à 0 qu'après 3 échecs consécutifs (erreur de connexion, réponse HTTP d'erreur ou erreur en cours de flux) observés par une même tâche, cette valeur n'étant pas configurable ; une fin de flux propre n'est pas un échec. Une source déclarée qu'aucune règle activée ne cible MUST NOT avoir de série `valerter_vl_source_up`.

#### Scenario: Source jamais joignable
- **WHEN** une source ciblée par une règle activée n'a encore accepté aucune connexion
- **THEN** `valerter_vl_source_up{vl_source="<source>"}` vaut 0

#### Scenario: Échec transitoire
- **WHEN** une tâche connectée subit 1 ou 2 échecs consécutifs puis se reconnecte
- **THEN** `valerter_vl_source_up` reste à 1

#### Scenario: Panne durable
- **WHEN** une tâche subit 3 échecs consécutifs vers sa source
- **THEN** `valerter_vl_source_up` pour cette source passe à 0

#### Scenario: Source déclarée mais non ciblée
- **WHEN** la source `vlarchive` est déclarée et qu'aucune règle activée ne la cible (toutes les règles activées ont un `vl_sources` qui ne la contient pas)
- **THEN** `/metrics` ne contient aucune série `valerter_vl_source_up{vl_source="vlarchive"}`

### Requirement: Initialisation des séries au démarrage
Lorsque les métriques sont activées, le démon SHALL, avant de lancer les tâches de règles, initialiser à zéro chaque série avec exactement le jeu de labels sous lequel elle est émise : `valerter_build_info`, `valerter_uptime_seconds`, `valerter_queue_size`, `valerter_alerts_dropped_total`, `valerter_vl_source_up` pour chaque source ciblée par au moins une règle activée ; pour chaque couple (règle activée, source résolue), `valerter_logs_matched_total`, `valerter_alerts_throttled_total`, `valerter_alerts_passed_total`, `valerter_rule_panics_total`, `valerter_rule_errors_total`, `valerter_reconnections_total`, `valerter_stream_ends_total`, `valerter_query_duration_seconds` et `valerter_last_query_timestamp` (labels `rule_name`, `vl_source`), `valerter_lines_discarded_total` (avec `reason="oversized"` et `reason="invalid_utf8"`) et `valerter_parse_errors_total` (avec `error_type="invalid_json"`, et `error_type="regex_no_match"` si la règle utilise un parser regex) ; pour chaque triplet (règle activée, source résolue, destination de la règle), `valerter_alerts_sent_total`, `valerter_notify_errors_total` et `valerter_alerts_failed_total` (labels `rule_name`, `vl_source`, `notifier_name`, `notifier_type`), ainsi que `valerter_email_recipient_errors_total` pour une destination email et `valerter_telegram_chat_errors_total` pour une destination telegram (labels `rule_name`, `vl_source`, `notifier_name`) ; et, pour chaque notifier telegram, `valerter_alerts_truncated_total{notifier_type="telegram", notifier_name}`. Aucune série portant un jeu de labels jamais utilisé à l'émission ne SHALL être créée.

#### Scenario: Séries visibles avant tout événement
- **WHEN** valerter démarre avec une règle activée sur deux sources et une destination, puis `/metrics` est scrapé avant tout événement
- **THEN** les séries listées ci-dessus sont présentes pour chacun des deux couples (règle, source) et pour chaque triplet (règle, source, destination) avec la valeur 0
- **AND** le log « Metrics initialized to zero » est émis avec `rule_source_pair_count`, `source_count` et `notifier_count`

#### Scenario: Jeux de labels distincts entre initialisation et émission
- **WHEN** une alerte de la règle `r` issue de la source `s` est envoyée avec succès par la destination `ops` de type mattermost après le démarrage
- **THEN** la série initialisée `valerter_alerts_sent_total{rule_name="r",vl_source="s",notifier_name="ops",notifier_type="mattermost"}` passe de 0 à 1
- **AND** aucune autre série `valerter_alerts_sent_total` n'existe pour la règle `r` et la source `s`

#### Scenario: Plus de séries à labels réduits
- **WHEN** `/metrics` est scrapé après le démarrage
- **THEN** aucune série `valerter_alerts_sent_total{rule_name, vl_source}` sans `notifier_name`, `valerter_alerts_failed_total{notifier}`, `valerter_notify_errors_total{notifier}` ni `valerter_parse_errors_total` sans `error_type` n'est présente

#### Scenario: Notifier non utilisé par une règle activée
- **WHEN** un notifier est déclaré mais n'est la destination d'aucune règle activée
- **THEN** aucune série `valerter_alerts_sent_total`, `valerter_notify_errors_total` ou `valerter_alerts_failed_total` n'est initialisée pour ce notifier

#### Scenario: Source non ciblée par une règle activée
- **WHEN** une source est déclarée mais n'est ciblée par aucune règle activée
- **THEN** aucune série `valerter_vl_source_up` n'est initialisée pour cette source et `source_count` ne la compte pas

### Requirement: Non-fuite des secrets dans les logs
Le démon MUST ne jamais écrire dans ses logs la valeur des secrets de configuration : les valeurs protégées (mot de passe `basic_auth`, valeurs des `headers` des sources VictoriaLogs, URL de webhook et autres champs secrets des notifiers) s'affichent `[REDACTED]` dans toute représentation de débogage ou d'affichage, la représentation de débogage des notifiers n'expose ni URL, ni en-têtes, ni jeton, ni identifiants de chat, et les erreurs HTTP des notifiers Mattermost, webhook et Telegram sont journalisées sans l'URL appelée. L'URL d'une source VictoriaLogs (qui peut contenir des identifiants ou un jeton issus de `${VAR}`) MUST n'apparaître dans les logs du streaming que masquée (identifiants et chaîne de requête remplacés par `***`, fragment retiré), et les erreurs de transport du streaming MUST être journalisées sans l'URL appelée.

#### Scenario: Représentation d'une configuration avec secrets
- **WHEN** une configuration contenant un mot de passe `basic_auth` et des en-têtes secrets est formatée pour le débogage
- **THEN** le résultat contient `[REDACTED]` à la place de chaque valeur secrète et ne contient aucune de ces valeurs

#### Scenario: Erreur réseau vers un webhook
- **WHEN** l'envoi vers un webhook Mattermost ou générique échoue sur une erreur de transport
- **THEN** le log d'erreur contient la cause de l'erreur mais pas l'URL du webhook

#### Scenario: Erreur réseau vers Telegram
- **WHEN** l'envoi vers l'API Telegram échoue sur une erreur de transport
- **THEN** le log d'erreur ne contient pas l'URL de l'API, qui inclut le jeton du bot

#### Scenario: URL de source avec secrets
- **WHEN** une source déclare `url: "http://user:${VL_PASS}@vl.example.com:9428/?token=${VL_TOKEN}"`, que `RUST_LOG=debug` est défini et que la connexion échoue
- **THEN** ni la valeur de `VL_PASS` ni celle de `VL_TOKEN` n'apparaissent dans les logs (`Connecting to VictoriaLogs tail endpoint`, `Connection failed`, `Stream read error`), qui contiennent l'URL masquée et la cause de l'erreur
