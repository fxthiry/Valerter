## MODIFIED Requirements

### Requirement: Compteurs du pipeline par règle et par source
Le démon SHALL exposer les compteurs suivants, chacun portant les labels `rule_name` et `vl_source` : `valerter_logs_matched_total` (lignes parsées avec succès, avant throttling), `valerter_alerts_passed_total` (alertes ayant passé le throttling), `valerter_alerts_throttled_total` (alertes bloquées par le throttling), `valerter_reconnections_total` (tentatives de reconnexion à VictoriaLogs après un échec : erreur de connexion, réponse HTTP d'erreur ou erreur en cours de flux), `valerter_stream_ends_total` (fins de flux propres, EOF sans erreur, suivies d'une reconnexion), `valerter_rule_panics_total` (panics de tâche) et `valerter_rule_errors_total` (erreurs fatales de tâche).

#### Scenario: Ligne parsée puis limitée
- **WHEN** une ligne de la règle `r` sur la source `s` est parsée puis bloquée par le throttling
- **THEN** `valerter_logs_matched_total{rule_name="r",vl_source="s"}` et `valerter_alerts_throttled_total{rule_name="r",vl_source="s"}` augmentent de 1

#### Scenario: Ancienne jauge par règle supprimée
- **WHEN** `/metrics` est scrapé
- **THEN** aucune série nommée `valerter_victorialogs_up` n'est présente

#### Scenario: Fin de flux propre distincte d'une reconnexion sur échec
- **WHEN** la connexion de la règle `r` sur la source `s` se termine une fois par un EOF propre, puis une fois par une erreur de connexion
- **THEN** `valerter_stream_ends_total{rule_name="r",vl_source="s"}` augmente de 1 pour l'EOF et `valerter_reconnections_total{rule_name="r",vl_source="s"}` augmente de 1 pour l'erreur

### Requirement: Compteurs de notification
Le démon SHALL exposer `valerter_alerts_sent_total`, `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec les labels `rule_name`, `vl_source`, `notifier_name` et `notifier_type` (`mattermost`, `webhook`, `email`, `telegram`, ou `unknown` pour une destination introuvable dans le registre), comptés une fois par alerte et par notifier ; `valerter_email_recipient_errors_total` et `valerter_telegram_chat_errors_total` avec les labels `rule_name`, `vl_source` et `notifier_name` ; et `valerter_alerts_truncated_total` avec les labels `notifier_type` et `notifier_name`. Tout échec définitif d'une alerte pour un notifier, y compris un échec de rendu de template au moment de l'envoi, MUST incrémenter `valerter_notify_errors_total` et `valerter_alerts_failed_total`.

#### Scenario: Envoi réussi
- **WHEN** une alerte de la règle `r` issue de la source `s` est envoyée avec succès par le notifier `ops` de type mattermost
- **THEN** `valerter_alerts_sent_total{rule_name="r",vl_source="s",notifier_name="ops",notifier_type="mattermost"}` augmente de 1

#### Scenario: Échec définitif
- **WHEN** l'envoi vers un notifier échoue définitivement après épuisement des tentatives
- **THEN** `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent de 1 avec les mêmes quatre labels

#### Scenario: Message tronqué
- **WHEN** un message Telegram est tronqué pour respecter la limite de longueur
- **THEN** `valerter_alerts_truncated_total{notifier_type="telegram", notifier_name}` augmente de 1

#### Scenario: Succès partiel compté une fois
- **WHEN** une alerte est livrée à au moins un destinataire d'un notifier email ou à au moins une discussion d'un notifier telegram, les autres échouant
- **THEN** `valerter_alerts_sent_total` augmente de 1 pour ce notifier, `valerter_alerts_failed_total` et `valerter_notify_errors_total` restent inchangés, et chaque cible en échec est comptée dans `valerter_email_recipient_errors_total` ou `valerter_telegram_chat_errors_total`

#### Scenario: Échec de rendu à l'envoi
- **WHEN** le rendu du `body_template` d'un webhook, du sujet ou du corps d'un email, ou du texte d'un message Telegram échoue au moment de l'envoi
- **THEN** `valerter_notify_errors_total` et `valerter_alerts_failed_total` augmentent de 1 avec les labels `rule_name`, `vl_source`, `notifier_name` et `notifier_type` du notifier concerné

### Requirement: Initialisation des séries au démarrage
Lorsque les métriques sont activées, le démon SHALL, avant de lancer les tâches de règles, initialiser à zéro chaque série avec exactement le jeu de labels sous lequel elle est émise : `valerter_build_info`, `valerter_uptime_seconds`, `valerter_queue_size`, `valerter_alerts_dropped_total`, `valerter_vl_source_up` pour chaque source déclarée ; pour chaque couple (règle activée, source résolue), `valerter_logs_matched_total`, `valerter_alerts_throttled_total`, `valerter_alerts_passed_total`, `valerter_rule_panics_total`, `valerter_rule_errors_total`, `valerter_reconnections_total`, `valerter_stream_ends_total`, `valerter_query_duration_seconds` et `valerter_last_query_timestamp` (labels `rule_name`, `vl_source`), `valerter_lines_discarded_total` (avec `reason="oversized"` et `reason="invalid_utf8"`) et `valerter_parse_errors_total` (avec `error_type="invalid_json"`, et `error_type="regex_no_match"` si la règle utilise un parser regex) ; pour chaque triplet (règle activée, source résolue, destination de la règle), `valerter_alerts_sent_total`, `valerter_notify_errors_total` et `valerter_alerts_failed_total` (labels `rule_name`, `vl_source`, `notifier_name`, `notifier_type`), ainsi que `valerter_email_recipient_errors_total` pour une destination email et `valerter_telegram_chat_errors_total` pour une destination telegram (labels `rule_name`, `vl_source`, `notifier_name`) ; et, pour chaque notifier telegram, `valerter_alerts_truncated_total{notifier_type="telegram", notifier_name}`. Aucune série portant un jeu de labels jamais utilisé à l'émission ne SHALL être créée.

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

### Requirement: Métriques émises avant l'installation de l'exporteur
Les métriques émises avant l'installation de l'exporteur Prometheus SHALL être perdues ; le démon MUST donc n'émettre aucune métrique pendant la création des notifiers, qui précède le démarrage du serveur de métriques, et les erreurs de configuration des notifiers (dont une variable d'environnement non définie) sont signalées uniquement par les logs et le code de sortie ; aucune métrique `valerter_notifier_config_errors_total` n'existe.

#### Scenario: Variable d'environnement manquante dans un notifier
- **WHEN** l'URL d'un notifier référence une variable d'environnement non définie
- **THEN** le démarrage échoue avec le code 1 avant l'ouverture du port de métriques, l'erreur est journalisée au niveau ERROR et aucune série `valerter_notifier_config_errors_total` n'est exposée

#### Scenario: Métrique absente en fonctionnement normal
- **WHEN** valerter démarre avec une configuration valide et `/metrics` est scrapé
- **THEN** aucune série ni texte d'aide `valerter_notifier_config_errors_total` n'est présent
