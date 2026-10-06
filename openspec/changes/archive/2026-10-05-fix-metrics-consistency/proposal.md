# Proposal

## Why

Les métriques Prometheus de valerter sont incohérentes à plusieurs endroits, ce qui rend les tableaux de bord et les
alertes trompeurs : les séries initialisées au démarrage n'ont pas les mêmes labels que celles réellement émises (des
séries fantômes restent à 0 pendant que les vraies n'apparaissent qu'au premier événement, ce qui casse `rate()` et
`increase()`), une métrique documentée n'est jamais observable, `email` et `telegram` ne comptent pas un succès partiel
de la même manière, certains échecs définitifs ne sont pas comptés et `valerter_reconnections_total` mélange
reconnexions sur échec et fins de flux normales. La doc `docs/metrics.md` est par ailleurs incomplète.

## What Changes

- **Initialisation alignée sur l'émission** : au démarrage, `valerter_alerts_sent_total`, `valerter_notify_errors_total`
  et `valerter_alerts_failed_total` sont initialisés pour chaque triplet (règle activée, source résolue, destination de
  la règle) avec les labels `rule_name`, `vl_source`, `notifier_name`, `notifier_type` ; `valerter_parse_errors_total`
  avec `error_type` (`invalid_json` toujours, `regex_no_match` pour les règles à parser regex) ;
  `valerter_lines_discarded_total` avec `reason="oversized"` et `reason="invalid_utf8"` ;
  `valerter_email_recipient_errors_total`, le nouveau `valerter_telegram_chat_errors_total` et
  `valerter_alerts_truncated_total` pour les destinations concernées.
- **BREAKING (métriques)** : suppression des séries d'initialisation à labels réduits
  `valerter_alerts_sent_total{rule_name, vl_source}`, `valerter_alerts_failed_total{notifier}` et
  `valerter_notify_errors_total{notifier}`, ainsi que de la série d'initialisation `valerter_parse_errors_total{rule_name, vl_source}`
  sans `error_type`.
- **BREAKING (métriques)** : suppression de `valerter_notifier_config_errors_total`, jamais observable (elle est
  incrémentée avant l'installation de l'exporteur et l'erreur interrompt le démarrage) ; les erreurs de configuration des
  notifiers restent signalées par les logs et le code de sortie 1.
- **Sémantique sent/failed unifiée par alerte et par notifier** : `telegram` s'aligne sur `email` — une alerte compte
  une seule fois en `valerter_alerts_sent_total` si au moins une discussion a réussi, et une seule fois en
  `valerter_notify_errors_total` + `valerter_alerts_failed_total` si toutes ont échoué ; les échecs par discussion sont
  comptés dans le nouveau compteur `valerter_telegram_chat_errors_total{rule_name, vl_source, notifier_name}`.
- **Échecs de rendu comptés** : un échec de rendu au moment de l'envoi (`body_template` webhook, sujet/corps email,
  texte Telegram) incrémente `valerter_notify_errors_total` et `valerter_alerts_failed_total`.
- **BREAKING (sémantique)** : `valerter_reconnections_total` ne compte plus que les tentatives de reconnexion après un
  échec ; une fin de flux propre (EOF sans erreur) est comptée dans le nouveau compteur
  `valerter_stream_ends_total{rule_name, vl_source}`, initialisé à 0. Cette inversion revient sur un choix délibéré de
  la 2.0.3, qui comptait l'EOF propre dans `valerter_reconnections_total` et avait été annoncée « no breaking
  changes » : elle est donc livrée en 2.1.0 avec une mention **BREAKING** explicite dans `CHANGELOG.md` et
  `MIGRATION.md`.
- **Documentation** : `docs/metrics.md` complété (`valerter_alerts_truncated_total`, `reason="invalid_utf8"`, nouveaux
  compteurs, sémantique par alerte, `notify_errors_total` décrit comme définitif et non transitoire, suppression de
  `valerter_notifier_config_errors_total`) ; `docs/notifiers.md` et `docs/architecture.md` alignés ; le commentaire de
  `MetricsServer` qui annonce un endpoint `/health` inexistant est corrigé.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `observability` : liste des compteurs du pipeline (sémantique de `valerter_reconnections_total`, ajout de
  `valerter_stream_ends_total`), compteurs de notification (sémantique par alerte, `valerter_telegram_chat_errors_total`,
  échecs de rendu), initialisation des séries au démarrage, métriques émises avant l'installation de l'exporteur.
- `notifier-telegram` : requirement « Résultat global et métriques par discussion » (comptage par alerte et compteur
  par discussion).
- `notifier-webhook` : requirement « Échec de rendu à l'envoi » (comptage de l'échec).
- `notifier-mattermost` : requirement « Résolution de webhook_url » (retrait de l'incrément de
  `valerter_notifier_config_errors_total`).
- `victorialogs-streaming` : requirement « Fin de flux propre avec backoff » (compteur dédié au lieu de
  `valerter_reconnections_total`).

## Impact

- Code : `src/metrics.rs` (`initialize_metrics` et sa signature, descriptions, commentaire `/health`), `src/main.rs`
  (construction de l'inventaire des séries à partir des règles et du registre), `src/notify/telegram.rs`,
  `src/notify/webhook.rs`, `src/notify/email.rs`, `src/notify/registry.rs`, `src/tail.rs`.
- Tests : `tests/metrics_snapshot.rs`, tests unitaires/wiremock des notifiers et du streaming.
- API publique de la crate : signature de `valerter::initialize_metrics` modifiée (utilisée par le binaire et les tests).
- Utilisateurs : requêtes PromQL et tableaux de bord qui utilisent le label `notifier`, `valerter_notifier_config_errors_total`,
  ou qui interprètent `valerter_reconnections_total` / les compteurs Telegram par discussion ; documenté dans
  `MIGRATION.md` et `CHANGELOG.md` (section 2.1.0).
- Hors périmètre : métrique `valerter_notify_errors_total{notifier_type="unknown"}` (destination absente du registre,
  capacité `notification-dispatch`), capacité de la file, labels de `valerter_alerts_truncated_total`.
