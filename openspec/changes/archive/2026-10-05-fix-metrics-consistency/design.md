# Design

## Context

Voir proposal.md (Why). État constaté dans le code :

- `initialize_metrics(rule_source_pairs, source_names, notifier_names)` (`src/metrics.rs`) crée
  `valerter_alerts_sent_total{rule_name, vl_source}`, `valerter_parse_errors_total{rule_name, vl_source}`,
  `valerter_lines_discarded_total{…, reason="oversized"}` et des séries « sentinelles »
  `valerter_alerts_failed_total{notifier}` / `valerter_notify_errors_total{notifier}`, alors que les sites d'émission
  (notifiers, `src/parser.rs`, `src/tail.rs`) utilisent `{rule_name, vl_source, notifier_name, notifier_type}`,
  `{…, error_type}` et aussi `reason="invalid_utf8"`. Prometheus voit donc deux séries distinctes par compteur ;
  `tests/metrics_snapshot.rs` fige aujourd'hui ces jeux réduits.
- `valerter_notifier_config_errors_total` est incrémenté dans `NotifierRegistry::create_notifier` (Mattermost
  uniquement), donc avant `MetricsServer::run` (`src/main.rs` crée le registre avant d'installer l'exporteur), et
  l'erreur fait sortir le démon en code 1 : la série n'est jamais observable. Webhook, email et telegram résolvent
  aussi des `${VAR}` sans l'incrémenter. Sans description `describe_counter!`.
- `TelegramNotifier::send` compte sent/failed par discussion ; `EmailNotifier::send` compte une fois par alerte et
  dispose de `valerter_email_recipient_errors_total` pour le détail par destinataire.
- Les échecs de rendu (`render_body_template` du webhook, `render_subject`/`render_body` de l'email, `prepare_text` de
  Telegram) sortent par `?` sans aucun compteur ; le worker (`src/notify/queue.rs`) se contente de journaliser car il
  suppose que « les métriques sont déjà enregistrées par le notifier ».
- `src/tail.rs` incrémente `valerter_reconnections_total` dans `log_reconnection_attempt` (chemins d'échec) et aussi
  dans la branche « Stream ended, reconnecting » (EOF propre), choix fait en v2.0.3.
- Le commentaire de `MetricsServer` annonce un health check sur `/health` qui n'existe pas : l'écouteur HTTP de
  `metrics-exporter-prometheus` ne fait pas de routage.

## Goals / Non-Goals

**Goals:**
- Une seule série par combinaison de labels réellement émise, présente à 0 dès le démarrage.
- Une sémantique unique pour `alerts_sent` / `alerts_failed` / `notify_errors` : une fois par alerte et par notifier.
- Ne garder que des métriques observables.

**Non-Goals:**
- Pas d'endpoint `/health` (on corrige le commentaire, on n'ajoute pas de route).
- Pas de changement des labels de `valerter_alerts_truncated_total` ni de `valerter_queue_size`.
- Pas de traitement de `notifier_type="unknown"` (destination absente du registre, relève de `notification-dispatch`,
  modifié par `isolate-notifier-delivery`).
- Pas de modification du rythme de reconnexion ni des logs du streaming (relève de `harden-vl-streaming`).

## Decisions

### D1. Inventaire des séries construit dans `main.rs`, passé à `initialize_metrics`

`initialize_metrics` reçoit une structure d'inventaire (par exemple `MetricsInventory`) contenant : les sources
déclarées, les couples (règle, source) avec l'indication « parser regex », les triplets
(règle, source, `notifier_name`, `notifier_type`) issus de `rule.notify.destinations` résolus via le registre
(`Notifier::notifier_type()`), et la liste des notifiers telegram. `main.rs` la construit avec la même logique de
fan-out que le moteur (déjà présente pour `rule_source_pairs`).
- Alternative écartée : passer `&RuntimeConfig` + `&NotifierRegistry` à `initialize_metrics` — couple `metrics.rs`
  à la config et au registre et complique `tests/metrics_snapshot.rs`. La structure plate reste testable sans config.
- Alternative écartée : garder les séries sentinelles « pour les tableaux de bord » — elles sont justement la source
  de la confusion (valeurs toujours 0, agrégations doublées si on somme sans filtre).

### D2. Initialiser seulement les combinaisons possibles

- `parse_errors_total` : `invalid_json` pour toutes les règles (l'enveloppe VictoriaLogs est toujours parsée en JSON),
  `regex_no_match` seulement pour les règles à parser regex — sinon on exposerait des séries impossibles.
- Sent/failed/notify_errors : seulement pour les destinations des règles activées (un notifier inutilisé n'émet
  jamais). `email_recipient_errors_total` / `telegram_chat_errors_total` seulement pour les destinations du bon type.
- `alerts_truncated_total` : un par notifier telegram (labels sans règle ni source, comme l'émission).
- Le log « Metrics initialized to zero » garde ses trois champs ; `notifier_count` devient le nombre de notifiers du
  registre (inchangé).

### D3. Supprimer `valerter_notifier_config_errors_total`

La rendre « visible » demanderait d'installer l'exporteur avant de créer les notifiers ; mais l'erreur arrête le démon
en code 1 immédiatement, donc aucun scrape ne la verrait jamais. Un compteur toujours à 0 n'apporte rien. Les logs
ERROR « Notifier configuration error » et le code de sortie (exploitables par systemd) suffisent. On retire
l'incrément, la ligne de doc, et on garde la résolution `${VAR}` à l'identique.
- Alternative écartée : l'incrémenter dans tous les notifiers (cohérence) — même problème d'observabilité.

### D4. Telegram aligné sur email, compteur dédié par discussion

`valerter_alerts_sent_total` +1 si au moins une discussion réussit ; si toutes échouent, `notify_errors` et
`alerts_failed` +1 une fois ; chaque discussion en échec incrémente `valerter_telegram_chat_errors_total{rule_name,
vl_source, notifier_name}`, symétrique de `valerter_email_recipient_errors_total`.
- Alternative écartée : aligner email sur telegram (comptage par cible) — `alerts_sent_total` cesserait de compter des
  alertes et `rate(alerts_failed_total) > 0` (alerte d'exemple de `docs/metrics.md`) sonnerait sur un succès partiel.
- Alternative écartée : un compteur générique `valerter_notify_target_errors_total{…, notifier_type}` remplaçant le
  compteur email — renommage cassant d'une métrique existante, sans gain suffisant.

### D5. Échecs de rendu comptés dans le notifier

Chaque notifier qui rend un template à l'envoi capture l'erreur de rendu, incrémente `notify_errors_total` et
`alerts_failed_total` (une fois, labels habituels) puis renvoie la même erreur qu'aujourd'hui (messages inchangés).
Un petit helper partagé (par exemple dans `src/notify/mod.rs` ou `payload.rs`) `record_permanent_failure(alert,
notifier_name, notifier_type)` factorise les paires d'incréments déjà dupliquées dans les quatre notifiers.
- Alternative écartée : compter dans le worker sur toute erreur renvoyée — le worker ne distingue pas les erreurs
  déjà comptées et doublerait les compteurs.

### D6. `valerter_stream_ends_total` pour les EOF propres

La branche EOF de `src/tail.rs` incrémente `valerter_stream_ends_total{rule_name, vl_source}` au lieu de
`valerter_reconnections_total`. `valerter_reconnections_total` redevient « reconnexion après échec », ce qui le rend
exploitable pour alerter ; les EOF fréquents (proxy à délai d'inactivité) restent visibles via le nouveau compteur.
Ce choix revient sciemment sur la 2.0.3, qui avait décidé de compter l'EOF propre dans
`valerter_reconnections_total` (entrée « Clean stream end » du CHANGELOG 2.0.3) dans une version annoncée sans
rupture. Un tableau de bord ou une alerte construit depuis la 2.0.3 sur ce compteur verra donc ses valeurs baisser :
le changement est livré en 2.1.0 et signalé comme **BREAKING** dans `CHANGELOG.md` et dans la section « Upgrading to
2.1.0 » de `MIGRATION.md`, avec l'équivalence `valerter_reconnections_total + valerter_stream_ends_total` pour
retrouver l'ancien total.
- Alternative écartée : un label `reason` sur `valerter_reconnections_total` — change le jeu de labels de toutes les
  séries existantes (plus cassant) et mélange toujours deux phénomènes sous un même nom.

### D7. Commentaire `/health`

Le commentaire de `MetricsServer` est corrigé pour dire que seul `/metrics` est documenté. Hypothèse à vérifier pendant
l'implémentation : l'écouteur de `metrics-exporter-prometheus` 0.18 sert les métriques quel que soit le chemin ; on ne
l'écrit pas dans les specs (comportement de la bibliothèque).

## Risks / Trade-offs

- [Requêtes PromQL ou tableaux de bord utilisant le label `notifier`, `valerter_notifier_config_errors_total` ou
  `valerter_reconnections_total` pour compter les EOF] → section dédiée dans `MIGRATION.md` avec équivalences
  (`sum by (notifier_name)`, `valerter_stream_ends_total`), entrée **Changed/Removed** dans `CHANGELOG.md`.
- [Telegram : `alerts_sent_total` baisse pour les notifiers multi-discussions] → documenté ; le détail par discussion
  reste disponible via `valerter_telegram_chat_errors_total`.
- [Cardinalité : un triplet par (règle, source, destination)] → identique à ce que l'émission crée déjà au premier
  événement ; on ne fait que l'anticiper.
- [Signature publique de `initialize_metrics` modifiée] → la crate n'est consommée que par son binaire et ses tests ;
  mention dans le CHANGELOG.
- [Chevauchement de fichiers avec `harden-vl-streaming` (`src/tail.rs`, même requirement « Fin de flux propre avec
  backoff ») et `harden-notifier-payloads` (mêmes fichiers de notifiers)] → implémentation séquentielle : ce change
  s'implémente après ces deux changes, sur leur code déjà fusionné. Sa version du requirement « Fin de flux propre
  avec backoff » reprend le backoff de première fin de flux vide introduit par `harden-vl-streaming` ; la modification
  ici est limitée à l'appel de compteur.
- [Utilisateurs qui ont adopté la sémantique 2.0.3 de `valerter_reconnections_total`] → mention **BREAKING**
  explicite en 2.1.0 (voir D6).

## Migration Plan

Livraison en 2.1.0, déploiement normal (paquet .deb). Pas de migration de configuration. Les utilisateurs mettent à jour leurs requêtes
selon `MIGRATION.md`. Retour arrière : réinstaller la version précédente, les anciennes séries réapparaissent.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`  ← ce change
11. `apply-notifier-overrides`

Pour ce change (10/11) : suit `harden-vl-streaming` et `harden-notifier-payloads`.
