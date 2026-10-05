# Proposal

## Why

Aujourd'hui toutes les alertes passent par une file unique consommée par un worker unique qui traite les alertes une par une : l'alerte suivante n'est prise qu'une fois terminés tous les envois (retries compris) de l'alerte courante (`src/notify/queue.rs`, `NotificationWorker::run` → `process_alert(...).await`). Un seul endpoint muet bloque donc **toutes** les destinations : pour un notifier HTTP (Mattermost, webhook, Telegram), 3 tentatives × 10 s de timeout + 0,5 s + 1 s de backoff ≈ 31,5 s par alerte ; Telegram peut attendre jusqu'à 60 s par `retry_after` sur un 429, et l'e-mail enchaîne destinataire par destinataire avec le timeout SMTP de lettre. Pendant ce temps la file (annoncée à 100) se remplit, puis écrase des alertes destinées à des canaux parfaitement sains. De plus, la capacité annoncée (100, `DEFAULT_QUEUE_CAPACITY`) n'est pas la capacité réelle : `tokio::sync::broadcast::channel` l'arrondit à la puissance de deux supérieure, soit 128. Enfin, une panique dans un notifier tue le worker unique et arrête silencieusement toute livraison.

## What Changes

- Remplacement du worker unique séquentiel par **une file et un worker de livraison par destination** (un par notifier du registre) : chaque destination consomme sa propre file dans l'ordre FIFO, indépendamment des autres. Un endpoint lent ou indisponible ne retarde plus que ses propres alertes.
- La mise en file (`NotificationQueue::send`) devient un routage : l'alerte est déposée, sans jamais bloquer le producteur, dans la file de chacune de ses destinations ; une destination inconnue du registre est détectée à ce moment-là (même log et même métrique qu'aujourd'hui).
- Capacité **exacte** de 100 alertes **par destination** (plus d'arrondi silencieux à 128) ; la politique drop-oldest s'applique par destination : une destination saturée ne fait perdre des alertes qu'à elle-même.
- Métriques : `valerter_queue_size` et `valerter_alerts_dropped_total` restent sans label et deviennent l'agrégat de toutes les files de destination (livraisons en attente / livraisons abandonnées) ; ajout de `valerter_destination_queue_size` et `valerter_destination_alerts_dropped_total` avec les labels `notifier_name` et `notifier_type`. Le log `Queue full, dropping <N> oldest alerts` gagne le champ `notifier`. Les sélecteurs PromQL existants restent valides, mais **le sens des seuils absolus change** : `valerter_queue_size` étant désormais une somme, elle peut atteindre 100 × N destinations (contre 128 au plus aujourd'hui), si bien qu'une alerte comme `valerter_queue_size > 50` ne signifie plus « file à moitié pleine » ; il est recommandé de la réécrire sur `valerter_destination_queue_size` (par exemple `max(valerter_destination_queue_size) > 50`).
- Une panique pendant l'envoi vers une destination est interceptée : elle est journalisée et comptée comme un échec de livraison, et le worker de cette destination continue avec l'alerte suivante.
- Changement de comportement visible (non cassant pour la configuration) : l'ordre FIFO n'est plus garanti globalement mais par destination ; une alerte envoyée à deux destinations compte pour deux livraisons dans les métriques de file, et les seuils absolus posés sur `valerter_queue_size` sont à revoir. Documenté dans CHANGELOG.md et MIGRATION.md (version 2.1.0).
- Hors périmètre : comportement à l'arrêt (vidage de la file, géré par `drain-notification-queue-on-shutdown`) ; capacité ou concurrence configurables ; parallélisation des destinataires à l'intérieur d'un même notifier e-mail ou Telegram.

## Capabilities

### New Capabilities

_Aucune._

### Modified Capabilities

- `notification-dispatch` : la file unique et le worker unique séquentiel sont remplacés par une file et un worker par destination ; capacité exacte par destination ; drop-oldest, jauge de file, fan-out et détection des destinations inconnues reformulés en conséquence ; interception des paniques de notifier.
- `observability` : le requirement « Métriques de la file de notifications » décrit désormais l'agrégat des files de destination et les nouvelles séries par destination.

## Impact

- Code : `src/notify/queue.rs` (réécriture : file par destination à capacité exacte, routage, workers), `src/notify/mod.rs` et `src/lib.rs` (exports), `src/main.rs` (création de la file après le registre, lancement et attente de plusieurs workers), `src/engine.rs` (tests construisant la file), `src/metrics.rs` (description et initialisation des nouvelles séries).
- Tests : `src/notify/tests.rs`, `tests/integration_notify.rs`, `tests/multi_source_integration.rs`, `tests/metrics_snapshot.rs` (API de construction de la file modifiée, nouveaux tests d'isolation avec wiremock). La migration des tests qui observent les alertes via `queue.subscribe()` représente l'essentiel du coût du change.
- Supervision des opérateurs : les règles d'alerte PromQL à seuil absolu sur `valerter_queue_size` changent de sens et sont à réécrire sur `valerter_destination_queue_size`.
- Docs : `docs/architecture.md`, `docs/metrics.md`, `docs/performance.md`, `CHANGELOG.md`, `MIGRATION.md`.
- Aucune nouvelle dépendance (tokio `Notify` + `std::sync::Mutex<VecDeque>` ; `futures_util::FutureExt::catch_unwind` déjà disponible via `futures-util`).
- Aucune modification de format de configuration.
