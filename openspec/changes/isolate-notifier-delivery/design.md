# Design

## Context

Voir proposal.md (Why) pour la motivation. État actuel du code, vérifié :

- `NotificationQueue` (`src/notify/queue.rs`) enveloppe un `tokio::sync::broadcast::Sender<AlertPayload>` créé avec `DEFAULT_QUEUE_CAPACITY = 100` ; `broadcast::channel` arrondit la capacité à la puissance de deux supérieure (128 emplacements effectifs). Le drop-oldest est natif (`RecvError::Lagged(n)`), `send` échoue (`QueueError::Closed`) s'il n'y a aucun receveur.
- `NotificationWorker::run` est une boucle unique : `recv()` → `process_alert(payload).await`, qui fait un `join_all` sur les destinations de l'alerte. Le fan-out est parallèle à l'intérieur d'une alerte, mais les alertes sont strictement sérialisées : la plus lente des destinations fixe le débit de toute la file.
- Retries (dans chaque notifier) : HTTP 3 tentatives, timeout 10 s (client partagé dans `main.rs`, et timeout explicite côté Telegram), backoff 500 ms → 5 s, soit ≈ 31,5 s pour un endpoint muet ; Telegram honore `retry_after` jusqu'à 60 s ; e-mail 3 tentatives par destinataire avec backoff 1 s → 30 s.
- `main.rs` crée la file **avant** le registre, lance un seul `tokio::spawn(worker.run(cancel))` et l'attend au plus 5 s à l'arrêt.
- Une panique dans `notifier.send` fait mourir la tâche du worker ; le receveur est alors libéré et toutes les mises en file suivantes échouent avec `notification queue closed`.
- Les tests d'intégration du moteur (`tests/multi_source_integration.rs`, `tests/metrics_snapshot.rs`) utilisent `queue.subscribe()` comme « robinet » pour observer les alertes produites.

## Goals / Non-Goals

**Goals:**

- Qu'une destination lente, indisponible, saturée ou qui panique n'affecte ni le délai ni les pertes des autres destinations.
- Conserver l'ordre d'arrivée des alertes pour une destination donnée (lisibilité dans un canal Mattermost ou Telegram).
- Une capacité de file réellement égale à la valeur documentée.
- Garder l'API producteur (`NotificationQueue::send`, non bloquante, `Clone`) inchangée pour le moteur.

**Non-Goals:**

- Comportement à l'arrêt : on conserve le comportement actuel (arrêt dès que chaque worker n'a plus d'envoi en cours, attente globale bornée à 5 s). Le vidage est l'objet de `drain-notification-queue-on-shutdown`.
- Concurrence > 1 au sein d'une même destination, capacité ou concurrence configurables.
- Parallélisation des destinataires e-mail ou des `chat_ids` Telegram à l'intérieur d'un notifier.
- Retouche des politiques de retry propres à chaque notifier.

## Decisions

### D1. Une file et un worker par destination (plutôt qu'un pool de workers sur la file unique)

Le `NotificationQueue` devient un routeur : une table `notifier_name → DestinationQueue` construite à partir du registre. `send(payload)` parcourt `payload.destinations` et pousse une copie dans la file de chaque destination connue. Un worker par destination consomme sa file séquentiellement.

Alternatives écartées :

- *Traitement concurrent borné (sémaphore de N alertes en vol) sur la file unique* : simple, mais n'isole pas. Si un endpoint est mort et que la plupart des alertes le ciblent, les N emplacements se remplissent d'envois de ≈ 31,5 s et les autres destinations retombent dans le même blocage ; l'ordre par destination est en plus perdu.
- *Dispatcher central + files par destination* (file d'entrée unique, une tâche qui relaie vers les files de destination) : ajoute un saut, une deuxième capacité à dimensionner et un deuxième point de perte, sans bénéfice puisque le routage est trivial et synchrone.
- *Concurrence par destination > 1* : casserait l'ordre au sein d'un canal ; le débit nominal d'un endpoint sain (quelques dizaines de ms par requête) est largement suffisant face au throttling en amont.

### D2. File de destination à capacité exacte : `Mutex<VecDeque>` + `tokio::sync::Notify`

Chaque `DestinationQueue` contient un `std::sync::Mutex<State>` (`VecDeque<Arc<AlertPayload>>`, compteur d'abandons non encore journalisés, drapeau `closed`) et un `Notify`. `push` verrouille brièvement (aucun `.await` sous le verrou), fait `pop_front` si la longueur atteint la capacité (abandon comptabilisé immédiatement dans les compteurs Prometheus), `push_back`, puis `notify_one()`. Le worker attend `notified()` ou l'annulation, puis dépile.

Alternatives écartées : `broadcast` par destination (garde l'arrondi à 128 et l'API `Lagged`, un seul consommateur suffit) ; `mpsc` borné (pas de drop-oldest : `try_send` sur file pleine abandonne la **nouvelle** alerte, contraire au contrat) ; crate externe de ring buffer (dépendance superflue pour ~60 lignes).

`DEFAULT_QUEUE_CAPACITY` reste à 100 et devient la capacité **par destination**. Le payload est partagé via `Arc<AlertPayload>` pour éviter de copier les chaînes N fois ; `Notifier::send(&AlertPayload)` est inchangé (`&*arc`).

### D3. Cycle de vie et API

- `NotificationQueue::new(capacity, registry: &NotifierRegistry)` crée une file par notifier (nom et type mémorisés pour les labels). `main.rs` crée donc la file **après** le registre (l'ordre de démarrage décrit dans `rule-engine` doit être mis à jour, voir Risks).
- `NotificationWorker::new(&queue, registry)` et `NotificationWorker::run(cancel)` sont conservés : `run` lance une tâche par destination dans un `JoinSet` et rend la main quand toutes sont terminées. `main.rs` garde donc un seul `worker_handle` et l'attente de 5 s couvre l'ensemble des workers.
- Fermeture : à la sortie de `run` (annulation), toutes les files sont marquées `closed` ; `send` renvoie alors `QueueError::Closed`. Une file créée sans worker démarré accepte les alertes (elles restent en attente) : c'est un changement par rapport au `broadcast` (qui échouait sans receveur) assumé, car le worker est toujours lancé au démarrage et le cas « aucun consommateur » ne survient qu'après l'arrêt.
- Destination inconnue : détectée dans `send` (même log, même métrique `notifier_type="unknown"`). `send` renvoie `Ok` si au moins une destination a reçu l'alerte ou si toutes étaient inconnues (l'erreur est déjà journalisée et comptée) ; seul l'état fermé produit une erreur.

### D4. Isolation des paniques

Chaque envoi est exécuté via `AssertUnwindSafe(notifier.send(&payload)).catch_unwind()` (`futures_util::FutureExt`). Une panique est journalisée (`Notifier panicked while sending alert`, champs `notifier`, `rule_name`), comptée dans `valerter_notify_errors_total` et `valerter_alerts_failed_total` avec les labels habituels, et le worker continue. Alternative écartée : un `tokio::spawn` par envoi (coût d'une tâche par alerte et perte de la séquentialité naturelle).

### D5. Métriques

- `valerter_queue_size` (sans label) = somme des longueurs de toutes les files de destination ; maintenu par un `AtomicUsize` partagé incrémenté/décrémenté sous le verrou de chaque file, puis publié.
- `valerter_alerts_dropped_total` (sans label) incrémenté à chaque abandon, quelle que soit la destination.
- Nouvelles séries `valerter_destination_queue_size{notifier_name, notifier_type}` et `valerter_destination_alerts_dropped_total{notifier_name, notifier_type}`, initialisées à 0 pour chaque notifier par une fonction dédiée `initialize_destination_metrics(&[(name, type)])` appelée par `main.rs` juste après `initialize_metrics` (fonction séparée pour ne pas modifier la signature de `initialize_metrics`, que `fix-metrics-consistency` retouche).
- Le log `Queue full, dropping <N> oldest alerts` est émis par le worker de la destination quand il dépile après des abandons (agrégation comme aujourd'hui avec `Lagged(n)`), avec `dropped_count` et `notifier`. Les compteurs sont incrémentés au moment de l'abandon, le log est différé pour éviter d'inonder les journaux depuis les tâches de règles.
- Choix de ne pas ajouter de label aux deux métriques existantes : les sélecteurs PromQL existants restent valides et les alertes relatives comme `rate(valerter_alerts_dropped_total[5m]) > 0` gardent leur sens. En revanche, `valerter_queue_size` devient une somme pouvant atteindre 100 × N destinations : un seuil absolu comme `valerter_queue_size > 50` ne mesure plus le remplissage d'une file (il peut se déclencher alors qu'aucune file n'est à moitié pleine, ou rester muet alors qu'une file de destination déborde si le seuil était calé sur 128). Les opérateurs sont invités à réécrire ces alertes sur `valerter_destination_queue_size` (ex. `max(valerter_destination_queue_size) > 50`) ; voir Risks et la tâche MIGRATION.

### D6. Adaptation des tests qui « écoutent » la file

`subscribe()` disparaît. C'est le poste le plus coûteux du change : une part importante des tests du moteur et des tests d'intégration observent aujourd'hui les alertes via `queue.subscribe()` et doivent tous être migrés. Les tests du moteur utiliseront un notifier de test `RecordingNotifier` (envoie chaque payload reçu dans un `mpsc`) enregistré dans un registre, avec un `NotificationWorker` lancé : ils observent ainsi le chemin réel de livraison. Un helper commun est ajouté dans `tests/common/`.

## Risks / Trade-offs

- [Mémoire : jusqu'à 100 alertes × nombre de notifiers en attente] → `Arc<AlertPayload>` partagé entre destinations ; ordre de grandeur de quelques Mo même avec des dizaines de notifiers ; à mentionner dans `docs/performance.md`.
- [Ordre global entre destinations perdu] → l'ordre est garanti par destination, seul cas observable par un humain ; documenté dans CHANGELOG/MIGRATION.
- [Sémantique de `valerter_alerts_dropped_total` et `valerter_queue_size` : livraisons et non plus alertes] → une alerte à 2 destinations compte double ; documenté dans `docs/metrics.md` et MIGRATION.md, séries par destination fournies pour le détail.
- [Seuils absolus des alertes PromQL existantes sur `valerter_queue_size` : la somme peut atteindre 100 × N destinations, une règle comme `valerter_queue_size > 50` change de sens] → signalé dans CHANGELOG et MIGRATION.md avec la recommandation de passer à `valerter_destination_queue_size` (ex. `max(valerter_destination_queue_size) > 50`) ; les alertes à base de `rate(...)` ne sont pas concernées.
- [Coût de mise en œuvre concentré sur les tests : migration de tous les tests qui observent la file via `queue.subscribe()`] → helper commun `RecordingNotifier` dans `tests/common/` (D6) pour mutualiser la migration ; à prévoir dans l'estimation du change.
- [Charge accrue sur un endpoint qui revient après une panne : il reçoit jusqu'à 100 alertes à la suite] → comportement acceptable (borne = capacité), identique en volume à aujourd'hui.
- [Chevauchement avec `drain-notification-queue-on-shutdown`] → ce change garde l'arrêt actuel ; le change de vidage devra vider **chaque** file de destination (prévoir une méthode `close()` + boucle « dépiler jusqu'à vide » par worker).
- [Ordre de démarrage décrit dans `rule-engine` (« création de la file de notifications (capacité 100) » avant le registre)] → devient inexact ; à aligner lors de l'archivage ou par le change qui modifie ce requirement (aucun change en cours ne le modifie : à réaligner à l'archivage).

## Migration Plan

- Aucune migration de configuration. Déploiement par mise à jour du binaire/.deb.
- Version : 2.1.0.
- Alertes PromQL : revoir toute règle à seuil absolu sur `valerter_queue_size` (la somme peut atteindre 100 × N destinations) et la réécrire de préférence sur `valerter_destination_queue_size` ; les règles fondées sur `rate(valerter_alerts_dropped_total[...])` restent valables.
- Tableaux de bord : ajouter éventuellement un panneau par destination sur `valerter_destination_queue_size`.
- Retour arrière : réinstaller la version précédente ; les nouvelles séries disparaissent simplement.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`  ← ce change
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (5/11) : précède `drain-notification-queue-on-shutdown`, qui vide chaque file de destination.
