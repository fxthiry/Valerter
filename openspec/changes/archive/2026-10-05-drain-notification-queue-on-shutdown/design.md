# Design

## Context

État actuel vérifié dans le code (voir proposal.md, « Why », pour la motivation) :

- `src/main.rs` crée un unique `CancellationToken` partagé par le moteur de règles, le worker de notifications, le serveur de métriques et la tâche d'uptime. La tâche de signaux attend un seul signal (`shutdown_signal()`), annule le jeton puis se termine : un second signal n'est plus écouté (comportement par défaut de tokio une fois le handler installé : le signal est simplement absorbé).
- `NotificationWorker::run` (`src/notify/queue.rs`) fait un `tokio::select!` entre `rx.recv()` et `cancel.cancelled()`. Le traitement d'une alerte (`process_alert`) est attendu dans la branche `recv`, donc il n'est pas interrompu par l'annulation ; mais au tour de boucle suivant, l'annulation gagne et les alertes encore dans le canal `broadcast` sont abandonnées.
- Après `engine.run()`, `main` fait `tokio::time::timeout(5 s, worker_handle)` puis `timeout(2 s, metrics_handle)` et retourne ; la destruction du runtime à la fin de `main` tue le worker s'il est encore en train d'envoyer.
- Les retries des notifiers sont internes (`MATTERMOST_MAX_RETRIES = 3`, timeout HTTP 10 s, backoff 500 ms/1 s ; email : backoff 1 s/2 s) : un envoi vers un endpoint muet dure jusqu'à ~31,5 s.
- `systemd/valerter.service` : `KillMode=mixed`, `TimeoutStopSec=30`.
- Le canal `broadcast` reste ouvert tant que `main` détient `queue` : la fin des producteurs ne provoque pas `RecvError::Closed`, le worker ne peut donc pas s'appuyer sur la fermeture du canal pour détecter la fin de file.

## Goals / Non-Goals

**Goals:**
- Séparer l'arrêt des producteurs (tâches de règles) de l'arrêt du consommateur (worker), pour vider la file une fois qu'elle ne peut plus grossir.
- Garantir une durée d'arrêt bornée et compatible avec `TimeoutStopSec=30`.
- Offrir une sortie de secours immédiate (second signal).
- Rester compatible avec un futur traitement concurrent des envois (change `isolate-notifier-delivery`) : la sémantique « vider la file et terminer les envois en cours » ne suppose pas un worker unique.

**Non-Goals:**
- Persister la file sur disque entre deux exécutions.
- Rendre le délai configurable (voir Decisions).
- Modifier la sortie anticipée du moteur (aucune règle active, toutes les tâches terminées) ou ses codes de sortie : périmètre de `fix-daemon-exit-codes` (implémenté avant ce change).
- Ajouter une métrique d'alertes perdues à l'arrêt : le processus se termine juste après, aucune collecte Prometheus ne la verrait ; le log WARN suffit.

## Decisions

### D1. Deux jetons : `cancel` (producteurs) et `drain` (worker)
Le worker reçoit un jeton distinct, annulé par `main` uniquement après le retour de `engine.run()`, c'est-à-dire après « All rule tasks stopped » (`tasks.abort_all()` puis `join_next` jusqu'au bout). À ce moment plus aucun clone de `NotificationQueue` n'émet. Le serveur de métriques et l'uptime gardent le jeton `cancel` (comportement inchangé : `/metrics` s'arrête dès le premier signal).

*Alternative écartée* : garder un seul jeton et faire vider le worker dès le signal. Les tâches de règles continueraient d'émettre pendant le vidage (elles s'arrêtent de façon asynchrone), la condition « file vide » ne serait pas stable.

Effet de bord voulu : dans les chemins où le moteur retourne sans signal (aucune règle active, toutes les tâches terminées), `main` déclenche aussi le vidage ; la file étant généralement vide, le worker s'arrête aussitôt au lieu que `main` attende l'expiration des 5 s actuelles. Les requirements correspondants de `rule-engine` (« Aucune règle activée », « Fin inattendue de toutes les tâches ») ont déjà été réécrits par `fix-daemon-exit-codes` (sortie rapide, code 1) et ne sont pas modifiés ici.

### D2. Mode vidage du worker par `try_recv`
`NotificationWorker::run(shutdown)` garde sa boucle ; quand `shutdown` est annulé (branche `select!` prise, ou vérifiée après chaque alerte traitée), le worker passe en mode vidage : boucle `rx.try_recv()` — `Ok` → `process_alert` puis mise à jour de `valerter_queue_size` ; `Lagged(n)` → même traitement que la boucle normale (log + `valerter_alerts_dropped_total`) ; `Empty` ou `Closed` → log `Notification queue drained` et retour. Le worker n'a pas de délai interne : la borne est appliquée par l'appelant (D3), ce qui garde le worker simple et testable.

*Alternative écartée* : `rx.len()`/`tx.len()` comme condition d'arrêt. `try_recv` est la seule lecture atomique du canal et gère `Lagged` correctement.

### D3. Borne de 20 s appliquée par l'appelant, avec `abort()`
Nouvelle fonction de bibliothèque (dans `src/notify/queue.rs`, réexportée), par exemple `await_worker_drain(handle: JoinHandle<()>, queue: &NotificationQueue, timeout: Duration) -> DrainOutcome` : journalise `Waiting for notification worker to drain queue...` avec `queued = queue.len()`, attend `handle` au plus `timeout` ; à l'expiration, appelle `handle.abort()` (un `timeout` sur un `JoinHandle` ne tue pas la tâche) et journalise `Shutdown drain timeout reached, alerts not delivered` avec `undelivered = queue.len()`. Constante `SHUTDOWN_DRAIN_TIMEOUT: Duration = 20 s`. Isoler cette logique hors de `main.rs` permet de la tester avec `tokio::time::pause()`.

Le décompte `undelivered` ne compte que les alertes restées dans le canal ; les envois en cours interrompus par `abort()` ne sont pas comptés (la spec le dit explicitement) : les dénombrer imposerait un compteur partagé dans le worker pour un gain faible.

### D4. Délai fixe de 20 s plutôt que configurable
Budget sous `TimeoutStopSec=30` : arrêt des tâches de règles (quasi immédiat, jusqu'à 5 s aujourd'hui si un délai de relance après panic est en cours, ce que `nonblocking-panic-supervision` corrige) + 20 s de vidage + 2 s pour le serveur de métriques (déjà arrêté en pratique) = 27 s au pire. Un délai configurable (`defaults.shutdown_timeout`) obligerait à modifier les requirements de `configuration` (schéma strict, valeurs par défaut) déjà touchés par `harden-config-validation`, et à valider sa cohérence avec l'unité systemd ; le besoin n'est pas établi. Le délai ne coûte rien quand la file est vide (sortie immédiate). Il pourra devenir configurable plus tard sans changer la sémantique.

*Alternative écartée* : compter les 20 s depuis la réception du signal. Plus simple à budgéter, mais la fenêtre de vidage effective deviendrait variable ; le budget systemd est de toute façon respecté.

### D5. Second signal : sortie immédiate avec le code 1
La tâche de signaux devient une boucle à deux étages : premier signal → log existant (« Received SIGTERM » / « Received SIGINT (Ctrl+C) »), « Initiating graceful shutdown », `cancel.cancel()` ; second signal (SIGINT ou SIGTERM, dans n'importe quel ordre) → log WARN `Second shutdown signal received, forcing immediate exit` puis `std::process::exit(1)`. Les handlers Unix sont créés une seule fois et `recv()` est réappelé (pas de recréation, pour ne pas perdre un signal arrivé entre les deux). La logique est écrite contre une source d'événements abstraite (par exemple une fonction générique prenant un futur « prochain signal » et une closure de sortie) pour être testée sans envoyer de vrais signaux ; le câblage réel reste dans `main.rs`.

Code 1 plutôt que 0 : l'arrêt forcé peut perdre des alertes, il doit se distinguer d'un arrêt propre ; systemd ne relance pas un service arrêté volontairement (`systemctl stop`) quel que soit le code. Les logs `tracing` vont sur stderr sans tampon : `process::exit` ne perd pas le WARN.

*Alternative écartée* : codes 130/143 (convention shell `128 + n°`). Plus informatif mais introduit une famille de codes que `fix-daemon-exit-codes` n'utilise pas ; 1 est le code d'échec déjà utilisé.

### D6. Pas de changement de l'unité systemd
`KillMode=mixed` envoie SIGTERM au processus principal seulement, puis SIGKILL au groupe après `TimeoutStopSec=30` : compatible avec D4. Aucune modification de `systemd/valerter.service`.

### D7. Application à une file et un worker par destination
Ce change s'appuie sur la structure introduite par `isolate-notifier-delivery` (une file et un worker par destination), implémenté avant lui. Les décisions D2 et D3 s'appliquent donc à **chaque file de destination** : à l'annulation du jeton `drain`, chaque worker de destination vide sa propre file (dépilement jusqu'à file vide, à la place de la boucle `try_recv` du canal `broadcast`, abandons en attente journalisés comme dans la boucle normale) ; `await_worker_drain` attend la fin de `NotificationWorker::run`, c'est-à-dire du `JoinSet` de tous les workers de destination, et `undelivered` est la somme des longueurs des files restantes (`queue.len()`, total toutes destinations). Les files sont marquées fermées à la fin du vidage. `nonblocking-panic-supervision` (implémenté après) s'appuie sur la séquence d'arrêt définie ici ; `fix-daemon-exit-codes` (implémenté avant) n'en dépend pas, et ce change remplace la séquence d'arrêt qu'il laisse en place après `cancel.cancel()`.

## Risks / Trade-offs

- [Un endpoint muet consomme tout le délai de sa propre destination et ses alertes suivantes sont perdues, chaque worker de destination restant séquentiel] → Borne de 20 s et WARN avec `undelivered` ; grâce à `isolate-notifier-delivery`, les autres destinations vident leurs files en parallèle et ne sont pas affectées.
- [Arrêt plus long qu'avant (jusqu'à ~20 s) qui peut surprendre en exploitation ou dans les scripts] → Documenté dans CHANGELOG.md et MIGRATION.md ; second signal pour forcer.
- [Mise à jour du paquet Debian : le `postinst` exécute `systemctl restart valerter` (dans `debian/postinst`, à la mise à jour quand le service est actif), qui attend la fin de l'arrêt] → `dpkg` (et donc `apt upgrade`) peut désormais rester bloqué jusqu'à ~27 s (budget de D4) lorsque des alertes sont en file ou qu'un endpoint est lent, au lieu de quelques secondes. Comportement assumé (c'est ce qui évite de perdre les alertes à la mise à jour) ; documenté dans MIGRATION.md et CHANGELOG.md. Le `postinst` n'est pas modifié (un `--no-block` rendrait la fin de la mise à jour asynchrone et masquerait un échec de redémarrage).
- [`docker stop` (10 s par défaut) envoie SIGKILL avant la fin du vidage] → Note dans MIGRATION.md et `docs/architecture.md` recommandant `--stop-timeout 30` / `stop_grace_period: 30s`. Ce n'est pas une régression : aujourd'hui la file est perdue de toute façon.
- [Requirements « Aucune règle activée » et « Fin inattendue de toutes les tâches »] → réécrits par `fix-daemon-exit-codes` (sortie rapide, code 1), sans dépendance à l'attente de 5 s ; non modifiés ici.
- [Chevauchement avec `nonblocking-panic-supervision` sur le délai de relance après panic qui retarde l'arrêt des tâches] → Absorbé par le budget de D4 (27 s au pire).
- [Tests d'intégration existants de `tests/integration_notify.rs` qui annulent le worker après un `sleep` : avec le vidage, le worker traite les alertes restantes avant de sortir] → Les relire ; ceux qui comptent les appels avec `expect(n)` restent justes si toutes les alertes devaient être envoyées, sinon ajuster.

## Migration Plan

Livré dans la version 2.1.0. Déploiement par mise à jour normale du paquet ; aucune action de configuration. À la mise à jour, le `systemctl restart` du `postinst` peut bloquer `dpkg` jusqu'à ~27 s si des alertes sont en file. Retour arrière : réinstaller la version précédente (aucun état persistant introduit).

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`  ← ce change
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (6/11) : suit `isolate-notifier-delivery` et `fix-daemon-exit-codes` ; précède `nonblocking-panic-supervision`.
