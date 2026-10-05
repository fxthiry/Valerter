# Tasks

## 1. Vidage de la file par le worker

- [ ] 1.1 Dans `src/notify/queue.rs`, ajouter le mode vidage à `NotificationWorker::run(shutdown)` (D2, D7), dans **chaque worker de destination** issu de `isolate-notifier-delivery` : à l'annulation du jeton `drain`, dépiler la file de la destination jusqu'à ce qu'elle soit vide (envoi + mise à jour de `valerter_queue_size` et `valerter_destination_queue_size`, abandons en attente journalisés comme dans la boucle normale), puis fermer la file ; une fois tous les workers terminés, log info `Notification queue drained` et retour ; mettre à jour la doc comment. Vérifier : `cargo build` passe.
- [ ] 1.2 Tests unitaires du worker (dans `src/notify/tests.rs`, notifier factice enregistrant l'ordre des appels) : trois alertes en file puis annulation → les trois sont envoyées dans l'ordre FIFO ; deux destinations dont l'une est bloquée → l'autre vide entièrement sa file ; file vide puis annulation → retour immédiat ; annulation pendant un envoi → l'envoi se termine puis les alertes restantes sont traitées. Vérifier : `cargo test notify::` passe.
- [ ] 1.3 Relire les tests existants de `tests/integration_notify.rs` qui annulent le worker après un `sleep` et ajuster ceux dont les attentes (`expect(n)`, compteurs) supposaient l'abandon de la file. Vérifier : `cargo test --test integration_notify` passe.

## 2. Attente bornée du vidage

- [ ] 2.1 Ajouter dans `src/notify/queue.rs` la constante `SHUTDOWN_DRAIN_TIMEOUT` (20 s) et la fonction `await_worker_drain(handle, &queue, timeout) -> DrainOutcome` (D3) : log `Waiting for notification worker to drain queue...` avec `queued`, attente bornée, `handle.abort()` et log WARN `Shutdown drain timeout reached, alerts not delivered` avec `undelivered = queue.len()` à l'expiration ; réexporter depuis `src/notify/mod.rs` et `src/lib.rs`. Vérifier : `cargo build` passe.
- [ ] 2.2 Tests unitaires avec `tokio::time::pause()` : worker qui termine avant le délai → `DrainOutcome::Drained` ; notifier factice bloqué indéfiniment avec deux alertes derrière → `DrainOutcome::TimedOut { undelivered: 2 }` au bout de 20 s et tâche du worker effectivement annulée (`JoinHandle::is_finished`). Vérifier : `cargo test` passe.

## 3. Séquence d'arrêt et second signal dans `main`

- [ ] 3.1 Dans `src/main.rs`, créer un jeton `drain` distinct passé au worker (D1), l'annuler après le retour de `engine.run()` puis appeler `await_worker_drain(worker_handle, &queue, SHUTDOWN_DRAIN_TIMEOUT)` à la place de `timeout(5 s, worker_handle)` ; le serveur de métriques et l'uptime gardent le jeton `cancel`. Vérifier : `cargo build` et, manuellement, `Ctrl+C` sur un démon sans alerte en file quitte immédiatement avec « Notification queue drained » puis « valerter shutdown complete ».
- [ ] 3.2 Remplacer la tâche de signaux par un gestionnaire à deux étages (D5) écrit contre une source d'événements abstraite : premier signal → logs existants + `cancel.cancel()` ; second signal (SIGINT ou SIGTERM) → WARN `Second shutdown signal received, forcing immediate exit` puis sortie code 1 ; handlers Unix créés une seule fois ; garder le repli `ctrl_c` hors Unix (deux `ctrl_c()` successifs). Vérifier : tests unitaires dans `src/main.rs` avec une source simulée (un événement → annulation sans sortie ; deux événements → closure de sortie appelée avec 1).
- [ ] 3.3 Test d'intégration `#[cfg(unix)]` dans `tests/` (binaire réel, sur le modèle de `tests/integration_validate.rs`) : source VictoriaLogs wiremock qui émet plusieurs lignes correspondantes, webhook wiremock avec un délai de réponse d'environ 1 s ; envoyer `kill -TERM` pendant que des alertes sont en file → toutes les alertes reçues par le webhook, code de sortie 0, stderr contenant « Notification queue drained ». Vérifier : `cargo test --test <nom>` passe.
- [ ] 3.4 Test d'intégration `#[cfg(unix)]` du second signal : webhook wiremock répondant après 30 s ; `kill -TERM` puis, une fois « Waiting for notification worker to drain queue... » lu sur stderr, un second `kill -TERM` → sortie en moins de 2 s avec le code 1 et le log « Second shutdown signal received, forcing immediate exit ». Vérifier : le test passe.

## 4. Documentation

- [ ] 4.1 `docs/architecture.md` : décrire la séquence d'arrêt (arrêt des tâches de règles, vidage de la file borné à 20 s, WARN `undelivered`, second signal → sortie immédiate code 1) dans la section « Notification Queue » et la ligne « Graceful shutdown », avec le budget sous `TimeoutStopSec=30` et la recommandation `docker stop --stop-timeout 30` / `stop_grace_period: 30s`. Vérifier : relecture, cohérence avec `specs/` du change.
- [ ] 4.2 `CHANGELOG.md` : ajouter à la section `## [2.1.0]` (la créer si elle n'existe pas), sous `### Changed` ou `### Fixed`, le vidage de la file à l'arrêt, le délai de 20 s, le second signal et le fait qu'une mise à jour du paquet Debian peut durer jusqu'à ~27 s de plus. Vérifier : format Keep a Changelog respecté.
- [ ] 4.3 `MIGRATION.md` : ajouter à la section « Upgrading to 2.1.0 » (la créer si elle n'existe pas) une courte note de changement de comportement : arrêt pouvant durer jusqu'à ~20 s de plus ; le `systemctl restart` exécuté par le `postinst` Debian à la mise à jour peut désormais bloquer `dpkg`/`apt` jusqu'à ~27 s quand des alertes sont en file (comportement attendu, ne pas interrompre) ; délai d'arrêt des orchestrateurs à porter à 30 s ; second signal pour forcer, code de sortie 1 dans ce cas ; aucune rupture de configuration. Vérifier : relecture.

## 5. Vérification d'ensemble

- [ ] 5.1 Lancer `cargo fmt --check`, `cargo clippy -- -D warnings` et `cargo test`. Vérifier : les trois commandes réussissent.
- [ ] 5.2 `openspec validate drain-notification-queue-on-shutdown --strict --no-interactive` passe.
