# Proposal

## Why

Aujourd'hui, un `systemctl stop` ou un `systemctl restart` (mise à jour du paquet, changement de configuration) perd silencieusement toutes les alertes en attente dans la file de notifications : le worker partage le jeton d'annulation des tâches de règles et s'arrête dès le signal reçu, sans vider la file (`src/notify/queue.rs`, `NotificationWorker::run`), puis `main` n'attend le worker que 5 s avant de détruire le runtime, ce qui coupe aussi l'alerte en cours d'envoi si ses retries dépassent ce délai (jusqu'à ~31,5 s pour un endpoint HTTP muet). Un redémarrage pendant un incident, précisément quand la file est pleine, efface donc les alertes les plus utiles, sans aucun log. À l'inverse, il n'existe aucun moyen de forcer un arrêt immédiat : un second Ctrl+C est ignoré.

## What Changes

- À l'arrêt (SIGTERM/SIGINT), les tâches de règles sont d'abord arrêtées (plus aucun producteur), puis le worker **vide la file** : il termine l'alerte en cours et envoie toutes les alertes encore en file, dans l'ordre, jusqu'à ce que la file soit vide.
- Ce vidage est **borné par un délai fixe de 20 s** (non configurable), compté à partir de la fin de l'arrêt des tâches de règles, choisi pour tenir avec le reste de la séquence d'arrêt sous le `TimeoutStopSec=30` de l'unité systemd livrée. Si la file est vide, le processus quitte aussitôt sans attendre.
- À l'expiration du délai, le worker est interrompu et un avertissement indique le nombre d'alertes non délivrées (`Shutdown drain timeout reached, alerts not delivered`, champ `undelivered`). Un vidage réussi est journalisé (`Notification queue drained`).
- Un **second SIGTERM/SIGINT** reçu pendant l'arrêt (quelle qu'en soit la phase) force la sortie immédiate du processus avec le code 1, après le log `Second shutdown signal received, forcing immediate exit`.
- Changement de comportement visible (pas de rupture de configuration) : un arrêt peut durer jusqu'à ~20 s de plus lorsque des alertes sont en attente ou qu'un endpoint est lent. En particulier, le `systemctl restart` exécuté par le `postinst` Debian lors d'une mise à jour peut bloquer `dpkg` jusqu'à ~27 s quand des alertes sont en file. Documenté dans CHANGELOG.md et MIGRATION.md (version 2.1.0 ; note sur `docker stop`, dont le délai par défaut de 10 s est plus court, et sur la durée de la mise à jour du paquet).

Ce change s'appuie sur les files par destination de `isolate-notifier-delivery` : le vidage s'applique à chaque file de destination. Hors périmètre : codes de sortie (change `fix-daemon-exit-codes`, implémenté avant) et délai de relance après panic (change `nonblocking-panic-supervision`, implémenté après), persistance de la file sur disque, délai configurable.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `notification-dispatch` : le requirement « Arrêt sans vidage de la file » est remplacé par un requirement de vidage borné de la file à l'arrêt (fin des envois en cours, envoi des alertes en file, délai de 20 s, log des alertes non délivrées).
- `rule-engine` : le requirement « Arrêt gracieux sur signal » est modifié (ordre arrêt des règles → vidage de la file, délai de 20 s au lieu de 5 s pour le worker, second signal qui force la sortie immédiate avec le code 1).

## Impact

- Code : `src/main.rs` (gestionnaire de signaux à deux étages, jeton de vidage distinct du jeton d'annulation des règles, attente bornée du worker), `src/notify/queue.rs` (mode vidage de `NotificationWorker`, constante du délai), éventuellement `src/lib.rs` (réexport de la constante).
- Tests : tests unitaires du worker (vidage complet, ordre FIFO, respect du délai, file vide) avec des notifiers factices ; test d'intégration wiremock dans `tests/integration_notify.rs`.
- Docs : `docs/architecture.md` (sections « Notification Queue » et graceful shutdown), CHANGELOG.md, MIGRATION.md.
- Exploitation : la mise à jour du paquet (`postinst` → `systemctl restart`) peut durer jusqu'à ~27 s de plus quand des alertes sont en file ; la séquence d'arrêt reste sous les 30 s de `TimeoutStopSec` de `systemd/valerter.service` (aucune modification de l'unité requise).
