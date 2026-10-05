# Proposal

## Why

Quand valerter ne surveille plus rien (toutes les tâches (règle, source) arrêtées, ou aucune règle activée), le démon se termine avec le code 0 : l'unité systemd livrée (`Restart=on-failure`) ne le relance pas et `systemctl status` affiche un service « inactive (dead) » sans erreur, alors que plus aucune alerte n'est produite. Une configuration dont toutes les règles sont désactivées passe en outre `--validate` sans erreur, et une mise à jour du `.deb` laisse le service arrêté. Pour un démon d'alerting, ces défaillances silencieuses sont le pire mode d'échec.

## What Changes

- **Code de sortie 1 quand toutes les tâches s'arrêtent sans demande d'arrêt** : la fin du moteur hors annulation devient une erreur (log ERROR, code de sortie 1), ce qui déclenche la relance par systemd (`Restart=on-failure`) et rend l'état visible (`failed`).
- **Configuration sans règle activée refusée à la validation** : `Config::validate()` rejette une configuration dont toutes les règles sont désactivées, si bien que `valerter --validate` le détecte et que le démarrage échoue avec le code 1 comme pour toute configuration invalide. **BREAKING** (comportement opérationnel) : une telle configuration, acceptée jusqu'ici, fait désormais échouer le démarrage. Le moteur conserve une garde défensive (`NoEnabledRules`, code 1) pour le cas où il serait lancé sans tâche.
- **Arrêt sans attente inutile dans ces cas** : dès que le moteur rend la main, `main` annule le jeton d'arrêt `cancel` puis suit la séquence d'arrêt existante, au lieu d'attendre l'expiration des délais fixes du worker (5 s) et du serveur de métriques (2 s). Si le change `drain-notification-queue-on-shutdown` est livré ensuite, sa séquence de vidage remplacera cette séquence.
- **Relance du service après mise à jour du `.deb`** : le `prerm` n'arrête plus le service lors d'un `upgrade`, et le `postinst` redémarre le service s'il est actif ou activé (`enabled`), y compris quand l'ancien `prerm` (≤ 2.0.3) l'a déjà arrêté. Deux secondes après le redémarrage, le `postinst` vérifie que le service est actif et, sinon, affiche sur la sortie d'erreur un avertissement bien visible renvoyant à `journalctl -u valerter`, sans faire échouer `dpkg`.
- Documentation (`docs/architecture.md`, `docs/getting-started.md`), `CHANGELOG.md` et `MIGRATION.md` (section 2.1.0) mis à jour.

Hors périmètre : la supervision des panics (délai de relance non bloquant, backoff), traitée par le change `nonblocking-panic-supervision` ; le vidage de la file à l'arrêt (change `drain-notification-queue-on-shutdown`) ; un code de sortie dédié aux configurations invalides et `RestartPreventExitStatus` dans l'unité systemd.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `rule-engine` : requirements « Aucune règle activée », « Fin inattendue de toutes les tâches », « Unité systemd fournie » (scénarios de relance et de sortie avec code 0) et « Paquet Debian » (scénarios de mise à jour). L'arrêt gracieux sur signal et la relance après panic restent hors périmètre.
- `configuration` : requirement « Présence minimale de notifiers, templates et règles » (au moins une règle activée).

## Impact

- Aucune dépendance : ce change s'implémente en premier, indépendamment de `drain-notification-queue-on-shutdown`.
- Code : `src/config/types.rs` (`Config::validate`), `src/engine.rs` (retours d'erreur de `run`, fabrique de tâche pour les tests), `src/error.rs` (nouvelles variantes de `RuleError`), `src/main.rs` (annulation du jeton dès la fin du moteur, propagation du code de sortie).
- Packaging : `debian/prerm`, `debian/postinst`. L'unité `systemd/valerter.service` n'est pas modifiée.
- Tests : tests unitaires de validation et du moteur, test d'intégration sur le binaire (configuration sans règle activée refusée par `--validate` et au démarrage, code 1).
- Exploitation : une configuration sans règle activée provoque la même boucle de relance systemd (toutes les 5 s) qu'une configuration invalide aujourd'hui ; documenté dans `MIGRATION.md`.
- Aucune nouvelle option de configuration, aucune nouvelle métrique. Livraison en 2.1.0.
