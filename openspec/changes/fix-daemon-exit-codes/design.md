# Design

## Context

État actuel (voir proposal.md, section Why, pour la motivation) :

- `RuleEngine::run` (`src/engine.rs`) renvoie `Ok(())` dans les trois cas de fin : annulation, aucune tâche lancée (`spawned_count == 0`) et `tasks.is_empty()` hors annulation. `main.rs::run` ne distingue donc pas un arrêt demandé d'une perte totale de surveillance et renvoie `Ok(())`, d'où le code 0.
- `Config::validate()` (`src/config/types.rs`) ne contrôle que `rules.is_empty()` : une configuration dont toutes les règles ont `enabled: false` est valide, passe `--validate`, puis le démon démarre et sort aussitôt avec le code 0.
- Après le retour du moteur, `main.rs` attend `worker_handle` (timeout 5 s) puis `metrics_handle` (timeout 2 s) sans jamais annuler le jeton `cancel` hors signal : le worker et le serveur de métriques tournent jusqu'au timeout, soit environ 7 s de latence avant la sortie.
- Depuis la 2.0.3, `stream_with_reconnect` ne renvoie plus d'erreur en pratique : une erreur fatale de tâche ne vient plus guère que de `TailClient::new` (construction du client reqwest). La perte de toutes les tâches reste possible (échec global de construction du client TLS, par exemple).
- `debian/prerm` arrête le service sur `upgrade` ; `debian/postinst` ne le redémarre que s'il est actif (`is-active`), ce qu'il n'est plus. Lors d'une mise à jour, c'est le prerm de l'**ancien** paquet qui s'exécute (`old-prerm upgrade <new-version>`) : le correctif doit donc vivre dans le postinst pour couvrir la transition depuis ≤ 2.0.3.
- Une configuration invalide fait déjà sortir le démon avec le code 1 ; sous l'unité livrée (`Restart=on-failure`, `RestartSec=5`), systemd le relance donc en boucle toutes les 5 s.

## Goals / Non-Goals

**Goals:**

- Distinguer dans le type de retour du moteur l'arrêt demandé des fins anormales, et les traduire en code de sortie 1.
- Détecter dès la validation (et donc avec `--validate`) une configuration sans règle activée.
- Supprimer l'attente fixe de 7 s après une fin anormale du moteur.
- Relancer le service après `dpkg -i` d'une nouvelle version et signaler clairement un redémarrage raté.

**Non-Goals:**

- La supervision des panics (délai de relance non bloquant, backoff) : change `nonblocking-panic-supervision`.
- La séquence d'arrêt sur signal, le vidage de la file, sa borne et le second signal : change `drain-notification-queue-on-shutdown`, qui remplacera la séquence d'arrêt utilisée ici.
- Relancer les tâches en erreur fatale : elles restent non relancées (requirement « Isolation des erreurs entre tâches » inchangé).
- Un code de sortie dédié aux configurations invalides et `RestartPreventExitStatus` / `StartLimit*` dans l'unité systemd.
- Valider la configuration dans le `postinst` (voir D5).

## Decisions

### D1. Nouvelles variantes de `RuleError` pour les fins anormales

`RuleError` gagne `NoEnabledRules` et `AllTasksStopped`. `run` renvoie `Ok(())` uniquement après annulation. `main.rs` les fait remonter comme aujourd'hui (`Err(anyhow!("Engine error: …"))`), ce qui donne le code 1 via le `Result` de `main`.

Alternative écartée : un `enum EngineExit` en valeur de retour `Ok(...)`. Plus verbeux pour le même résultat ; le chemin d'erreur existe déjà dans `main.rs` et n'est aujourd'hui jamais emprunté.

Les messages de log existants (« No enabled rules found, engine will exit », « All rule tasks completed unexpectedly ») sont conservés au caractère près pour ne pas casser d'éventuelles alertes sur les logs ; seul leur niveau passe de WARN à ERROR.

### D2. Refus d'une configuration sans règle activée dans `Config::validate()`

Juste après le contrôle `rules.is_empty()`, `validate()` ajoute l'erreur `all rules are disabled: enable at least one rule in config.yaml or rules.d/` quand `rules` n'est pas vide et qu'aucune règle n'a `enabled: true`. L'erreur rejoint la liste collectée (validation exhaustive) ; les deux erreurs sont exclusives. Comme `--validate` et le démarrage passent par la même validation, les deux la signalent et sortent avec le code 1.

`NoEnabledRules` reste dans le moteur comme garde défensive : elle n'est plus atteignable depuis une configuration chargée normalement, mais protège les constructions directes de `RuntimeConfig` (tests, évolutions futures) contre un retour silencieux en code 0.

Alternative écartée : contrôle dans le seul mode `--validate` (`src/cli` / change `complete-validate-mode`). Le démarrage aurait alors un comportement différent de la validation, contraire à la parité recherchée.

### D3. Toute fin du moteur déclenche la séquence d'arrêt existante

Dans `main.rs::run`, dès le retour de `engine.run(...)`, quelle qu'en soit la cause, `main` appelle `cancel.cancel()` (idempotent si un signal l'a déjà annulé) puis suit la séquence d'arrêt actuelle : attente du worker et du serveur de métriques avec leurs timeouts existants. Le worker, le serveur de métriques et la tâche d'uptime observant ce jeton, ils s'arrêtent aussitôt ; les timeouts ne servent plus que de garde-fous et la sortie est quasi immédiate.

Codes de sortie : 0 uniquement après un arrêt demandé par signal ; 1 pour `NoEnabledRules` / `AllTasksStopped`.

Ce change ne dépend pas de `drain-notification-queue-on-shutdown`. Quand celui-ci sera implémenté, sa séquence (annulation du jeton des règles, vidage borné de la file via le jeton `drain`, arrêt métriques/uptime) remplacera la séquence ci-dessus, y compris après une fin anormale. D'ici là, comme pour un arrêt sur signal aujourd'hui, les alertes encore en file au moment d'une fin anormale ne sont pas garanties.

### D4. Fabrique de tâche pour tester les fins anormales

`spawn_single_rule` appelle directement `run_rule`, ce qui rend les fins de tâche intestables sans réseau. On introduit un paramètre de fabrique de tâche (fonction ou trait interne `RuleRunner`, `pub(crate)`), avec `run_rule` comme implémentation par défaut et une implémentation de test qui renvoie une erreur, se termine ou boucle selon un script. Le change `nonblocking-panic-supervision` réutilisera cette fabrique pour ses tests de panic.

### D5. Scripts Debian

- `prerm` : ne plus arrêter le service sur `upgrade` (garder `remove` et `deconfigure`). L'ancien processus continue de tourner pendant l'unpack (le binaire remplacé reste mappé), ce qui réduit l'interruption à la durée du `restart`.
- `postinst configure` avec `$2` non vide (mise à jour) : après `daemon-reload`, `systemctl restart valerter` si `is-active` **ou** `is-enabled`. Le test `is-enabled` couvre la transition depuis ≤ 2.0.3 dont le prerm a déjà arrêté le service ; c'est aussi le comportement de `deb-systemd-invoke` (n'agit que sur une unité activée). Première installation inchangée : rien n'est démarré ni activé (la configuration d'exemple doit être éditée d'abord).
- Contrôle après redémarrage : `sleep 2`, puis `systemctl is-active --quiet valerter ||` affichage sur la sortie d'erreur d'un avertissement bien visible (bandeau sur plusieurs lignes, par exemple `WARNING: valerter failed to start after upgrade` suivi de `Check the logs with: journalctl -u valerter`). Le délai de 2 s laisse le temps à une configuration invalide de faire sortir le processus (code 1, puis `activating (auto-restart)`, donc non actif). Le script continue et sort en 0 : `dpkg` ne doit pas échouer pour un problème de configuration locale.
- Le `|| true` sur le `restart` est conservé pour la même raison.

Pas de `valerter --validate` dans le `postinst` : l'unité n'a pas d'`EnvironmentFile`, mais les variables `${VAR}` de la configuration peuvent être fournies au service par un drop-in systemd (`Environment=`) invisible pour root lors de l'exécution du script ; une validation lancée depuis le `postinst` signalerait alors à tort des variables indéfinies. Le contrôle de l'état réel du service après redémarrage ne souffre pas de ce biais.

Alternative écartée : passer à `systemd-units` de cargo-deb (scripts générés par dh). Changement de packaging plus large, interaction avec les scripts manuels existants à requalifier.

## Risks / Trade-offs

- [Une configuration sans règle activée provoque désormais une boucle de relance systemd toutes les 5 s] → Même comportement qu'une configuration invalide aujourd'hui (déjà code 1) ; `StartLimitBurst`/`StartLimitIntervalSec` par défaut ne l'arrêtent pas avec `RestartSec=5`. Désormais détectable en amont par `--validate`. Documenté dans `MIGRATION.md` avec la consigne de désactiver le service plutôt que toutes les règles.
- [Un service activé mais volontairement arrêté est redémarré par la mise à jour] → Comportement standard Debian ; documenté dans `CHANGELOG.md` et `docs/getting-started.md`.
- [Mise à jour depuis ≤ 2.0.3 d'un service démarré à la main sans être activé] → L'ancien prerm l'arrête et rien ne permet de savoir qu'il tournait ; il reste arrêté. Documenté (une seule fois, à la transition).
- [Le contrôle à 2 s peut manquer un échec plus tardif (par exemple validation qui dépend du réseau)] → Il vise l'échec de démarrage typique (configuration invalide, sortie immédiate) ; il n'est qu'un avertissement, l'état `failed` et le journal restent la référence.
- [Alertes en file perdues lors d'une fin anormale tant que le vidage n'est pas livré] → Comportement identique à l'arrêt sur signal actuel ; corrigé par `drain-notification-queue-on-shutdown`, livré dans la même version.
- [La fabrique de tâche (D4) complexifie l'API interne du moteur] → Limitée à `pub(crate)`, aucune incidence sur l'API publique `RuleEngine::new`.

## Migration Plan

1. Livré en 2.1.0 (comportement visible : code de sortie, refus de la configuration sans règle activée, relance après mise à jour). Entrées dans la section `## [2.1.0]` de `CHANGELOG.md` (Fixed / Changed) et dans la section « Upgrading to 2.1.0 » de `MIGRATION.md`.
2. Rollback : réinstaller le `.deb` précédent ; aucun état persistant, aucune configuration modifiée. Le prerm de la nouvelle version n'arrêtant plus le service sur `upgrade`, le postinst de l'ancienne version (qui ne relance que si actif) relancera bien le service.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`  ← ce change
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (1/11) : en premier, sans dépendance ; `drain-notification-queue-on-shutdown` remplacera plus tard la séquence d'arrêt laissée en place après `cancel.cancel()`.
