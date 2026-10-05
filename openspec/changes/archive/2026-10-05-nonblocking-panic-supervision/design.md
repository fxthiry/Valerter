# Design

## Context

- Dans `supervise_tasks` (`src/engine.rs`), la branche panic fait `tokio::time::sleep(PANIC_RESTART_DELAY).await` à l'intérieur du bras de `tokio::select!` : pendant 5 s ni `join_next_with_id` ni `cancel.cancelled()` ne sont scrutés. Plusieurs panics simultanés s'additionnent (N × 5 s). Aucun compteur par couple : une tâche qui panique de façon déterministe est relancée toutes les 5 s indéfiniment.
- `handle_to_context` associe l'identifiant de tâche Tokio au couple (règle, source) et à son `RuleSpawnContext`, cloné pour la relance. `fix-cross-source-throttle-dedup` ajoute à ce contexte le magasin de throttle partagé par règle ; les deux changes touchent les mêmes structures et s'appliquent l'un après l'autre.
- `fix-daemon-exit-codes` (implémenté avant) fait renvoyer `Err(AllTasksStopped)` au moteur quand le `JoinSet` se vide hors annulation, et introduit une fabrique de tâche `pub(crate)` qui permet de simuler des tâches qui paniquent.
- `drain-notification-queue-on-shutdown` (implémenté avant) définit la séquence d'arrêt et son budget sous `TimeoutStopSec=30` ; le délai de relance bloquant pouvait y ajouter jusqu'à 5 s.

## Goals / Non-Goals

**Goals:**

- Rendre la boucle de supervision réactive en permanence (aucun `await` bloquant dans un bras du `select!`).
- Espacer les relances d'un couple qui panique en boucle, avec des constantes en dur et testables.
- Ne jamais perdre définitivement la surveillance d'un couple à cause de panics.

**Non-Goals:**

- Abandonner un couple après un nombre de panics : écarté (voir D2).
- Rendre le backoff configurable, ajouter des métriques.
- Relancer les tâches en erreur fatale : elles restent non relancées (requirement « Isolation des erreurs entre tâches » inchangé).
- Codes de sortie et fin anormale du moteur (`fix-daemon-exit-codes`), séquence d'arrêt (`drain-notification-queue-on-shutdown`).

## Decisions

### D1. Délai de relance porté par la tâche relancée

Au lieu de dormir dans le superviseur, la branche panic insère immédiatement dans le même `JoinSet` une tâche qui fait :

```text
select! { sleep(delay) => {}, cancel.cancelled() => return Ok(()) }
log "Rule-source task respawned after panic"
run_rule(ctx, cancel).await
```

Conséquences : la boucle de supervision ne bloque plus ; l'arrêt annule la tâche pendant son sommeil (`abort_all` ou la branche `cancel`) ; une tâche en attente reste dans le `JoinSet`, donc la détection « All rule tasks completed unexpectedly » ne se déclenche pas à tort ; les panics simultanés ont des délais indépendants. `handle_to_context` est mis à jour avec le nouvel identifiant de tâche, comme aujourd'hui.

Alternatives écartées : `tokio_util::time::DelayQueue` ou un second `JoinSet` de minuteries scruté dans le `select!`. Fonctionnels mais ajoutent une source d'événements et un état « en attente » à compter à part pour la détection de fin ; la tâche différée réutilise toute la mécanique existante.

### D2. Backoff exponentiel plafonné, relance infinie

Constantes dans `engine.rs` :

- `PANIC_RESTART_BASE_DELAY = 5 s`, `PANIC_RESTART_MAX_DELAY = 300 s`, délai = `min(base × 2^(n-1), max)` pour le n-ième panic consécutif (calcul saturant pour éviter tout dépassement quand n devient grand) ;
- `PANIC_STABLE_RUN_RESET = 600 s` : si la tâche a tourné au moins ce temps depuis sa (re)lance effective (fin du sommeil), le compteur repart à 1.

Le compteur et l'instant de lancement effectif sont stockés dans la valeur de `handle_to_context`, enrichie d'un `consecutive_panics: u32` et d'un `started_at: Instant` calculé comme instant de programmation + délai (aucun état partagé avec la tâche). Pas de jitter : les panics sont des bugs, pas une charge réseau à étaler.

Aucun plafond du nombre de relances : un couple qui panique en boucle est relancé toutes les 5 min au plus tard, indéfiniment. Abandonner un couple ferait cesser silencieusement les alertes d'une règle sur une source, ce qui est le mode d'échec que le projet cherche à éliminer ; un panic peut aussi dépendre des données (une ligne particulière) et disparaître ensuite. `valerter_rule_panics_total{rule_name, vl_source}` augmente à chaque panic et constitue le signal d'alerte (règle Prometheus documentée dans `docs/metrics.md`). `valerter_rule_errors_total` n'est pas incrémenté par un panic : sa sémantique (erreurs fatales de tâche) reste inchangée.

Alternatives écartées : abandon après N panics consécutifs (perte silencieuse de surveillance, et nécessiterait de surcharger `valerter_rule_errors_total`) ; constantes configurables (aucun besoin exprimé, surface de validation en plus).

### D3. Tests en temps virtuel

Les tests réutilisent la fabrique de tâche de `fix-daemon-exit-codes` avec une implémentation qui panique selon un script, et `#[tokio::test(start_paused = true)]` (feature `test-util`, absente de `full` : l'ajouter via une entrée `tokio` en `[dev-dependencies]`) pour avancer le temps sans attendre.

## Risks / Trade-offs

- [Un couple qui panique en boucle produit un panic toutes les 5 min indéfiniment] → Coût négligeable (une connexion `/tail` et quelques lignes de log toutes les 5 min) ; visible via `valerter_rule_panics_total` et le log ERROR « Rule task panicked - CRITICAL » ; préférable à une perte silencieuse de surveillance.
- [Le délai maximal de 5 min retarde la reprise après un panic transitoire répété] → La remise à zéro après 10 min de fonctionnement stable ramène le délai à 5 s.
- [Conflits de fusion avec `fix-cross-source-throttle-dedup` sur `supervise_tasks` / `RuleSpawnContext`] → Changes séquentiels ; celui implémenté en second rebase sur le premier.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`  ← ce change
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (7/11) : suit `drain-notification-queue-on-shutdown` et `fix-cross-source-throttle-dedup`.
