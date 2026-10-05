# Proposal

## Why

Quand une tâche (règle, source) panique, la boucle de supervision de `RuleEngine` dort 5 s à l'intérieur de son `select!` : pendant ce délai, les autres tâches ne sont plus supervisées et une demande d'arrêt n'est pas prise en compte (plusieurs panics simultanés cumulent leurs délais). Par ailleurs, une tâche qui panique de façon déterministe est relancée toutes les 5 s indéfiniment, sans aucun espacement, ce qui inonde les logs et martèle VictoriaLogs.

## What Changes

- **Délai de relance après panic non bloquant** : le délai est porté par la tâche relancée elle-même ; la boucle de supervision continue de traiter les autres tâches et l'arrêt pendant ce délai, et une tâche en attente de relance est annulée immédiatement à l'arrêt, sans retarder la séquence d'arrêt.
- **Backoff exponentiel par couple (règle, source)** : 5 s, doublé à chaque panic consécutif, plafonné à 5 min ; compteur remis à zéro après 10 minutes de fonctionnement sans panic.
- **Relance infinie** : un couple n'est jamais abandonné, quel que soit le nombre de panics ; `valerter_rule_panics_total{rule_name, vl_source}` continue d'augmenter à chaque panic et sert de signal d'alerte. `valerter_rule_errors_total` garde sa sémantique actuelle (erreurs fatales uniquement).
- Documentation (`docs/architecture.md`, `docs/metrics.md`) et `CHANGELOG.md` (section 2.1.0) mis à jour.

Hors périmètre : codes de sortie et fin anormale du moteur (change `fix-daemon-exit-codes`), séquence d'arrêt et vidage de la file (change `drain-notification-queue-on-shutdown`), backoff configurable, nouvelles métriques.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `rule-engine` : le requirement « Relance après panic » est remplacé (REMOVED + ADDED) par « Relance après panic non bloquante avec backoff », le scénario « Supervision suspendue pendant le délai » disparaissant.

## Impact

- Ordre : s'implémente après `drain-notification-queue-on-shutdown` (l'annulation immédiate d'une tâche en attente de relance s'insère dans sa séquence d'arrêt) et réutilise la fabrique de tâche de test introduite par `fix-daemon-exit-codes`.
- Code : `src/engine.rs` (`supervise_tasks`, `spawn_single_rule`, valeur de `handle_to_context` enrichie, constantes de backoff). Modifie `supervise_tasks` et `RuleSpawnContext` / `handle_to_context` comme `fix-cross-source-throttle-dedup` : les deux changes sont séquentiels, le second rebase sur le premier.
- Tests : tests unitaires du superviseur en temps virtuel (`tokio::time::pause`, feature `test-util` en dev-dependency).
- Aucune nouvelle option de configuration, aucune nouvelle métrique, aucun changement de configuration requis. Livraison en 2.1.0.
