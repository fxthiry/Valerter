# Proposal

## Why

MIGRATION.md, docs/configuration.md et le CHANGELOG v2.0.0 promettent qu'une règle multi-sources peut dédupliquer ses alertes entre sources en posant `throttle.key: "{{ rule_name }}"`. C'est faux aujourd'hui : chaque tâche (règle, source) crée son propre `Throttler` et donc son propre cache moka (`run_rule` dans `src/engine.rs`), si bien que deux sources ayant une clé rendue identique ne partagent jamais de compteur. Une même panne vue par `vlprod` et `vldev` produit deux alertes au lieu d'une, en contradiction avec la documentation publiée. Par ailleurs, docs/architecture.md décrit l'algorithme comme une « sliding window » alors que le cache moka (`time_to_live`) implémente une fenêtre fixe ancrée sur le premier événement.

## What Changes

- Un cache de throttling unique est créé **par règle** et partagé entre toutes les tâches (règle, source) de cette règle ; le compteur d'une clé est commun à toutes les sources qui rendent cette même clé.
- La clé par défaut `<rule_name>-<vl_source>:global` est inchangée : comme elle contient le nom de la source, l'isolation par source reste le comportement par défaut, sans configuration.
- **BREAKING (comportement)** : une clé personnalisée qui ne contient pas `{{ vl_source }}` (ex. `{{ rule_name }}`, `{{ host }}`) est désormais partagée entre les sources de la règle. C'est la sémantique documentée ; pour retrouver un compteur par source avec une clé personnalisée, il suffit d'y ajouter `{{ vl_source }}`. Documenté dans MIGRATION.md et CHANGELOG.md (version 2.1.0).
- Un log INFO est émis au démarrage, une fois par règle ciblant au moins deux sources effectives, lorsque sa clé de throttle personnalisée ne référence pas `vl_source` : il indique que le compteur est partagé entre les sources de la règle et qu'il suffit d'ajouter `{{ vl_source }}` à la clé pour l'isoler. La détection est statique (variables non déclarées du template minijinja), sans rendu d'essai.
- La remise à zéro après reconnexion d'une source ne vide plus tout le cache : elle n'invalide que les clés alimentées exclusivement par cette source, pour ne pas effacer l'état de dédoublonnage entretenu par les autres sources encore connectées.
- La borne du cache devient 10 000 clés × nombre de sources de la règle (même budget mémoire total qu'aujourd'hui), toujours non configurable.
- Le cache partagé survit à la relance d'une tâche après panic (il appartient à la règle, pas à la tâche).
- Documentation : « sliding window » → « fixed window » dans docs/architecture.md ; portée du cache par règle et rôle de `{{ vl_source }}` dans la clé expliqués dans docs/configuration.md.
- Inchangé : métriques `valerter_alerts_passed_total` / `valerter_alerts_throttled_total` (toujours étiquetées par la source qui a évalué l'événement), clé de repli `<rule_name>:error`, syntaxe et validation du bloc `throttle`.

## Capabilities

### New Capabilities

_Aucune._

### Modified Capabilities

- `throttling` : remplacement de l'isolation par couple (règle, source) par un cache partagé par règle ; log INFO au démarrage pour une règle multi-sources dont la clé personnalisée ne référence pas `vl_source` ; borne du cache recalculée par règle ; remise à zéro après reconnexion limitée aux clés propres à la source ; persistance du cache à la relance d'une tâche.
- `rule-engine` : le requirement « État isolé par tâche » ne couvre plus l'état de throttling (parser et connexion restent propres à chaque tâche).

## Impact

- Code : `src/throttle.rs` (séparation d'un magasin partagé par règle et d'une vue par tâche, invalidation sélective, détection statique de `vl_source` dans la clé), `src/engine.rs` (création du magasin et log INFO dans `spawn_rule_tasks`, transport via `RuleSpawnContext`, `ThrottleResetCallback`).
- Tests : unitaires dans `src/throttle.rs` et `src/engine.rs` ; intégration wiremock dans `tests/multi_source_integration.rs`.
- Docs : docs/architecture.md, docs/configuration.md, MIGRATION.md, CHANGELOG.md, examples/multi-source/README.md.
- Aucune dépendance nouvelle (moka déjà présent) ; aucun changement de format de configuration.
- Déploiements concernés par le changement de comportement : règles multi-sources (sans `vl_sources` ou avec plusieurs sources) utilisant une `throttle.key` personnalisée sans `{{ vl_source }}`.
