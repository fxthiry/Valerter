# Tasks

## 1. Préparation des tests

- [ ] 1.1 Ajouter `tokio` avec la feature `test-util` dans `[dev-dependencies]` de `Cargo.toml` et vérifier que `cargo test --no-run` compile ; ajouter à la fabrique de tâche de test (introduite par `fix-daemon-exit-codes`) un comportement « panique selon un script » (design D3)

## 2. Relance après panic non bloquante

- [ ] 2.1 Remplacer le `sleep` dans la branche panic de `supervise_tasks` par une tâche différée insérée dans le `JoinSet` (design D1), interrompue par le jeton d'annulation, qui journalise « Rule-source task respawned after panic » à la fin du délai, et mettre à jour `handle_to_context` avec le nouvel identifiant ; test `start_paused` : pendant le délai d'une tâche paniquée, une erreur fatale d'une autre tâche est journalisée et comptée sans attendre, et une annulation fait rendre `run` immédiatement (`Ok(())`, aucune relance)
- [ ] 2.2 Test : deux couples qui paniquent simultanément sont relancés chacun après 5 s (temps virtuel total 5 s, pas 10 s), et une tâche en attente de relance empêche la détection « All rule tasks completed unexpectedly »

## 3. Backoff

- [ ] 3.1 Implémenter le backoff par couple (design D2 : 5 s doublé, plafond 300 s, calcul saturant, remise à zéro après 600 s de fonctionnement, `consecutive_panics` dans le log « Respawning rule-source task after panic delay »), sans aucun plafond du nombre de relances ; tests `start_paused` vérifiant la suite 5/10/20/40… plafonnée à 300 s, la remise à zéro après 10 min de fonctionnement stable, et qu'un couple qui panique plus de 10 fois de suite est toujours relancé, `valerter_rule_panics_total` étant incrémenté à chaque panic et `valerter_rule_errors_total` jamais
- [ ] 3.2 Mettre à jour `docs/architecture.md` (puce « Panic recovery » : délai non bloquant, backoff, relance infinie ; corriger la puce « Metric » obsolète sur `valerter_rule_panics_total{rule_name}`) et `docs/metrics.md` (description de `valerter_rule_panics_total` : « auto-restarted with exponential backoff (5 s to 5 min), never abandoned » et exemple d'alerte Prometheus sur son augmentation)

## 4. CHANGELOG et vérification finale

- [ ] 4.1 Ajouter à la section `## [2.1.0]` de `CHANGELOG.md` (la créer si elle n'existe pas) : Fixed (supervision et arrêt non bloqués pendant le délai de relance après panic) et Changed (backoff exponentiel des relances après panic, 5 s à 5 min) ; aucune entrée MIGRATION nécessaire (aucune action de l'exploitant)
- [ ] 4.2 Vérification finale : `cargo fmt --check`, `cargo clippy -- -D warnings` et `cargo test` passent
