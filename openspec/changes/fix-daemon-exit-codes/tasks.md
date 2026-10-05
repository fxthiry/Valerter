# Tasks

## 1. Configuration sans règle activée

- [ ] 1.1 Dans `Config::validate()` (`src/config/types.rs`, après le contrôle `rules.is_empty()`), ajouter l'erreur `all rules are disabled: enable at least one rule in config.yaml or rules.d/` quand `rules` n'est pas vide et qu'aucune règle n'est activée (design D2) ; tests unitaires : toutes les règles désactivées → erreur signalée (avec les autres erreurs éventuelles, validation exhaustive) ; une règle activée parmi des désactivées → pas d'erreur ; aucune règle → seule l'erreur `no rules defined` est signalée
- [ ] 1.2 Mettre à jour les fixtures et tests existants qui chargent une configuration dont toutes les règles sont désactivées (rechercher `enabled: false` dans `tests/` et `src/`) pour qu'ils restent pertinents

## 2. Fins anormales du moteur et code de sortie

- [ ] 2.1 Introduire dans `src/engine.rs` une fabrique de tâche `pub(crate)` (design D4) utilisée par `spawn_single_rule`, `run_rule` restant l'implémentation par défaut de `RuleEngine::new` ; vérifier que les tests existants de `engine.rs` passent sans modification de comportement
- [ ] 2.2 Ajouter `RuleError::NoEnabledRules` et `RuleError::AllTasksStopped` dans `src/error.rs` (messages `Display` en anglais) et un test de `Display` dans le module de tests existant
- [ ] 2.3 Dans `RuleEngine::run`, renvoyer `Err(NoEnabledRules)` quand aucune tâche n'est lancée (garde défensive) et `Err(AllTasksStopped)` quand le `JoinSet` se vide hors annulation, en passant les deux logs existants au niveau ERROR sans changer leur texte ; mettre à jour `engine_run_no_enabled_rules_exits` et `engine_run_with_empty_rules` pour attendre ces erreurs, et ajouter un test (fabrique de test renvoyant une erreur fatale pour toutes les tâches) qui vérifie `Err(AllTasksStopped)` et l'incrément de `valerter_rule_errors_total`
- [ ] 2.4 Dans `src/main.rs::run`, appeler `cancel.cancel()` dès le retour de `engine.run`, quelle qu'en soit la cause, puis suivre la séquence d'arrêt existante (design D3), en conservant la remontée d'erreur (code 1) ; vérifier que `Ok(())` n'est renvoyé qu'après un arrêt demandé par signal
- [ ] 2.5 Ajouter un test d'intégration dans `tests/` (modèle `integration_validate.rs` : binaire construit une fois) avec une fixture dont toutes les règles sont désactivées : `valerter --validate` sort avec le code 1 et sa sortie d'erreur contient `all rules are disabled` ; le lancement du démon sur la même fixture sort avec le code 1 et le même message, sans tenter de démarrer le moteur
- [ ] 2.6 Mettre à jour `docs/architecture.md` (section « Key properties » : comportement de fin, code de sortie, relance systemd) et vérifier que la doc ne mentionne plus de sortie en code 0 hors arrêt par signal ni de démarrage possible avec toutes les règles désactivées

## 3. Scripts Debian

- [ ] 3.1 Modifier `debian/prerm` pour ne plus arrêter le service sur `upgrade` (garder `remove` et `deconfigure`)
- [ ] 3.2 Modifier `debian/postinst` pour, sur mise à jour (`$2` non vide), redémarrer le service si `systemctl is-active` ou `systemctl is-enabled`, puis, uniquement si un redémarrage a été lancé, `sleep 2` et `systemctl is-active --quiet valerter ||` afficher sur la sortie d'erreur un avertissement bien visible indiquant `journalctl -u valerter`, le script sortant en 0 dans tous les cas (design D5) ; ne pas appeler `valerter --validate` ; vérifier avec `sh -n` sur les deux scripts et `shellcheck` s'il est disponible
- [ ] 3.3 Vérifier sur une VM ou un conteneur Debian avec systemd : `cargo deb`, installation 2.0.3 activée puis mise à jour vers le nouveau paquet → service actif avec le nouveau binaire (`systemctl status`, `valerter --version`) ; même mise à jour avec une configuration rendue invalide → avertissement affiché sur la sortie d'erreur et `dpkg` termine avec succès ; service désactivé et arrêté → reste arrêté ; première installation → rien n'est démarré
- [ ] 3.4 Mettre à jour `docs/getting-started.md` (section « Updating » : le `systemctl restart` manuel n'est plus nécessaire pour un service activé ; avertissement affiché si le service ne redémarre pas ; cas d'un service démarré à la main sans être activé lors de la mise à jour depuis ≤ 2.0.3)

## 4. CHANGELOG, MIGRATION et vérification finale

- [ ] 4.1 Ajouter à la section `## [2.1.0]` de `CHANGELOG.md` (la créer si elle n'existe pas) : Fixed (code de sortie 1 et arrêt sans attente quand plus aucune tâche ne tourne, relance du service après mise à jour du `.deb` avec avertissement en cas d'échec) et Changed (configuration sans règle activée refusée par la validation et par `--validate`)
- [ ] 4.2 MIGRATION : ajouter à la section « Upgrading to 2.1.0 » de `MIGRATION.md` (la créer si elle n'existe pas) : une configuration dont toutes les règles sont désactivées est désormais refusée (désactiver le service plutôt que toutes les règles) ; la boucle de relance systemd sur configuration invalide existe déjà (code 1, relance toutes les 5 s par `Restart=on-failure`) et s'applique désormais aussi à ce cas ; un code de sortie dédié avec `RestartPreventExitStatus` est hors périmètre de cette version ; alertes possibles sur le code de sortie / l'état `failed` ; redémarrage automatique des services activés lors des mises à jour
- [ ] 4.3 Vérification finale : `cargo fmt --check`, `cargo clippy -- -D warnings` et `cargo test` passent ; lancement manuel du démon avec une configuration dont toutes les règles sont désactivées → code 1 immédiat avec le message de validation
