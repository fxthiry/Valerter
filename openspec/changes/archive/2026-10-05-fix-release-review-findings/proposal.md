# Proposal

## Why

La relecture finale de `release/2.1.0` a relevé des défauts vérifiés dans le code : des templates invalides acceptés par `--validate` (règle throttlée comme un seul compteur en production), des doubles livraisons, des secrets de source dans les logs, des sorties d'erreur non structurées, un paquet Debian qui peut supprimer le binaire d'un service en cours de redémarrage, des replis Telegram/Mattermost trop larges, ainsi qu'une documentation et des specs qui décrivent un comportement qui n'est plus celui du code. Tout doit être corrigé avant la publication de 2.1.0, encore non publiée.

## What Changes

- **Rendu d'essai des templates** : le rendu de validation ne s'arrête plus sur une conversion (`| int`, `| float`, `| round`, `| abs`) ni sur un filtre intégré appliqué à un champ (`| split`, `| upper`, `| items`…), et il est effectué deux fois (conditions vraies et boucles à un élément, puis conditions fausses, boucles vides et `is defined` faux) pour couvrir les branches `else`, `{% if not x %}`, `is not defined` et les corps de `{% for %}`. **BREAKING (par rapport aux préversions 2.1.0 uniquement)** : des templates jusqu'ici acceptés par erreur (filtre inconnu après `| int`, dans un `else` ou un corps de boucle) sont refusés. La limite restante (arithmétique sur un champ brut, corps des `elif`) est documentée.
- **Indice `/`** : `{{ total/count }}` (division entre deux identifiants simples) n'est plus refusé ; l'indice reste produit pour les chemins pointés de l'issue #41.
- **Destinations en double** : `notify.destinations: [mm, mm]` est refusé à la validation (comme les doublons de `vl_sources`).
- **`${VAR}`** : substitution en une seule passe (une valeur substituée n'est plus re-substituée).
- **Logs de streaming** : l'URL de source n'apparaît plus que masquée et les erreurs de transport sont journalisées sans URL.
- **Ordre déterministe** des erreurs `Notifier configuration error` (par nom de notifier) et de l'en-tête de webhook invalide signalé (ordre alphabétique).
- **Paquet Debian** : `prerm remove` arrête toujours le service (même en `activating (auto-restart)`) et le désactive avant la suppression des fichiers ; `postinst` ne touche à systemd que si systemd est le gestionnaire actif.
- **Sorties fatales** : toute erreur fatale passe par les logs (respecte `--log-format json`), plus de ligne `Error: …` non structurée ; la destruction du runtime n'attend pas plus de 2 s des tâches bloquantes.
- **Corps des réponses non-2xx de VictoriaLogs** lu de façon bornée (taille et durée).
- **`valerter_vl_source_up`** initialisée seulement pour les sources ciblées par au moins une règle activée.
- **Repli Telegram** limité aux 400 dont la description contient `can't parse entities` (insensible à la casse).
- **Repli Mattermost** : sur un 4xx (≠ 429) avec le canal de la règle, renvoi avec le `channel` du notifier s'il existe (et diffère), sinon sans `channel`.
- **Destination inconnue à l'exécution** : comptée comme tout échec définitif (`valerter_notify_errors_total` et `valerter_alerts_failed_total`, labels habituels, `notifier_type="unknown"`).
- **Documentation** : `docs/metrics.md`, `docs/architecture.md`, `docs/configuration.md`, `docs/getting-started.md`, `docs/notifiers.md`, `config/config.example.yaml`, `README.md`, et les entrées 2.1.0 de `CHANGELOG.md` et `MIGRATION.md` corrigées.
- **Specs** alignées sur les messages et comportements réels du code.
- **Nettoyage** : variantes `RuleError` jamais construites, `TailClient::connect_and_receive` (tests migrés vers `stream_with_reconnect`), tests mal nommés ou qui ne testent rien, test d'inventaire des métriques recopié à la main, WARN JSON non vérifié.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `message-templating` : rendu d'essai en deux passes avec filtres intégrés permissifs ; indice `/` limité aux chemins de champ.
- `configuration` : validation des templates (limites), destinations sans doublon, substitution `${VAR}` en une passe, ordre déterministe des erreurs de notifiers.
- `throttling` : la validation de `throttle.key` détecte un filtre inconnu après une conversion.
- `notification-dispatch` : message `invalid configuration:` des variables non définies ; destination inconnue comptée comme échec définitif.
- `notifier-webhook` : messages d'erreur réels (`invalid configuration:`, `body_template: <détail>`), échappement `{{ '$' }}{VAR}`, limite des messages d'erreur de syntaxe.
- `notifier-mattermost` : message `invalid configuration:` ; repli sur le canal du notifier.
- `notifier-telegram` : repli en texte brut limité aux erreurs d'analyse des entités.
- `observability` : `vl_source_up` limité aux sources ciblées, anti-rebond sans « fin de flux », URL de source masquée dans les logs.
- `victorialogs-streaming` : lecture bornée du corps des réponses non-2xx.
- `rule-engine` : erreurs fatales journalisées, arrêt du runtime borné, fin inattendue des tâches avec vidage, scripts Debian.

## Impact

- Code : `src/config/validation.rs`, `src/config/types.rs`, `src/config/env.rs`, `src/tail.rs`, `src/notify/{registry,webhook,telegram,mattermost,queue}.rs`, `src/main.rs`, `src/metrics.rs`, `src/lib.rs`, `src/error.rs`, `src/engine.rs`, `debian/{prerm,postrm,postinst}`.
- Tests : `tests/integration_streaming.rs`, `tests/integration_notify.rs`, `tests/metrics_snapshot.rs`, `tests/integration_validate.rs`, `tests/integration_exit_codes.rs`, `tests/common/`.
- Aucune nouvelle dépendance. Pas de changement de version (`Cargo.toml`, date du CHANGELOG : étape de release séparée). L'agrégation de `valerter_vl_source_up` n'est pas refondue, seulement documentée.
