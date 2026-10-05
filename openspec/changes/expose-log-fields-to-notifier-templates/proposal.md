# Proposal

## Why

Les templates propres aux notifiers (`body_template` webhook, Telegram et email, `subject_template` email) ne voient que `title`, `body`, `rule_name`, `vl_source` et les horodatages : aucun champ du log. Pour mettre en forme une valeur (gras, code, lien, objet JSON structuré), l'opérateur doit donc la cuire dans `body` au niveau du template de règle, là où il ignore vers quel canal elle partira : c'est le mélange balisage/données que décrit l'issue #24 (même famille de bugs que Grafana #49200, Alertmanager #2923 ou Apprise #1764). La documentation Telegram aggrave le problème : elle conseille de mettre du HTML dans `body` alors que le template par défaut l'échappe (`{{ body|e }}`), si bien que les balises s'affichent telles quelles.

Ce change pose les deux premières marches de l'issue #24 (L0 + L1) pour 2.1.0 : corriger ce conseil et donner aux templates de notifier un accès direct, sûr et échappable aux champs du log. Il est le socle du change `markdown-body-format` (L2).

## What Changes

- **L0 — documentation Telegram** : `docs/notifiers.md` et `config/config.example.yaml` ne conseillent plus de mettre du HTML dans `body` avec le template par défaut ; ils montrent le balisage écrit dans `body_template` et les valeurs échappées une à une (`{{ log.host | e }}`), et renvoient vers `body_format: markdown` (change `markdown-body-format`) et l'issue #24.
- **L1 — variable `log`** dans les templates de notifier (`body_template` webhook, Telegram et email, `subject_template` email) : objet contenant tous les champs de l'événement parsé, dans la même vue dépliée qu'au niveau du template de règle (`{{ log.host }}`, `{{ log.k8s.pod }}`, `{{ log["k8s.pod"] }}`), sans collision avec `title`/`body`. Le template de règle (`title`, `body`, `email_body_html`, `throttle.key`) reste inchangé : `log` n'y est pas injecté.
- **Filtres d'échappement** propres à valerter, disponibles dans tous les templates : `md_escape` (Markdown CommonMark, jeu de caractères compatible Mattermost) et `mdv2_escape` (Telegram MarkdownV2). L'échappement HTML reste `| e`.
- Le payload d'alerte transporte les champs du log (partagés entre destinations, jamais copiés par destination) ; ils ne sont **jamais journalisés** (représentation de débogage comprise).
- Les templates de notifier sont compilés une seule fois, à la construction du notifier, au lieu d'être recompilés à chaque envoi.
- Le rendu d'essai de validation prend en charge les nouveaux filtres (une erreur après `md_escape` reste détectée) ; un **avertissement** est journalisé au démarrage et par `--validate` quand un template de notifier référence une variable de premier niveau inexistante à ce niveau (ex. `{{ host }}` au lieu de `{{ log.host }}`).
- Documentation (`docs/notifiers.md`, `docs/configuration.md`, exemple PagerDuty `custom_details` construit avec `log`), CHANGELOG `[2.1.0]` (repassé en `Unreleased`, la release étant repoussée) et MIGRATION « Upgrading to 2.1.0 ».
- Aucune rupture de compatibilité : un template existant se rend à l'identique.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `message-templating` : filtres propres à valerter autorisés en plus des filtres intégrés ; nouveaux filtres `md_escape` et `mdv2_escape` ; variable `log` dans les templates de notifier ; rendu d'essai des nouveaux filtres ; avertissement sur les variables inconnues des templates de notifier.
- `notification-dispatch` : le payload d'alerte transporte les champs du log ; ces champs ne sont jamais journalisés.
- `notifier-webhook` : `log` ajouté au contexte du `body_template`.
- `notifier-telegram` : `log` ajouté au contexte du texte.
- `notifier-email` : `log` ajouté aux contextes du sujet et du corps (échappé en HTML dans le corps).

## Impact

- Code : `src/notify/payload.rs` (champ `log`, `Debug` manuel), `src/engine.rs` (`process_log_line` : dépliage unique des champs, partagé avec l'étage 1), `src/template.rs` (rendu à partir du contexte déplié, enregistrement des filtres), nouveau module de filtres (`src/template/filters.rs` ou équivalent), `src/notify/{telegram,webhook,email}.rs` (environnement compilé à la construction, `log` dans le contexte), `src/throttle.rs` (filtres), `src/config/validation.rs` (rendu d'essai, garde-fou, avertissement), tests unitaires et d'intégration.
- Documentation : `docs/notifiers.md`, `docs/configuration.md`, `config/config.example.yaml`, `CHANGELOG.md`, `MIGRATION.md`.
- Dépendances : aucune nouvelle.
- Mémoire : chaque alerte en file conserve ses champs (partagés par `Arc` entre destinations, au plus 100 alertes par destination).
- Hors périmètre (suites de l'issue #24) : `body_format: markdown` (change `markdown-body-format`), L3 (champs natifs des canaux, troncature sur l'arbre), L4 (nouveaux connecteurs).
