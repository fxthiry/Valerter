# Proposal

## Why

Le `body` d'un template de règle est une seule chaîne envoyée à des canaux qui parlent des dialectes différents : Markdown pour Mattermost, sous-ensemble HTML pour Telegram (`parse_mode: HTML`), HTML pour l'email, n'importe quoi pour un webhook. Aujourd'hui, un `body` écrit en Markdown s'affiche avec ses `**` sur Telegram, et une valeur du log contenant `_`, `*`, `<` ou `&` casse la mise en forme ou fait rejeter le message (Grafana #49200, Robusta #1982, Apprise #1764) : balisage et données sont mêlés dans la même chaîne, puis échappés au mauvais niveau, ou pas du tout. Le change `expose-log-fields-to-notifier-templates` permet de contourner le problème notifier par notifier ; ce change (L2 de l'issue #24) le règle à la source pour 2.1.0 : un corps écrit une fois en Markdown, valeurs échappées automatiquement, rendu par valerter dans le format de chaque canal.

Il dépend du change `expose-log-fields-to-notifier-templates` (filtres valerter, environnements d'étage 2 compilés, contexte `log`) et s'implémente après lui.

## What Changes

- Nouveau champ optionnel `body_format: text | markdown` sur les templates de règle, défaut `text` : avec `text`, comportement strictement inchangé ; avec `markdown`, le `body` est un Markdown source dont chaque valeur insérée (`{{ … }}`) est échappée automatiquement (`| safe` pour désactiver). `title` reste du texte brut.
- Filtres et fonction sûrs pour composer du Markdown à partir de valeurs : `code` (span de code), `codeblock(lang)` (bloc de code), `link(text, url)`.
- valerter analyse ce Markdown (nouvelle dépendance `pulldown-cmark`) en un sous-ensemble restreint (paragraphe, saut de ligne, gras, italique, barré, code, bloc de code, lien, citation, liste, titre, filet ; HTML brut et tableaux rendus comme texte) et le rend dans le format de chaque notifier : `plain`, `html`, `telegram_html` ou `markdown` (resérialisé avec un échappement compatible Mattermost).
- Nouvelle clé `format` par notifier, validée au démarrage et par `--validate`, avec un format par défaut par type : Mattermost `markdown` ; Telegram `telegram_html` (ou `plain` si `parse_mode` n'est pas `HTML`) ; email `html` ; webhook `plain`. Formats acceptés : Mattermost `markdown` ; Telegram `telegram_html`, `plain` ; email `html` ; webhook `plain`, `markdown`, `html`.
- Pour une alerte `markdown`, le `body` vu par les notifiers (texte de l'attachment Mattermost, JSON par défaut du webhook, variable `body` des `body_template`) est le rendu dans le format du notifier ; les rendus `html` et `telegram_html` sont déjà échappés, si bien que le template Telegram par défaut (`{{ body|e }}`) fonctionne sans modification.
- Email : priorité `email_body_html` > rendu `html` du corps Markdown > `body` texte échappé ; un template `markdown` n'a plus besoin d'`email_body_html` pour une destination email. Le `body` texte n'est plus inséré sans échappement dans le corps email (seul le message de repli était concerné).
- Rendu d'essai de validation adapté aux corps Markdown et aux nouveaux filtres.
- Documentation (`docs/configuration.md`, `docs/notifiers.md`) et CHANGELOG `[2.1.0]` (Added, Fixed) ; MIGRATION inchangé : aucune rupture, fonctionnalité opt-in.

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `message-templating` : champ `body_format` ; échappement Markdown automatique et son opt-out ; filtres `code`, `codeblock` et fonction `link` ; sous-ensemble Markdown reconnu ; rendus `plain`, `html`, `telegram_html` et `markdown` ; rendu d'essai des corps Markdown ; `email_body_html` facultatif pour un template `markdown`.
- `notification-dispatch` : format de sortie par notifier (clé `format`, défauts, formats acceptés) ; corps transmis aux notifiers selon ce format.
- `notifier-mattermost` : clé `format` ; texte de l'attachment issu du rendu `markdown` pour une alerte Markdown.
- `notifier-webhook` : clé `format` ; `body` du JSON par défaut et du `body_template` issu du rendu du format.
- `notifier-telegram` : clé `format` ; cohérence avec `parse_mode` ; `body` du texte issu du rendu du format.
- `notifier-email` : clé `format` ; priorité du corps ; `email_body_html` facultatif pour un template Markdown.
- `configuration` : contrôle de démarrage `email_body_html` limité aux templates `text`.

## Impact

- Code : `src/config/types.rs` (`TemplateConfig.body_format`), `src/config/runtime.rs` (`CompiledTemplate`), `src/config/notifiers.rs` (clé `format` des quatre types), `src/config/validation.rs` et `src/config/types.rs` (rendu d'essai Markdown, garde-fou), `src/preflight.rs` (contrôle `email_body_html`), `src/template.rs` (environnement Markdown, `RenderedMessage`), nouveau module de rendu Markdown (`src/markdown/`), module de filtres (ajouts), `src/notify/{traits,mattermost,webhook,telegram,email}.rs`.
- Dépendance : `pulldown-cmark = { version = "0.13.4", default-features = false }` (MIT, Rust pur, MSRV 1.71.1 ; compatible musl et cargo-deb).
- Documentation : `docs/configuration.md`, `docs/notifiers.md`, `config/config.example.yaml`, `CHANGELOG.md`.
- Compatibilité : opt-in ; une configuration sans `body_format` ni `format` produit des envois identiques à 2.1.0 sans ce change.
- Hors périmètre (issue #24) : bascule du défaut vers `markdown` (envisagée en 3.0), L3 (champs natifs des canaux, troncature sur l'arbre, tableaux), L4 (nouveaux connecteurs, MarkdownV2 natif pour Telegram, multipart texte pour l'email).
