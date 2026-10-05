# Design

## Context

Voir proposal.md (Why). Ce design suppose le change `expose-log-fields-to-notifier-templates` implémenté : module de filtres valerter avec `valerter_filters()` / `register()`, environnements d'étage 2 compilés à la construction des notifiers, champ `log` du payload, dépliage unique des champs dans `process_log_line`. État du code vérifié sur `release/2.1.0` (1856d61) pour le reste :

- `TemplateConfig` (`src/config/types.rs:261-268`, `deny_unknown_fields`) → `CompiledTemplate` (`src/config/runtime.rs:61-66`) → `TemplateEngine::render` (`src/template.rs:125-174`) → `RenderedMessage { title, body, email_body_html, accent_color }` (`src/template.rs:37-48`, `#[derive(Debug, Clone, PartialEq)]`), partagé par `Arc<AlertPayload>` entre les files de destination (`src/notify/queue.rs:223`).
- Contrôle `email_body_html` : `validate_email_templates` (`src/preflight.rs:152-200`).
- Validation des templates de règle : `src/config/types.rs:888-931` (syntaxe puis `validate_template_render` pour `title`, `body`, `email_body_html`) ; environnement de validation `validation_env` (`src/config/validation.rs:213`), racine `ValidationRoot` qui masque les globales de l'environnement (`:107-118`).
- Configurations des notifiers : `src/config/notifiers.rs:40-100` (`deny_unknown_fields` sur les quatre types) ; Telegram normalise `parse_mode` (`src/notify/telegram.rs:307-318`).
- Email : `render_body` insère `email_body_html` **ou, à défaut, `body`** en `Value::from_safe_string` (`src/notify/email.rs:454-462`) : le `body` texte n'est **pas** échappé aujourd'hui (seul le message de repli atteint ce chemin, `email_body_html` étant exigé ailleurs).
- API vérifiées dans les sources : minijinja 2.24.0 (`~/.cargo/registry`) et pulldown-cmark 0.13.4 (dernière version stable sur crates.io au 05/10/2026, publiée le 20/05/2026, MSRV 1.71.1, features par défaut `getopts` + `html`).

## Goals / Non-Goals

**Goals:**

- Un corps écrit une fois, en Markdown, rendu correctement sur chaque canal.
- Les valeurs du log ne peuvent jamais devenir du balisage (ni Markdown, ni HTML), quel que soit le canal.
- Sortie `telegram_html` toujours acceptée par l'API Bot (hors troncature, inchangée).
- Compatibilité stricte : sans `body_format: markdown`, aucun envoi ne change (seule exception : l'échappement du `body` texte dans le corps email, qui ne concerne que le message de repli, cf. D9).

**Non-Goals:**

- Bascule du défaut vers `markdown` (3.0).
- Tableaux, troncature sur l'arbre (balises refermées), champs natifs des canaux (attachments `fields`, blocs Slack) : L3.
- MarkdownV2 généré par valerter, partie texte multipart pour l'email, nouveaux connecteurs : L4.
- Mise en forme Markdown de `title` : il reste du texte brut, échappé par chaque rendu.

## Decisions

### D1. `body_format` porté par le template de règle, défaut `text`

Le format décrit la **source** écrite par l'opérateur : c'est une propriété du template, pas du notifier. Enum serde `BodyFormat { Text, Markdown }` en minuscules ; une valeur inconnue est refusée au chargement par serde (`unknown variant ..., expected `text` or `markdown``). Le défaut `text` garantit la compatibilité.

### D2. Auto-échappement Markdown : `AutoEscape::Custom("markdown")` + `set_formatter`

`TemplateEngine` gagne un troisième environnement, `md_env`, avec `set_auto_escape_callback(|_| AutoEscape::Custom("markdown"))` et un formateur :

```rust
env.set_formatter(|out, state, value| {
    if value.is_safe() { return out.write_str(value.as_str().unwrap_or_default()).map_err(Into::into); }
    match state.auto_escape() {
        AutoEscape::Custom("markdown") => out.write_str(&escape_all_ascii_punct(&value.to_string())).map_err(Into::into),
        _ => minijinja::escape_formatter(out, state, value),
    }
});
```

(le code exact reste à l'implémentation : une valeur sûre non chaîne passe par `to_string`). Points vérifiés dans minijinja 2.24 :

- le formateur par défaut **échoue** sur un `AutoEscape::Custom` (`Default formatter does not know how to format to custom format`, `src/utils.rs:122`) : le formateur personnalisé est obligatoire, y compris dans l'environnement de validation (D10) ;
- le filtre `escape`/`e` détecte un mode `Custom` et passe par le formateur de l'environnement (`filters.rs:145-175`) : dans un template `markdown`, `| e` échappe donc en Markdown, pas en HTML, et rend une valeur sûre (pas de double échappement) ; c'est documenté ;
- `| safe` et `| tojson` rendent des valeurs sûres (`Value::from_safe_string`, `filters.rs` `tojson` : « safe for both HTML and JSON »), insérées telles quelles ;
- une valeur indéfinie s'affiche vide (`UndefinedBehavior::Lenient`).

Jeu échappé : **toute la ponctuation ASCII**, chacune préfixée de `\` (CommonMark 0.31.2 §2.4 : tout caractère de ponctuation ASCII peut être échappé, toujours valide). Le source Markdown produit n'est **jamais** envoyé tel quel à un canal : il est analysé par pulldown-cmark puis resérialisé (D5), si bien que la sur-échappe est invisible. `title` est rendu avec l'environnement texte (pas d'échappement), `email_body_html` avec l'environnement HTML, inchangés.

Les filtres valerter s'adaptent au mode : `md_escape` (change précédent) renvoie, sous `Custom("markdown")`, l'échappement complet en valeur sûre (équivalent à l'auto-échappement) ; `code`, `codeblock` et `link` renvoient une valeur sûre sous `Custom("markdown")` et une chaîne ordinaire ailleurs (sinon `{{ x | code }}` dans `email_body_html` injecterait la valeur sans échappement HTML). Le mode se lit par `state.auto_escape()`.

### D3. `code`, `codeblock(lang)`, `link(text, url)`

- `code` : clôture de N+1 backticks (N = plus longue suite de la valeur, minimum 1), espaces de bordure si la valeur commence ou finit par un backtick (CommonMark retire une espace de chaque côté). Un saut de ligne dans un span de code devient une espace (règle CommonMark), documenté.
- `codeblock(lang)` : clôture ```` ``` ```` (ou plus longue que la plus longue suite de backticks de la valeur), langue filtrée sur `[A-Za-z0-9_+.#-]`, contenu brut suivi d'un saut de ligne. Le filtre ne peut pas savoir s'il est en début de ligne : la doc impose de le placer seul sur sa ligne. Un `{{ x }}` brut écrit **dans** une clôture Markdown du template est auto-échappé, donc affiche des barres obliques inverses : documenté, avec `codeblock` comme solution.
- `link` : fonction globale. Destination : encodage pourcentage des espaces, caractères de contrôle, `<`, `>`, `(`, `)` et `\` (le reste de l'URL est laissé intact). **Écart au brief**, qui disait « URL encodée » : encoder toute l'URL casserait `https://` et les requêtes ; seul ce qui casse la syntaxe de destination est encodé. Schémas autorisés `http`, `https`, `mailto` ; sinon texte « texte (url) ». Les rendus appliquent la même liste blanche de schémas aux liens écrits directement dans la source (`[x](javascript:…)`), car un lien littéral du template peut aussi contenir une valeur insérée avec `| safe`.

Les trois rejoignent `valerter_filters()` (et une liste `valerter_functions()` pour `link`) : enregistrés dans tous les environnements, et enveloppés par la validation.

### D4. Analyse : pulldown-cmark 0.13.4 vers un arbre restreint maison

`pulldown-cmark = { version = "0.13.4", default-features = false }` : sans `getopts` (binaire) ni `html` (on écrit nos rendus). Options : `Options::ENABLE_STRIKETHROUGH` seulement (pas de tables, notes, listes de tâches, maths, GFM, attributs de titre). Un module `src/markdown/` convertit le flux d'`Event` en un arbre `Block`/`Inline` limité à la liste blanche :

- `Start/End(Paragraph | Heading | BlockQuote(None) | CodeBlock | List | Item | Emphasis | Strong | Strikethrough | Link | Image)`, `Text`, `Code`, `SoftBreak` (→ saut forcé : les alertes sont orientées lignes, et Mattermost comme Telegram affichent déjà chaque saut de ligne), `HardBreak`, `Rule` ;
- `Html` / `InlineHtml` → `Text` (littéral) ; `Start(HtmlBlock)` → paragraphe de texte ;
- `Image` → lien vers l'URL de l'image, texte = texte alternatif ;
- les autres variantes (`Table*`, `FootnoteReference`, `TaskListMarker`, maths, `DefinitionList*`…, non émises avec ces options) → texte de repli ; `Event` et `Tag` ne sont pas `non_exhaustive` en 0.13.4, le `match` est donc exhaustif et une variante ajoutée par une future version cassera la compilation au lieu de passer en silence.

L'arbre ne dépend pas de pulldown-cmark dans ses types publics : un changement de version de la crate reste local au convertisseur.

### D5. Quatre rendus

Détail normatif dans les specs (`message-templating`, « Rendu … du corps Markdown »). Choix structurants :

- `plain` : aucune marque ; lien « texte (url) » ; listes `- ` / `N. ` ; citation `> ` ; filet `---`.
- `html` (email) : éléments standard de la liste blanche, échappement `& < > " '`, `href` filtré.
- `telegram_html` : balises de la liste de l'API Bot uniquement, toujours équilibrées par construction (écriture depuis l'arbre, jamais par concaténation de chaînes brutes) ; titre en `<b>`, listes en texte (`• `), filet `———`, `<pre><code class="language-x">` pour un bloc avec langue ; texte ré-échappé `&`, `<`, `>` (et `"` dans `href`).
- `markdown` (Mattermost, webhook opt-in) : **resérialisation** de l'arbre, pas passage tel quel de la source. **Écart au brief**, qui prévoyait le passage tel quel : la source contient l'échappement complet de D2 (`10\:49\:35`, `https\:\/\/…`), or le moteur de Mattermost (fork `mattermost/marked`) n'honore que `` \ ` * { } [ ] ( ) # + - . ! _ > | ~ `` (vérifié le 05/10/2026, règle `inline.escape`) et afficherait les autres barres obliques inverses ; de plus le passage tel quel laisserait passer tableaux et HTML que les autres rendus neutralisent. La resérialisation échappe au plus juste, uniquement avec des échappements du jeu Mattermost (spec « Rendu markdown du corps Markdown »), encode `<` en `&lt;` et un `&` d'entité en `&amp;` (lus littéralement par Mattermost comme par CommonMark), et écrit les destinations de lien sans chevrons, encodées comme dans `link`.

### D6. `RenderedMessage` : source + rendus mémoïsés

`RenderedMessage` gagne `body_format: BodyFormat` et `renders: Arc<[OnceLock<String>; 4]>` (un emplacement par `OutputFormat`), plus une méthode `body_for(format) -> BodyText { text: &str, safe: bool }` : `Text` → `body` brut, `safe = false` ; `Markdown` → rendu mémoïsé (`OnceLock::get_or_init` : parse + rendu au premier appel), `safe = matches!(format, Html | TelegramHtml)`. `OnceLock` est `Sync` : deux workers de destination peuvent appeler `body_for` en parallèle sur le même `Arc<AlertPayload>`, le rendu n'est calculé qu'une fois. `PartialEq` devient manuel (compare la source, pas le cache). Alternative écartée : quatre rendus calculés d'avance à l'étage 1 (coût payé même pour un seul notifier, et couplage du moteur de templates à la liste des notifiers).

### D7. Format de sortie par notifier : défauts et formats acceptés

Le trait `Notifier` gagne `fn output_format(&self) -> OutputFormat` ; chaque notifier résout au moment de `from_config` sa clé `format` (enum serde `OutputFormat { Plain, Markdown, Html, TelegramHtml }`, noms `plain`, `markdown`, `html`, `telegram_html`) contre la liste de son type, avec le message d'erreur de la spec.

| Type | Défaut | Acceptés | Justification |
|------|--------|----------|---------------|
| mattermost | `markdown` | `markdown` | Mattermost rend nativement le Markdown ; `plain` y serait réinterprété comme Markdown (un `*` du log redeviendrait de l'emphase) : le seul format sûr est le Markdown échappé. |
| telegram | `telegram_html` (`plain` si `parse_mode` ≠ `HTML`) | `telegram_html`, `plain` | `telegram_html` exige `parse_mode: HTML` (refus explicite sinon) ; `plain` permet `parse_mode: MarkdownV2` avec `{{ body \| mdv2_escape }}`. Pas de `markdown` : le Markdown Telegram n'est pas du CommonMark. |
| email | `html` | `html` | Le message est un `text/html` mono-partie (spec `notifier-email`, « Format du message ») ; une partie texte relève de L4. La clé existe pour l'uniformité et l'évolution. |
| webhook | `plain` | `plain`, `markdown`, `html` | Voir ci-dessous. |

**Défaut du webhook : `plain`.** Le webhook vise des cibles inconnues (PagerDuty, ticketing, passerelles SMS, API maison) dont la majorité n'interprète pas le Markdown ; le corps JSON par défaut est générique. `plain` y donne un texte propre (`web-01 logs (https://…)`), alors que `markdown` y laisserait `**`, `\_` et des destinations de lien. Les cibles Markdown (Discord, Rocket.Chat, GitHub, un Mattermost par webhook générique) déclarent `format: markdown` ; Teams ou une API HTML, `format: html`. Le défaut ne concerne que les alertes `markdown` : une alerte `text` part inchangée.

### D8. Corps vu par les notifiers

Chaque notifier appelle `alert.message.body_for(self.output_format())` : Mattermost met le texte dans `attachments[0].text` ; le webhook dans `body` du JSON par défaut ou dans la variable `body` du `body_template` ; Telegram dans `body` (le template par défaut `{{ body|e }}` reste inchangé : `escape` laisse intacte une valeur sûre, `filters.rs:146`) ; l'email selon D9. Une valeur sûre est passée en `Value::from_safe_string`, une autre en chaîne ordinaire : un `body` `plain` reste échappé par `|e` dans Telegram, et un `body` `html` n'est pas ré-échappé dans le corps email.

### D9. Email : priorité du corps, `email_body_html` facultatif pour `markdown`

Corps : `email_body_html` (sûr) > rendu `html` (sûr) > `body` texte en chaîne ordinaire, donc échappé par l'auto-échappement HTML du template de corps. Ce dernier point **corrige** le code actuel (`src/notify/email.rs:454-462` marque le `body` texte comme sûr) ; seul le message de repli l'atteint aujourd'hui, l'exigence `email_body_html` couvrant les autres cas. Sujet : `body` = `body_for(Plain)` pour une alerte `markdown` (un sujet est du texte). `validate_email_templates` (`src/preflight.rs:152`) ignore les templates `markdown`. **Écart au brief**, qui posait « body texte échappé » comme état existant : c'est une correction apportée par ce change.

### D10. Validation

- Rendu d'essai du `body` d'un template `markdown` dans un `validation_env` doté du même `set_auto_escape_callback` et du même formateur (une fonction `install_markdown_escape(&mut Environment)` partagée avec `TemplateEngine`) : sans cela, la première sortie lèverait l'`InvalidOperation` du formateur par défaut, erreur « dépendante des valeurs » donc avalée, et la passe s'arrêterait en silence, laissant passer tout filtre inconnu placé après. Le formateur reçoit des sentinelles (`TruthyChainable`, qui s'affichent vides) : il les échappe en chaîne vide.
- `code`, `codeblock` enveloppés comme les autres filtres ; `link` ajouté comme globale de `validation_env` (la racine de validation masque les globales, `src/config/validation.rs:113`) et enveloppé de la même façon (argument sentinelle → feuille sentinelle) ; le garde-fou `builtin_filter_wrappers_still_report_unknown_filters` couvre aussi `link`.
- Format : validé à l'instanciation des notifiers (démarrage et `--validate`), messages de la spec ; incohérence `telegram_html` / `parse_mode` refusée dans `TelegramNotifier::from_config`.

### D11. Repli et troncature

Le message de repli d'étage 1 est construit en `BodyFormat::Text` (corps transmis tel quel). La troncature Telegram (4096 points de code, repli texte brut sur `can't parse entities`) s'applique au texte final, inchangée : une coupe au milieu d'une balise du rendu `telegram_html` est rattrapée par le repli existant ; la troncature sur l'arbre est L3.

### D12. Recouvrement avec `expose-log-fields-to-notifier-templates`

Ce change MODIFIE trois requirements que le change précédent modifie aussi : `notifier-webhook` « Rendu du body_template », `notifier-telegram` « Rendu du texte » et `notifier-email` « Rendu du sujet et du corps ». Chaque delta **reprend intégralement la version du change précédent** (variable `log` et scénarios ajoutés compris) et n'y ajoute que la définition de `body` et ses scénarios. Ordre d'archivage obligatoire : `expose-log-fields-to-notifier-templates` d'abord, puis ce change. Les autres requirements touchés ici (`Champs d'un template`, `Échappement HTML de email_body_html`, `Corps HTML obligatoire pour les destinations email`, configurations des notifiers, `Attachment unique`, `Corps JSON par défaut`, `Exigence de email_body_html au démarrage`, `Validations de démarrage dépendant des notifiers`) ne sont pas modifiés par le change précédent. Les filtres de ce change sont des requirements ADDED : « Moteur minijinja et syntaxe Jinja2 », reformulé par le change précédent pour admettre « les filtres et fonctions propres à valerter décrits par cette spécification », n'a pas à être retouché.

## Risks / Trade-offs

- [Nouvelle dépendance d'analyse sur des données en partie externes] → pulldown-cmark est mûr, sans `unsafe` exposé, linéaire en pratique ; entrée bornée (ligne ≤ 1 MiB en amont) ; features par défaut désactivées ; licence MIT compatible Apache-2.0.
- [Coût CPU par alerte] → une analyse et un rendu par format effectivement utilisé, mémoïsés et partagés entre destinations ; négligeable devant un envoi HTTP.
- [Surprise : `| e` échappe en Markdown dans un template `markdown`] → documenté ; c'est le comportement souhaité (échappement du contexte courant).
- [`{{ x }}` dans une clôture Markdown du template affiche des barres obliques inverses] → documenté, `codeblock`/`code` recommandés.
- [Rendu `markdown` moins fidèle à la source (resérialisé)] → sémantiquement équivalent sur la liste blanche ; tests dorés.
- [Troncature Telegram au milieu d'une balise] → repli texte brut existant ; L3.
- [Écarts au brief] → passage tel quel remplacé par une resérialisation (D5), encodage d'URL limité à la syntaxe (D3), échappement du `body` texte email ajouté (D9) : signalés ici et dans le rapport.

## Migration Plan

Aucune action : fonctionnalité opt-in. MIGRATION « Upgrading to 2.1.0 » présente `body_format: markdown`, les formats par défaut, la dispense d'`email_body_html` et l'échappement du `body` texte dans le corps email (message de repli). Retour arrière : supprimer `body_format` et `format` des fichiers de configuration.
