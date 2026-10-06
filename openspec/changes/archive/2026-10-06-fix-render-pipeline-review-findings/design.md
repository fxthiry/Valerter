# Design

## Context

Voir proposal.md (Why) pour la motivation et les specs du change pour les exigences. État du code sur `release/2.1.0` (896dbf0) :

- `src/markdown/parse.rs` : `Builder` empile un `Frame` par `Event::Start` (`Builder::start`, l.210) sans limite ; la pile est un `Vec` (itératif), mais l'arbre produit (`Vec<Block>`/`Vec<Inline>` imbriqués) est ensuite parcouru récursivement par `one_line` (l.129), `block_inlines` (l.99), les rendus de `src/markdown/render.rs` (`plain_inlines` l.174, `Html::blocks` l.248 / `Html::inlines` l.334, `md_blocks` l.396, `md_inlines` l.571, `md_wrap` l.629) et par les `Drop`/`Clone`/`PartialEq` dérivés. Une profondeur de 20 000 suffit à épuiser une pile de 2 Mio (taille par défaut des workers Tokio) : abandon du processus, que la supervision des tâches ne rattrape pas.
- `src/parser.rs:311` `insert_nested` est récursif sur les segments d'une clé pointée ; il est désormais appelé à chaque alerte via `AlertPayload::log_from_fields` (`src/notify/payload.rs:48`, appelé par `src/engine.rs:763`). Le `serde_json::Value` produit est ensuite converti (`Value::from_serialize`) puis détruit, deux autres parcours récursifs.
- `src/template/filters.rs` : le formateur Markdown (l.80-89) écrit tel quel toute valeur sûre ; `code`, `codeblock` (l.119-135) et `link` (l.141-154) renvoient du Markdown marqué sûr, inséré dans la source avant l'analyse ; `tojson` (intégré à minijinja) renvoie aussi une chaîne sûre.
- `src/template/mod.rs` : `render_with` (l.380) appelle `env.render_str` ; `RenderedMessage::body_for` (l.106) analyse `body` à la demande par format (`crate::markdown::render`).
- `src/notify/telegram.rs` : `truncate_text` (l.83) coupe le texte brut à 4096 points de code ; `prepare_text` (l.379) l'applique au rendu du `body_template` ; `send_to_chat` (l.404) renvoie le même texte sans `parse_mode` sur `can't parse entities` (l.433).
- minijinja 2.24 (verrouillé) fournit `State::get_or_set_temp_object`, `Template::render_and_return_state`, les objets dynamiques (`Value::from_object`, `downcast_object_ref`) et, derrière la feature `urlencode`, le filtre `urlencode` (dépendance `percent-encoding` 2.3.2, déjà dans `Cargo.lock`).

## Goals / Non-Goals

**Goals:**
- Aucune ligne de log, jusqu'à `MAX_LINE_SIZE` (1 Mio), ne peut arrêter le processus par débordement de pile, quel que soit le template.
- Aucune valeur du log ne devient du balisage actif sans `| safe` explicite, quel que soit l'emplacement des filtres Markdown dans le template.
- Ce que valerter envoie à Telegram en `parse_mode: HTML` respecte la syntaxe et les règles d'imbrication de l'API Bot, y compris après troncature.

**Non-Goals:**
- Neutraliser l'auto-détection côté client (URL nues, `@channel`, `#hashtag`) : documentée, pas filtrée (constat 11), comme en mode `text`.
- Changer la troncature des `parse_mode` MarkdownV2 et Markdown, ou le comptage en UTF-16 (voir Risks).
- Relever la taille de pile des workers Tokio : la borne doit tenir sur la pile par défaut.

## Decisions

### D1. Profondeur bornée à l'analyse (constat 1)

`MAX_DEPTH = 32` éléments ouverts (racine exclue). Dans `Builder::start`, si `stack.len() > MAX_DEPTH`, le `Kind` calculé est remplacé par `Kind::Transparent` : le cadre est empilé (pour rester apparié avec son `Event::End`) mais, à sa fermeture, ses blocs et inlines sont reversés au parent ; le texte est conservé, l'élément perdu. Un `Item` devenu transparent sous une `List` qui ne l'est pas pousse son contenu dans `Frame::blocks` de la liste, que `Kind::List` ignore aujourd'hui à la fermeture : la fermeture d'une `List` ajoute donc ces blocs et inlines reçus directement (cas possible uniquement via des enfants transparents) comme un dernier élément, pour ne perdre aucun texte. Un `CodeBlock` devenu transparent voit son texte reçu par `text()` comme inlines (le `match` sur `top.kind` le traite déjà ainsi).

Ainsi l'arbre a une profondeur ≤ 32 : tous les parcours récursifs (rendus, `one_line`, `block_inlines`, `Drop`, `Clone`, `PartialEq`) sont bornés sans être réécrits en itératif. La pile de `Builder` reste un `Vec` sur le tas (50 000 cadres vides ≈ quelques Mo, transitoires).

Alternatives écartées : réécrire chaque rendu en itératif (six fonctions, plus le `Drop` manuel des deux énumérations) — coûteux et fragile ; limiter la longueur de la source — ne borne pas la profondeur (`>`×20 000 = 40 Ko). 32 suffit largement à un message d'alerte et reste loin de la pile (un niveau de rendu coûte quelques centaines d'octets en debug).

pulldown-cmark 0.13 analyse dans un arbre en arène parcouru itérativement ; les tests de D1 (50 000 niveaux sur un fil de 2 Mio) le vérifient. Si l'un d'eux débordait encore avec la borne en place, le débordement viendrait de la crate : le test le montrera et la tâche correspondante prévoit alors une garde sur la source (voir tasks 1.4).

### D2. Dépliage des clés pointées borné (constat 2)

`MAX_DOTTED_SEGMENTS = 32`. Dans `unflatten_dotted_keys`, une clé dont `split('.')` donne plus de 32 segments n'est pas dépliée : elle reste plate dans `out` (déjà cloné), avec `tracing::warn!(conflicting_key = <clé tronquée à 128 octets>, segments, "skipping dotted-key expansion: too many segments")`. La récursion d'`insert_nested` est alors bornée à 32 ; la conversion `from_serialize` et le `Drop` du `serde_json::Value` aussi (la profondeur du JSON de la ligne est déjà bornée à 128 par serde_json). La clé est tronquée dans le journal pour ne pas écrire 40 Ko par alerte.

Alternative écartée : rendre `insert_nested` itératif — corrige la récursion mais laisse un objet de 20 000 niveaux que `from_serialize`, le rendu (`tojson`) et le `Drop` parcourent récursivement.

### D3. Jetons de substitution des filtres Markdown (constat 3)

**Principe.** Dans un environnement Markdown (`in_markdown(state)`), `code`, `codeblock` et `md_link` ne renvoient plus du Markdown mais un objet `MarkdownElement` (`Value::from_object`) :

```text
enum MarkdownElement { Code(String), CodeBlock { lang: String, text: String }, Link { text: String, dest: String }, Text(String) }
```

`md_link` avec un schéma refusé renvoie `Text("text (url)")` ; `code` d'une valeur vide renvoie la chaîne vide (comportement actuel, valeur fausse) ; hors environnement Markdown, les trois renvoient la chaîne Markdown actuelle, inchangée. Le `Display` de l'objet (`Object::render`) écrit le Markdown actuel (span, bloc clôturé, `[texte](url)`) : c'est ce qu'obtient toute conversion en chaîne (`~`, `| upper`, `| e`, `{% autoescape false %}`), donc une chaîne ordinaire, échappée ensuite comme une valeur (comportement identique à aujourd'hui pour une chaîne sûre combinée).

**Émission du jeton.** Le formateur Markdown, recevant un `MarkdownElement`, l'ajoute à la liste d'emplacements du rendu en cours — `state.get_or_set_temp_object::<Slots, _>("valerter.markdown.slots", Slots::default)`, `Slots(Mutex<Vec<MarkdownElement>>)` — et écrit le jeton `U+E000 <index décimal ASCII> U+E001`.

**Caractères choisis.** U+E000 et U+E001, premiers points de code de la zone d'usage privé du BMP : catégorie Unicode `Co`, ni ponctuation ni espace pour CommonMark, donc lus comme des lettres (une emphase autour d'un jeton s'ouvre et se ferme comme autour d'un mot), jamais produits par pulldown-cmark, encodés sur 3 octets en UTF-8. Les chiffres entre les deux ne peuvent pas ouvrir de liste ordonnée puisqu'ils suivent U+E000.

**Neutralisation dans les valeurs.** `markdown::escape` (utilisé par le formateur pour toute valeur non sûre, par `md_escape` en mode Markdown et pour le texte de `md_link`) remplace U+E000 et U+E001 par U+FFFD. Aucune valeur du log ne peut donc produire un jeton sans `| safe`. Les chaînes sûres sont écrites telles quelles, jetons compris : c'est ce qui permet aux captures `{% set x %}…{% endset %}` et aux macros (sorties sûres contenant des jetons du même rendu) de fonctionner. Une valeur passée par `| safe` est par définition de confiance ; au pire elle désigne un emplacement existant, ce qui duplique un contenu littéral, sans balisage. `tojson` n'étant plus sûr (D4), il ne contourne pas la neutralisation.

**Récupération.** `render_with` pour l'environnement Markdown devient `env.template_from_str(source)?.render_and_return_state(ctx)` ; les emplacements sont lus sur l'état (`get_temp` + `downcast_object`) et stockés dans `RenderedMessage` (nouveau champ `slots: Arc<[MarkdownElement]>`, vide pour un corps `text` et pour le message de repli ; inclus dans `PartialEq`). `body_for` appelle `markdown::render(&self.body, &self.slots, format)` ; `parse(source, slots)` applique la substitution. Le rendu d'essai (`validation_env` avec `markdown: true`) utilise le même formateur ; les emplacements y sont simplement ignorés.

**Substitution après l'analyse.** Une passe sur l'arbre (profondeur bornée par D1) cherche les jetons `U+E000 [0-9]+ U+E001` dans le texte :

| Emplacement du jeton | `CodeBlock` | `Code` | `Link` | `Text` |
|---|---|---|---|---|
| Inline enfant direct d'un `Paragraph`/`Plain` | le bloc est coupé : inlines avant (blancs et sauts de fin retirés), `Block::CodeBlock`, inlines après ; parties vides omises | `Inline::Code` | `Inline::Link { dest, children: [Text(text)] }` | `Inline::Text` |
| Inline dans `Strong`/`Emphasis`/`Strikethrough`/`Link` ou dans un `Heading` | `Inline::Code(text)` (sauts de ligne → espaces, comme `code`) | idem | idem (un lien dans un lien est déjà rendu en texte par les rendus) | idem |
| Texte d'un `CodeBlock` du template (clôturé ou indenté) | texte brut | contenu | `text (url)` | texte |
| Destination d'un lien du template | texte brut (encodé par les rendus) | contenu | `url` | texte |
| Langue d'un bloc de code | supprimé (`sanitize_lang` filtrerait déjà ces caractères) | | | |
| Index inconnu (jeton écrit dans la source du template) | U+FFFD | | | |

`Block::CodeBlock.text` respecte l'invariant actuel (se termine par un saut de ligne sauf s'il est vide). Les blocs `HtmlBlock` devenant des paragraphes de texte, leurs jetons suivent la première ligne du tableau. Aucun cas ne rend une partie du contenu comme du Markdown actif : les « contextes dégradés » (bloc impossible) donnent du code en ligne ou du texte littéral.

Alternatives écartées : jeton autoporteur (contenu encodé dans des caractères d'usage privé, sans état) — multiplie la taille par 4 et reste falsifiable ; *nonce* aléatoire par rendu — inutile une fois les valeurs non sûres neutralisées ; exiger « seul sur sa ligne » et le valider — impossible à vérifier statiquement (`{% if %}`, boucles) et ne couvre pas les listes et citations.

### D4. `tojson` non sûr en Markdown (constat 4)

Ajout de `("tojson", tojson)` à `valerter_filters()` : l'enveloppe appelle `minijinja::filters::tojson(value, indent, kwargs)` puis, si `in_markdown(state)`, renvoie `Value::from(result.to_string())` (chaîne non sûre, donc échappée et neutralisée par le formateur) ; sinon elle renvoie le résultat intact (sûr, comme aujourd'hui dans `email_body_html` et les `body_template` JSON). Enregistrée après les intégrés, elle les remplace dans les trois environnements de production et dans `validation_env` (qui chaîne `builtin_filters()` puis `valerter_filters()`). `| safe` reste la seule échappatoire, ce que la doc dit désormais explicitement.

### D5. Troncature Telegram consciente du HTML (constat 5)

`truncate_text(text, html: bool)` ; `html` vaut `parse_mode == "HTML"`, quel que soit `format` : le texte envoyé est du HTML dès que `parse_mode` est HTML (le template par défaut produit `<b>…</b>` et des entités même en `format: plain`), ce qui élargit légèrement le constat (formulé pour `telegram_html`).

Algorithme (une passe de comptage, une passe de copie si nécessaire) :
- `<` suivi d'un `>` plus loin : balise, zéro caractère visible ; ouvrante (`<nom …>`) → `nom` (minuscules, jusqu'au premier blanc, `>` ou `/`) empilé ; fermante (`</nom>`) → dépile jusqu'au `nom` correspondant s'il est dans la pile, ignorée sinon. Un `<` sans `>` compte comme un caractère visible (texte mal formé : Telegram le rejettera, le repli s'en charge).
- `&` suivi de `#[0-9]{1,7};`, `#x[0-9A-Fa-f]{1,6};` ou `[A-Za-z][A-Za-z0-9]{0,31};` : entité, un caractère visible, jamais coupée ; sinon `&` compte un.
- Tout autre point de code compte un.
- Si le total visible ≤ 4096 : texte inchangé, pas de métrique. Sinon copie jusqu'au 4095ᵉ caractère visible (frontière de balise ou d'entité), ajout de `…`, puis `</nom>` pour chaque nom encore empilé, du plus interne au plus externe (`<pre><code class=…>` → `</code></pre>`, `<a href=…>` → `</a>`, `<span class="tg-spoiler">` → `</span>`). Les balises fermantes n'ajoutent aucun caractère visible.

Repli en texte brut : le texte de renvoi est calculé une fois par alerte (avec le texte HTML) : pour `body_format: markdown`, `titre + "\n" + body_for(Plain)` (titre omis s'il est vide), tronqué en mode brut ; sinon le texte HTML envoyé, comme aujourd'hui. Ajouter le titre reproduit la structure du template par défaut ; ré-rendre le `body_template` avec le corps `plain` a été écarté (les balises du template et le `| e` du corps s'afficheraient littéralement en texte brut), de même que retirer les balises du HTML rejeté par regex (le HTML rejeté est par hypothèse mal formé : une regex mangerait le texte situé entre un `<` nu et le `>` suivant).

### D6. Règle d'imbrication Telegram (constat 6)

Texte officiel (https://core.telegram.org/bots/api#formatting-options, consulté le 06/10/2026) :

> Message entities can be nested, providing following restrictions are met:
> - If two entities have common characters, then one of them is fully contained inside another.
> - bold, italic, underline, strikethrough, and spoiler entities can contain and can be part of any other entities, except pre and code.
> - blockquote and expandable_blockquote entities can't be nested.
> - All other entities can't contain each other.

Le texte laisse ambigu le statut de `blockquote` vis-à-vis de « all other entities ». L'implémentation de référence (tdlib, `are_entities_valid` dans `td/telegram/MessageEntity.cpp`) le tranche : `pre`/`code` ne contiennent rien et ne peuvent être contenus que par un `blockquote` ; un lien (entité « continue ») ne peut contenir ni lien ni `blockquote` ; un `blockquote` ne contient pas de `blockquote` ; deux entités de même type ne s'imbriquent pas. Règle retenue pour `telegram_html`, appliquée par `Html` quand `telegram` est vrai :

| Parent → enfant | `b`/`i`/`s` | `a` | `code`/`pre` | `blockquote` |
|---|---|---|---|---|
| racine, élément de liste | oui | oui | oui | oui |
| `b`/`i`/`s` | oui, sauf même balise (rendu sans la balise) | oui | **non** → texte échappé | impossible (bloc) |
| `a` | oui | **non** → texte (existant) | **non** → texte échappé | impossible |
| `code`/`pre` | ne contiennent que du texte | | | |
| `blockquote` | oui | oui | oui | **non** → aplati (existant) |

Mise en œuvre : `Html` gagne `in_entity: bool` (dans `b`/`i`/`s`/`a`, titre compris puisqu'il est rendu en `<b>`) et `open_strong`, `open_em`, `open_del: bool`. `Inline::Code` sous `in_entity` → `self.esc(t)` sans `<code>` ; `Strong`/`Emphasis`/`Strikethrough` dont la balise est déjà ouverte → contenu seul. `Block::CodeBlock` n'apparaît jamais sous une entité inline (les blocs ne sont pas contenus par des inlines ; un bloc de code dans un élément de liste ou une citation reste permis). Le rendu `html` (email) n'est pas concerné : HTML autorise ces imbrications.

Le test de propriété `telegram_html_and_html_are_always_well_formed` est étendu : `check_telegram` vérifie, en plus de l'équilibre, ces règles sur la pile des balises ouvertes (`<pre><code class="language-…">` compte comme une seule entité `pre`), et `FRAGMENTS` gagne des combinaisons code/lien/emphase/titre/citation.

### D7. Sauts de ligne et indentation des valeurs : neutralisés (constat 7, tranché)

Décision : neutraliser dans `markdown::escape`, donc dans le formateur, plutôt que seulement documenter. Pour une valeur non sûre : LF, CRLF et CR sont écrits `\n` ; chaque espace de tête d'une ligne devient U+00A0 et chaque tabulation de tête quatre U+00A0 ; une ligne vide devient un U+00A0 seul ; le reste est échappé comme aujourd'hui.

Justification :
- Une ligne vide est la seule façon pour une valeur de terminer un paragraphe (et donc une emphase, un élément de liste, une citation) ; une ligne non vide est une continuation de paragraphe, dans laquelle aucune structure de bloc ne peut démarrer, puisque toute ponctuation de début de ligne est déjà échappée. CommonMark ne considère comme vide qu'une ligne d'espaces U+0020 ou de tabulations : U+00A0 la rend non vide, de façon invisible.
- L'indentation de tête (4 espaces) est la seule autre structure accessible (bloc de code indenté en début de paragraphe) ; la convertir en U+00A0 l'empêche et conserve l'indentation visible des traces de pile sur tous les canaux, alors que CommonMark la supprimerait dans une continuation.
- Le coût est faible : quelques lignes dans une fonction déjà centrale, aucun changement de l'arbre ni des rendus.

Alternatives écartées : documentation seule — `**{{ _msg }}**` avec un `_msg` multiligne est un cas courant et l'emphase cassée affiche des `**` ; saut dur `\` + saut de ligne — une ligne vide reste vide et une ligne réduite à `\` a un rendu peu lisible.

Conséquence assumée : le rendu `plain` (webhook par défaut) contient des U+00A0 là où la valeur avait une indentation ou une ligne vide ; la doc le dit. La batterie hostile (`"    four"`) change d'attendu.

### D8. `link` → `md_link` (constat 8)

Renommage simple dans `valerter_functions()`, la doc, les exemples, les fixtures et les tests. Un champ d'événement nommé `md_link` masquerait encore la fonction (le contexte de minijinja prime sur les globales) : nom choisi improbable dans un log, et documenté. Pas d'alias `link` : la fonction n'a jamais été publiée.

### D9. `urlencode` (constat 9)

`Cargo.toml` : `minijinja = { version = "2.12", features = ["builtins", "json", "urlencode"] }`. `("urlencode", Value::from_function(f::urlencode))` ajouté à `builtin_filters()` de `src/config/validation.rs` (avec mise à jour du commentaire « minijinja 2.24 with the builtins, json and urlencode features ») ; le test garde-fou `builtin_filter_wrappers_still_report_unknown_filters` le couvre automatiquement puisqu'il itère `builtin_filters()` et `valerter_filters()`, et il itère `valerter_functions()` pour `md_link`. Exemples : `md_link("Logs in VictoriaLogs", "https://vl.example.com/select/vmui?query=" ~ ("host:" ~ host) | urlencode)`.

### D10. Documentation (constats 4, 10, 11, 12) et CHANGELOG

- Promesse : « values of the log cannot become markup on any channel » devient « values of the log are shown as text on every channel, unless you insert them with `| safe` » suivi d'une note : comme en mode texte, les URL nues, `@channel`/`@here` (Mattermost) et mentions restent détectées par le client.
- Discord (constat 10) : le rendu `markdown` vise le moteur de Mattermost et écrit `<` en `&lt;` et `&` en `&amp;` devant une entité ; Discord ne décode pas les entités et Rocket.Chat n'a pas été vérifié. Ils sont retirés de la recommandation `format: markdown` (gardée pour Mattermost via un webhook générique et les moteurs CommonMark/GFM, qui décodent les entités) ; l'exemple `discord-md` devient un exemple Mattermost générique, et un exemple Discord en `plain` (défaut) est ajouté.
- Mémoire (constat 12) : par alerte en attente, ordre de grandeur pour une ligne de taille L insérée une fois dans un corps Markdown : `log` ≤ 2L (clés plates + copies dépliées), source Markdown ≤ 2L (une barre oblique par ponctuation), rendus calculés pour les formats effectivement utilisés : `plain` ≤ L, `markdown` ≤ 4L (`<` → `&lt;`), `html` ≤ 6L (`"` → `&quot;`), `telegram_html` ≤ 5L (`&` → `&amp;`) ; soit jusqu'à environ 20 Mio pour une ligne de 1 Mio dans le pire cas, multiplié par le nombre d'insertions de la valeur. Les facteurs sont à confirmer dans le code au moment de rédiger (tâche 8.5) ; la doc donne la formule, le pire cas et le cas courant (lignes de quelques centaines d'octets : négligeable).
- CHANGELOG `## [2.1.0] - Unreleased` : entrées corrigées en place dans `### Added` (promesse, `| tojson`, `codeblock` n'importe où, `md_link`, `urlencode`, sauts de ligne) et dans `### Fixed` (repli Telegram : ne plus citer la coupure de balise par la troncature) ; nouvelles entrées `### Fixed` (troncature Telegram HTML, préexistante) et `### Security` (clé pointée démesurée : abandon du processus, préexistant). Les débordements du corps Markdown et l'injection via `codeblock`/`tojson` ne concernent qu'une fonction non publiée : corrigés dans l'entrée `Added` existante, sans entrée de sécurité.

## Risks / Trade-offs

- [La limite Telegram est peut-être comptée en unités UTF-16 et non en points de code] → comportement existant conservé (le comptage visible ne fait que réduire le texte compté) ; un message de 4096 points de code astraux pourrait être refusé. Mitigation : le repli existant ; point à rouvrir si un rejet `message is too long` est observé.
- [Un jeton dans un contexte non prévu par le tableau de D3] → l'index inconnu ou non substitué devient U+FFFD, jamais du Markdown actif ; la batterie hostile et le test de propriété couvrent les contextes.
- [`render_and_return_state` compile le template à chaque rendu, comme `render_str` aujourd'hui] → pas de régression de performance ; les emplacements ne coûtent qu'une allocation par filtre utilisé.
- [Les U+00A0 de D7 dans le rendu `plain`] → visibles seulement pour des valeurs indentées ou à lignes vides ; documenté.
- [Un template qui chaînait un filtre après `code`/`codeblock`/`md_link`] → il obtient une chaîne échappée (backticks visibles), comme aujourd'hui pour une chaîne sûre modifiée ; documenté : le filtre Markdown doit terminer l'expression.
- [Borne de 32 trop basse pour un usage légitime] → un message d'alerte ne dépasse pas quelques niveaux ; au-delà, le texte est conservé, seule la mise en forme est perdue.
- [Avertissement de clé pointée démesurée à chaque alerte] → même politique que la collision existante ; clé tronquée dans le journal.

## Migration Plan

Aucune migration de configuration publiée : `link` n'existe que dans les préversions de la 2.1.0 (renommage signalé dans l'entrée CHANGELOG corrigée, pas dans MIGRATION.md). Le comportement des templates `text` est inchangé, hors troncature Telegram en `parse_mode: HTML` (qui ne coupe plus le HTML) et clés pointées de plus de 32 segments (non dépliées). Retour arrière : revert de la PR.
