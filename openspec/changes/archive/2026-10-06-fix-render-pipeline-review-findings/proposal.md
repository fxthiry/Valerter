# Proposal

## Why

La relecture ciblée des PR #63 (variable `log` à l'étage 2) et #64 (`body_format: markdown`) a reproduit deux abandons du processus entier par débordement de pile, déclenchables par une simple ligne de log : emphases ou citations imbriquées dans un corps Markdown, et clé pointée à des milliers de segments. Elle a aussi montré que des valeurs du log peuvent encore devenir du balisage actif (`codeblock` mal placé, `| tojson`), que la troncature Telegram casse le HTML, et que la documentation promet plus que le code. La 2.1.0 n'est pas publiée : c'est le moment de corriger, avant que `link`, la promesse « cannot become markup » et le comportement de `codeblock` ne figent.

## What Changes

**Bloquant**
- Profondeur d'imbrication bornée (32) à l'analyse du corps Markdown : au-delà, l'élément est transparent et son texte conservé ; aucun rendu ni aucune destruction d'arbre ne peut plus déborder la pile (constat 1).
- Dépliage des clés pointées limité à 32 segments : au-delà, seule la clé plate est conservée et un avertissement est journalisé (constat 2, préexistant, devenu atteignable à chaque alerte via `log`).

**Important**
- `code`, `codeblock` et `md_link` émettent dans un corps Markdown un jeton de substitution (caractère d'usage privé + index) ; leur contenu est stocké à part et substitué après l'analyse, si bien qu'il reste littéral quel que soit l'endroit où le filtre est écrit (élément de liste, citation, ligne indentée, milieu de paragraphe). Les jetons ne peuvent pas être forgés par une valeur du log (constat 3).
- `| tojson` n'est plus une échappatoire dans un corps Markdown : son résultat est échappé comme toute valeur ; `| safe` reste la seule (constat 4).
- Troncature Telegram consciente du HTML en `parse_mode: HTML` : seul le texte visible est compté (entité = 1), aucune balise ni entité n'est coupée, les balises ouvertes sont refermées ; le repli en texte brut d'une alerte Markdown envoie le titre et le rendu `plain` au lieu du HTML brut (constat 5).
- Rendu `telegram_html` conforme aux règles d'imbrication de l'API Bot : pas de `code`/`pre` dans `b`/`i`/`s`/`a`, pas de lien dans un lien, pas de citation dans une citation, pas d'entité imbriquée dans une entité de même type (constat 6).

**Mineur**
- Sauts de ligne et indentation des valeurs neutralisés dans le formateur Markdown : une ligne vide ou l'indentation d'une valeur ne peut plus fermer un paragraphe, une emphase ou ouvrir un bloc de code (constat 7).
- Fonction `link` renommée `md_link` (nom non publié, masqué par tout champ d'événement nommé `link`) (constat 8). **BREAKING** uniquement par rapport aux préversions de la 2.1.0 ; aucune version publiée ne contient `link`.
- Feature minijinja `urlencode` activée ; filtre `urlencode` connu de `--validate` et utilisé dans les exemples de lien (constat 9).
- Documentation : Discord retiré de la recommandation `format: markdown` (constat 10), promesse « cannot become markup » nuancée (`| safe`, URL nues, `@channel`) (constats 4 et 11), estimation mémoire de `docs/performance.md` corrigée (constat 12).
- CHANGELOG `## [2.1.0] - Unreleased` : entrées existantes corrigées (promesse, `link` → `md_link`, `codeblock`, `tojson`, repli Telegram), nouvelles entrées Fixed/Security.

Hors périmètre : version et date du CHANGELOG (étape de release séparée), troncature des `parse_mode` MarkdownV2/Markdown (inchangée).

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities
- `message-templating` : profondeur bornée du corps Markdown, jetons de substitution de `code`/`codeblock`/`md_link`, `tojson` échappé, neutralisation des sauts de ligne et de l'indentation des valeurs, `link` → `md_link`, filtre `urlencode`, règles d'imbrication `telegram_html`, dépliage des clés pointées borné.
- `log-parsing` : vue imbriquée des clés pointées limitée à 32 segments.
- `notifier-telegram` : troncature consciente du HTML et repli en texte brut fondé sur le rendu `plain`.

## Impact

- Code : `src/markdown/parse.rs` (borne de profondeur, substitution des jetons), `src/markdown/render.rs` (imbrication Telegram), `src/markdown/mod.rs` (`escape` neutralise les caractères de jeton), `src/template/filters.rs` (jetons, `tojson` enveloppé, `md_link`, sauts de ligne), `src/template/mod.rs` (rendu avec état, emplacements dans `RenderedMessage`), `src/parser.rs` (`insert_nested`), `src/notify/telegram.rs` (troncature HTML, repli plain), `src/config/validation.rs` (`urlencode`, `md_link`).
- Dépendances : feature `urlencode` de minijinja (tire `percent-encoding`, déjà dans l'arbre via reqwest/url).
- Configuration : seul le nom `link` change (préversion uniquement) ; aucune clé de configuration nouvelle.
- Documentation : `docs/configuration.md`, `docs/notifiers.md`, `docs/performance.md`, `config/config.example.yaml`, `CHANGELOG.md`, fixtures `tests/fixtures/config_docs_markdown.yaml` et `config_email_markdown_no_email_body_html.yaml`.
