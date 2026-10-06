# Design

## Context

Voir proposal.md (Why). État actuel du code, vérifié sur `release/2.1.0` (1856d61) :

- **Étage 1** (template de règle) : `TemplateEngine` (`src/template.rs:61-218`) garde deux `Environment<'static>` (texte, et HTML auto-échappé pour `email_body_html`) et rend chaque champ avec `render_str` (`src/template.rs:187`, `:205`), donc recompile la source à chaque alerte. Chaque appel à `render_string` refait `parser::unflatten_dotted_keys(fields)` (`src/parser.rs:279`) puis `inject_context` : le dépliage est fait deux ou trois fois par alerte. `unflatten_dotted_keys` **conserve** la clé plate (`"k8s.pod"`) **et** ajoute l'objet déplié (`k8s.pod`), et ignore le dépliage (avertissement sans valeur) si le premier segment est un scalaire.
- **Payload** : `process_log_line` (`src/engine.rs:718-800`) construit `AlertPayload` (`src/notify/payload.rs:12-34`, `#[derive(Debug, Clone)]`) sans aucun champ du log ; la file le partage en `Arc<AlertPayload>` entre destinations (`src/notify/queue.rs:223`).
- **Étage 2** : chaque envoi crée un `Environment::new()`, ajoute la source et la compile : Telegram `render_body_template` (`src/notify/telegram.rs:94-110`), webhook `render_body_template` (`src/notify/webhook.rs:104-122`), email `render_subject` (`src/notify/email.rs:416-435`) et `render_body` (`src/notify/email.rs:443-474`, auto-échappement HTML, `body` passé en `Value::from_safe_string`). Les contextes sont des `context!` fermés (`title`, `body`, `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted`, plus `accent_color` pour l'email). Mattermost n'a pas de template d'étage 2.
- **Validation** : `validate_notifier_template` (`src/config/validation.rs:307`) = syntaxe + `validate_template_render` (deux passes, `src/config/validation.rs:264-301`). La racine `ValidationRoot` rend **tout** nom de premier niveau sentinelle, donc `{{ log.x }}` passe déjà la validation, mais `{{ host }}` (inexistant à l'étage 2) passe aussi en silence. Les filtres sont ceux de `builtin_filters()` (`src/config/validation.rs:138-187`), enveloppés par `validation_env` (`:213-235`) ; le test garde-fou `builtin_filter_wrappers_still_report_unknown_filters` (`:705`) vérifie qu'un filtre inconnu est encore signalé après chacun d'eux.
- **Autres environnements** : `throttle.rs:233` (clé de throttle, `render_str`) et `throttle.rs:389` (analyse statique `undeclared_variables`, API disponible sans feature dans minijinja 2.24).
- minijinja verrouillé en **2.24.0** (`Cargo.lock`), features `builtins` et `json` ; `UndefinedBehavior::Lenient` est le défaut d'`Environment::new()`. `Environment<'static>` est `Send + Sync` (déjà partagé par `Arc<TemplateEngine>` dans `src/engine.rs:290` ; le commentaire « Environment is not Sync » de `src/template.rs:57` est faux et sera corrigé).
- Le conseil erroné de L0 figure à deux endroits : `docs/notifiers.md:424-429` (note « email_body_html » de la section Telegram) **et** `config/config.example.yaml:139-143`.

## Goals / Non-Goals

**Goals:**

- Accès en lecture, à l'étage 2, à tous les champs du log, sous un nom qui ne peut entrer en collision avec rien.
- Des filtres d'échappement explicites pour les dialectes Markdown que valerter cible aujourd'hui (Mattermost, Telegram MarkdownV2).
- Templates d'étage 2 compilés une fois ; un seul dépliage des champs par alerte, partagé entre étage 1 et étage 2.
- Aucune différence de rendu pour une configuration existante.

**Non-Goals:**

- Auto-échappement par format, rendus par notifier, `body_format` : change `markdown-body-format`.
- Exposer `log` dans le template de règle (`title`, `body`, `email_body_html`, `throttle.key`).
- Ajouter `log` au corps JSON **par défaut** du webhook (sa liste de clés est « exactement » spécifiée ; des consommateurs stricts casseraient).
- Template d'étage 2 pour Mattermost (L3/L4 de l'issue #24).

## Decisions

### D1. Nom du contexte : `log`

`log` est retenu, parmi `log`, `fields` et `event` :

- cohérent avec les variables d'étage 2 existantes `log_timestamp` / `log_timestamp_formatted` (« ce qui vient du log ») ;
- à l'étage 2 le contexte est fermé (variables synthétiques uniquement) : aucune collision possible, contrairement à l'étage 1 où un champ `log` est courant (sortie de conteneur Docker/Kubernetes via Fluent Bit). C'est pour cela que `log` n'est **pas** injecté à l'étage 1 (scénario « Template de règle inchangé ») ;
- `fields` est écarté : la spec et l'indice d'erreur de l'issue #41 (`message-templating`, « Indice pour les noms de champ contenant une barre oblique ») affirment explicitement qu'aucune variable `fields` n'existe ; l'introduire à l'étage 2 seulement brouillerait ce message ;
- `event` est écarté : terme interne des specs, absent de la documentation utilisateur, qui parle de « log » et de « fields ».

### D2. Transport : `minijinja::Value` construit une fois par alerte

`process_log_line` déplie les champs **une fois** (`unflatten_dotted_keys`), rend l'étage 1 à partir de cette vue (nouvelle signature de `TemplateEngine::render` prenant le contexte déplié ; `inject_context` travaille sur une copie de surface pour l'étage 1 seulement), puis stocke dans `AlertPayload` un champ `log: minijinja::Value` créé par `Value::from_serialize(&unflattened)`. Un `minijinja::Value` est immuable, `Send + Sync` et se clone par compteur de références : chaque notifier l'insère dans son contexte sans copie. Alternative écartée : `Arc<serde_json::Value>` reconverti à chaque rendu (une conversion par destination et par template au lieu d'une par alerte).

Comme la vue est celle de l'étage 1, `{{ log | tojson }}` contient à la fois `"k8s.pod"` et `"k8s": {"pod": …}` ; c'est documenté (l'exemple PagerDuty le mentionne et montre aussi la sélection de champs). Une vue « brute seulement » n'est pas ajoutée (pas de besoin avéré).

Le repli d'étage 1 (`render_with_fallback`) ne touche pas `log` : l'alerte reste exploitable par les templates de notifier ; la garantie « le message de repli ne contient pas les valeurs » porte sur `title`/`body`, inchangée.

### D3. `Debug` manuel d'`AlertPayload`

`#[derive(Debug)]` exposerait toutes les valeurs. `AlertPayload` reçoit un `impl Debug` qui affiche `log` sous la forme `log_field_count`. Les logs existants (`queue.rs`, workers, notifiers) ne formatent jamais le payload entier ; un test vérifie la sortie de débogage et un test d'intégration vérifie qu'un échec d'envoi ne journalise pas une valeur sentinelle.

### D4. Environnements d'étage 2 compilés à la construction

Chaque notifier construit dans `from_config` un `Environment<'static>` (`add_template_owned("body", source)`, `"subject"` pour l'email), avec les filtres valerter (D5) et, pour le corps email, `set_auto_escape_callback(|_| AutoEscape::Html)`. À l'envoi : `env.get_template(..)?.render(ctx)`. La compilation ayant déjà réussi pendant la validation, une erreur de syntaxe à l'envoi devient impossible ; les messages d'erreur de rendu (`template error: ...`, `template render error: ...`) et leur comptage sont inchangés. Le template par défaut Telegram et le template email intégré sont compilés de la même façon. Les représentations `Debug` manuelles des notifiers n'exposent pas l'environnement (la source webhook résolue peut contenir un secret, exigence existante).

### D5. Filtres propres à valerter : un module, un point d'enregistrement

Un module (`src/template/filters.rs`, ou `src/filters.rs` si `template.rs` reste un fichier) expose `md_escape`, `mdv2_escape` et `register(env: &mut Environment)`, appelé par **tous** les environnements : étage 1 (texte et HTML), étage 2, clé de throttle (`throttle.rs:233`) et validation. Une liste `valerter_filters() -> Vec<(&'static str, Value)>` alimente à la fois `register` et `validation_env`, qui les enveloppe comme les filtres intégrés (même `filter_substitute` : une feuille sentinelle) ; le garde-fou `builtin_filter_wrappers_still_report_unknown_filters` itère sur `builtin_filters()` **et** `valerter_filters()`. Le change `markdown-body-format` ajoutera ses filtres et sa fonction `link` à cette même liste.

Jeux de caractères :

- `md_escape` : `` \ ` * _ { } [ ] ( ) # + - . ! > | ~ ``. C'est exactement le jeu d'échappement du moteur Markdown de Mattermost (fork `mattermost/marked`, règle `inline.escape` : `` /^\\([`*{}\[\]()#+\-.!_>|~]|\\(?!\w))/ ``, vérifiée le 05/10/2026) ; tous ces caractères sont aussi échappables en CommonMark. Échapper toute la ponctuation ASCII (`:`, `/`, `@`, `=`, `<`, `&`…) ferait apparaître des barres obliques inverses dans Mattermost (`10\:49\:35`, `https\:\/\/…`). Limite documentée : `<` et `&` ne sont pas neutralisés, sans effet sur Mattermost (qui n'interprète pas le HTML) mais à connaître pour un consommateur CommonMark qui rendrait du HTML.
- `mdv2_escape` : les 18 caractères réservés listés par l'API Bot (`_ * [ ] ( ) ~ ` > # + - = | { } . !`) **plus** `\`, que l'API exige aussi d'échapper pour l'afficher ; usage hors entités `pre`/`code` (où seuls `` ` `` et `\` sont à échapper), documenté.
- Pas de `tg_escape` : `| e` produit déjà les entités attendues par Telegram en `parse_mode: HTML` (`&lt;`, `&gt;`, `&amp;`, et des entités numériques acceptées par l'API).

Les deux filtres renvoient une chaîne ordinaire (non « safe ») : dans un environnement HTML auto-échappé (corps email, `email_body_html`), le résultat est en plus échappé en HTML, ce qui est correct.

### D6. Avertissement sur les variables inconnues d'étage 2

À la construction de chaque notifier, `env.get_template(..).undeclared_variables(false)` donne les variables de premier niveau lues ; on retire le contexte connu du template (`title`, `body`, `rule_name`, `vl_source`, `log_timestamp`, `log_timestamp_formatted`, `log`, plus `accent_color` pour l'email) et les globales de l'environnement (`env.globals()`), puis on journalise un WARN `Notifier template references unknown variable` (champs `notifier`, `field`, `variable`). Avertissement et non erreur : un template existant qui lit une variable inexistante se rend aujourd'hui avec une chaîne vide ; le refuser serait une rupture. Le message cible la confusion la plus probable après ce change (`{{ host }}` au lieu de `{{ log.host }}`).

### D7. L0 : ce que dit la documentation Telegram

La note « email_body_html » de `docs/notifiers.md` et le commentaire de `config/config.example.yaml` sont réécrits : avec le template par défaut, `body` est échappé, donc du HTML dans `body` s'affiche littéralement ; pour formater, écrire le balisage dans `body_template` et échapper chaque valeur insérée (`{{ title|e }}`, `{{ log.host|e }}`) ; `{{ body }}` sans `|e` n'est sûr que si `body` ne contient aucune donnée du log. Renvoi vers `body_format: markdown` (change suivant, même version) et vers l'issue #24.

## Risks / Trade-offs

- [Mémoire : les champs du log restent en file avec l'alerte] → partagés par `Arc` entre destinations ; borne inchangée de 100 alertes par destination ; une ligne est déjà plafonnée à 1 MiB en amont, et `_msg` était souvent déjà recopié dans `body`. Mention dans `docs/performance.md`.
- [Fuite de secrets du log vers un canal] → c'est un choix explicite de l'opérateur (il écrit `{{ log.x }}`) ; aucun log valerter ne les contient (D3) ; la doc rappelle que `{{ log | tojson }}` envoie tout l'événement.
- [`{{ log | tojson }}` contient les clés plates et dépliées] → documenté ; sélection explicite de champs montrée dans l'exemple.
- [`md_escape` ne neutralise pas `<` et `&`] → choix de compatibilité Mattermost (D5), documenté ; le change `markdown-body-format` traite le HTML brut au niveau de l'arbre.
- [Nouveau WARN au démarrage pour des configurations existantes lisant une variable inconnue] → n'empêche ni le démarrage ni `--validate` ; mentionné dans MIGRATION.

## Migration Plan

Aucune action requise : les templates existants se rendent à l'identique. MIGRATION « Upgrading to 2.1.0 » décrit `log`, les deux filtres, l'avertissement éventuel, et la correction du conseil Telegram (passer le balisage dans `body_template`). Retour arrière : retirer les usages de `log`, `md_escape` et `mdv2_escape` suffit pour revenir à 2.0.x.
