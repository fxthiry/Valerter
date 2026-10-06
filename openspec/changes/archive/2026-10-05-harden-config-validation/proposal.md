# Proposal

## Why

La validation fail-fast de valerter laisse passer plusieurs erreurs de configuration qui ne se manifestent qu'à l'exécution, en silence ou en boucle : un `defaults.throttle` à `count: 0` supprime toutes les alertes de toutes les règles sans throttle propre, un filtre inconnu dans `throttle.key` regroupe tous les événements sous la clé de repli `<règle>:error`, un filtre inconnu dans un `body_template` de notifier fait échouer chaque envoi, un nom d'en-tête invalide sur une source VictoriaLogs provoque une boucle de reconnexion, une URL de notifier issue d'une `${VAR}` n'est jamais revérifiée, et un `parse_mode` Telegram erroné renvoie un HTTP 400 à chaque alerte. À l'inverse, le rendu d'essai des templates rejette à tort des templates corrects (`{{ status | int }}`), et l'indice donné pour les champs contenant `/` propose une syntaxe (`fields[...]`) qui n'existe pas. Ces trous contredisent la promesse « une configuration qui démarre est une configuration qui fonctionne », et `valerter --validate` ne peut pas jouer son rôle de garde-fou avant une mise à jour.

## What Changes

- **BREAKING** `defaults.throttle` est validé comme un throttle de règle : `count >= 1`, `window > 0`, syntaxe et rendu d'essai de `key`. Une configuration aujourd'hui acceptée avec `count: 0` ou `window: 0s` dans `defaults` est désormais refusée au chargement (au lieu d'un simple avertissement à l'exécution).
- **BREAKING** `throttle.key` (règles et `defaults`) subit un rendu d'essai au chargement : un filtre, test ou fonction inconnu est refusé au lieu de basculer à l'exécution sur la clé de repli `<règle>:error`.
- **BREAKING** Les `body_template` des notifiers webhook, Telegram et email (en ligne, `body_template_file` ou template intégré) subissent un rendu d'essai à l'instanciation des notifiers : un filtre inconnu est refusé au démarrage et par `valerter --validate` (qui construit les notifiers via le pré-vol de `complete-validate-mode`), au lieu d'échouer à chaque envoi.
- Le rendu d'essai (templates de messages, `subject_template`, `throttle.key`, `body_template`) ne rejette plus que les erreurs décelables avec un contexte fictif : syntaxe, filtre/test/fonction/méthode inconnus, et opérateur `/` appliqué à un chemin de champ. Les erreurs de type dues au contexte fictif (`| int`, `| float`, `| round`, arithmétique…) ne sont plus des faux positifs.
- **BREAKING** Les noms (et valeurs) d'en-têtes `headers` des sources VictoriaLogs sont validés au chargement ; un nom invalide est refusé avec un message qui ne répète pas la valeur.
- L'URL des sources VictoriaLogs est validée après résolution des `${VAR}` sans exception pour `${` ; l'URL résolue des notifiers webhook (`url`) et Mattermost (`webhook_url`) est revérifiée (analysable, schéma `http`/`https`) à l'instanciation, sans répéter l'URL.
- **BREAKING** `parse_mode` Telegram est restreint à `HTML`, `MarkdownV2` ou `Markdown` (insensible à la casse, normalisé vers la forme canonique) et vérifié à l'instanciation du notifier (démarrage et `valerter --validate`).
- L'ordre des règles issues de `rules.d/` devient déterministe : règles du fichier principal dans l'ordre déclaré, puis entrées de `rules.d/` triées par (chemin de fichier, nom de règle). Les erreurs de validation sur templates et notifiers sont listées dans l'ordre alphabétique des noms.
- Le message de collision entre deux fichiers d'un même répertoire `.d/` utilise le singulier comme les autres collisions (`duplicate rule name`, `duplicate template name`, `duplicate notifier name`).
- L'indice pour les champs contenant `/` ne propose plus `fields["..."]` (variable inexistante) pour un nom de premier niveau ; il explique que ce champ n'est pas adressable et suggère de le renommer dans la requête LogsQL.

Ce change s'implémente après `complete-validate-mode` : les contrôles de notifiers qu'il ajoute vivent uniquement dans la construction des notifiers, que le pré-vol partagé exécute au démarrage comme en `--validate` ; ils ne sont pas dupliqués dans `Config::validate()`. Le refus d'une configuration dont toutes les règles sont désactivées n'est pas traité ici (change `fix-daemon-exit-codes`).

## Capabilities

### New Capabilities

Aucune.

### Modified Capabilities

- `configuration` : validation de `defaults.throttle`, des en-têtes et de l'URL résolue des sources VictoriaLogs, rendu d'essai de `throttle.key`, ordre déterministe des règles `.d/`, message de collision au singulier.
- `throttling` : bornes de `defaults.throttle` refusées au chargement, rendu d'essai de la clé au chargement (la clé de repli ne sert plus qu'aux erreurs imprévisibles).
- `message-templating` : rendu d'essai limité aux erreurs décelables avec un contexte fictif ; indice corrigé pour les champs de premier niveau contenant `/`.
- `notifier-webhook` : rendu d'essai du `body_template` à l'instanciation, revérification de l'URL résolue.
- `notifier-telegram` : rendu d'essai du `body_template` et validation/normalisation de `parse_mode` à l'instanciation.
- `notifier-email` : rendu d'essai du template de corps (en ligne, fichier ou intégré) à l'instanciation.
- `notifier-mattermost` : revérification de `webhook_url` résolue.

## Impact

- Code : `src/config/types.rs` (`Config::validate`, tri des entrées `.d/` dans `merge_rules`, collisions), `src/config/validation.rs` (rendu d'essai, indice `/`, validation d'URL et d'en-têtes), `src/notify/{webhook,telegram,email}.rs` et `src/notify/registry.rs` (instanciation), `src/throttle.rs` (avertissements devenus inatteignables).
- Comportement visible : des configurations aujourd'hui acceptées sont refusées au démarrage (voir **BREAKING**). Le démon refusera de redémarrer après mise à jour du `.deb` si la configuration est concernée : à documenter dans la section « Upgrading to 2.1.0 » de `MIGRATION.md` (lancer `valerter --validate` avant la mise à jour) et dans la section `## [2.1.0]` de `CHANGELOG.md`. Livraison en 2.1.0.
- Docs : `docs/configuration.md`, `docs/notifiers.md`.
- Aucune nouvelle dépendance (`reqwest::header::HeaderName`/`HeaderValue` sont déjà disponibles).
