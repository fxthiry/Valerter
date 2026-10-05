# Design

## Context

Voir `proposal.md` (section Why) pour la motivation. État du code vérifié avant planification (et état attendu après
`harden-notifier-payloads`, appliqué avant ce change) :

- `src/notify/webhook.rs` : `from_config` résout `url` et chaque valeur de `headers` avec `resolve_env_vars` (erreur
  `invalid notifier '<nom>': url: undefined environment variable: <NOM>`), mais stocke le `body_template` brut, le valide
  puis le rend par un `Environment::new()` minijinja. La spec de référence verrouille même ce comportement (scénario
  « Pas de substitution d'environnement dans le template »).
- Après `harden-notifier-payloads` : `tojson` est documenté et l'exemple PagerDuty porte
  `"routing_key": "<your-integration-key>"` en attendant ce change.
- `src/notify/mattermost.rs` : `build_mattermost_payload` reçoit `self.channel` ; `AlertPayload` ne porte pas le
  `notify.mattermost_channel` de la règle, qui n'est lu que par `warn_unused_mattermost_channels` dans `src/main.rs`.
  `send` abandonne sur tout 4xx autre que 429 (`client error: <statut>`).
- Un webhook entrant Mattermost peut être verrouillé sur un canal (« Lock to this channel ») et rejeter alors en 4xx toute
  requête qui demande un autre canal ; un canal inexistant est aussi rejeté en 4xx.

## Goals / Non-Goals

**Goals:**
- `${VAR}` résolu de façon homogène dans tous les champs textuels du notifier webhook (`url`, `headers`, `body_template`).
- `notify.mattermost_channel` appliqué conformément à la doc, sans perte d'alerte si l'override est refusé.
- Ruptures annoncées et expliquées dans MIGRATION.md (section 2.1.0).

**Non-Goals:**
- Résolution des `${VAR}` dans les `body_template` Telegram ou email (non demandée, pas d'usage identifié).
- Syntaxe d'échappement pour un `${…}` littéral (cohérent avec `url`/`headers`, qui n'en ont pas).
- Métriques des notifiers (change `fix-metrics-consistency`) : aucun requirement de métrique n'est modifié ; le repli
  Mattermost ne crée pas de métrique dédiée et le comptage sent/failed reste celui de l'issue finale de l'envoi.
- Repli pour le `channel` configuré au niveau du notifier : comportement existant, déjà exercé, inchangé.

## Decisions

### 1. `${VAR}` résolu dans le `body_template` à l'instanciation, par substitution textuelle

Appeler `resolve_env_vars` sur la source du template avant `validate_body_template`, avec le préfixe d'erreur
`body_template:` — même mécanisme, même message et même moment que `url` et `headers`, donc couvert automatiquement par
tout contrôle qui construit les notifiers (dont `--validate`, voir `complete-validate-mode`, et le rendu d'essai de
`harden-config-validation`, qui opère alors sur la source résolue). La substitution porte sur la source du template,
jamais sur le rendu : un `${HOME}` présent dans un log reste littéral, ce qui empêche d'exfiltrer l'environnement via le
contenu des logs.
Alternative écartée : remplacer `${VAR}` par une variable de contexte cachée injectée au rendu (évite qu'une valeur
contenant `{{` soit interprétée par Jinja). Plus robuste en théorie mais incohérent avec `url`/`headers` et plus complexe ;
les valeurs d'environnement sont fournies par l'opérateur et considérées de confiance. Le risque est documenté.
La source résolue peut contenir un secret : elle reste confinée dans le notifier (le `Debug` actuel n'affiche que
`has_body_template`, le `trace!` n'affiche que `body_len`, l'avertissement JSON de `harden-notifier-payloads` n'affiche
jamais le corps) ; un test verrouille cette propriété.

### 2. `mattermost_channel` transporté par `AlertPayload`

Ajouter `mattermost_channel: Option<Arc<str>>` (ou `Option<String>`) à `AlertPayload`, alimenté dans `src/engine.rs` à
partir de `ctx.rule.notify.mattermost_channel` (cloné une fois par tâche, comme `destinations`). Le notifier Mattermost
choisit `alert.mattermost_channel.or(self.channel)`. Les autres notifiers ignorent le champ.
Alternative écartée : aligner seulement la doc et déclarer la clé sans effet — garde une clé morte dans le schéma et
contredit ce que les utilisateurs ont pu configurer sur la foi de la doc.

### 3. Repli sans `channel` sur rejet 4xx de l'override de règle

Si le canal effectif provient de la règle (`alert.mattermost_channel` défini) et que la réponse est un 4xx autre que
429, `send` journalise en `warn` `Mattermost rejected channel override, resending without channel` (champs
`notifier_name`, `rule_name`, `channel` demandé, statut ; jamais l'URL du webhook) puis renvoie une seule fois le même
message sans le champ `channel`. Le renvoi suit la politique de relance habituelle (5xx, 429, erreurs réseau : 3
tentatives au plus pour ce renvoi) ; un 4xx sur le renvoi est un échec définitif `client error: <statut>`.
Pourquoi omettre `channel` plutôt que retomber sur le `channel` du notifier : un webhook verrouillé refuse tout canal
explicite différent du sien, y compris celui du notifier ; seule l'omission garantit que le message arrive dans le canal
par défaut du webhook. Pourquoi limiter le repli à l'override de règle : c'est le seul chemin nouveau, jamais exercé en
production ; le `channel` du notifier garde son comportement actuel (abandon sur 4xx), qui est déjà connu des opérateurs.
Coût accepté : un 4xx sans rapport avec le canal (payload refusé) entraîne un renvoi inutile, lui aussi rejeté.
Le corps est construit au plus deux fois par alerte (avec et sans canal) ; chaque variante est réutilisée à l'identique
entre ses propres tentatives.

### 4. Ordre et coordination

Ce change est implémenté en dernier : il s'appuie sur `tojson` et les exemples réécrits par `harden-notifier-payloads`,
et ses deltas `notifier-webhook` (« Rendu du body_template ») reprennent le texte tel que modifié par ce dernier.

## Risks / Trade-offs

- [Un `body_template` contenait un `${…}` littéral voulu] → démarrage en échec avec un message explicite nommant la
  variable ; MIGRATION.md l'annonce.
- [Valeur d'environnement contenant `{{`, `{%` ou `"`] → interprétée par Jinja ou cassant le JSON ; documenté, valeurs
  opérateur de confiance.
- [Override `mattermost_channel` désormais appliqué] → les alertes de la règle changent de canal ; MIGRATION.md explique
  comment conserver l'ancien comportement (retirer la clé).
- [Webhook verrouillé ou canal mal orthographié] → repli sans `channel` : l'alerte arrive dans le canal par défaut du
  webhook, au prix d'une requête supplémentaire par alerte et d'un avertissement à chaque alerte tant que la
  configuration n'est pas corrigée (bruit volontaire).

## Migration Plan

Déploiement par mise à jour du binaire/.deb, sans nouvelle clé. Avant mise à jour, l'opérateur cherche les `${`
présents dans ses `body_template` webhook (définir la variable ou retirer le motif) et les règles qui définissent
`mattermost_channel` (vérifier le canal et le verrouillage du webhook, ou retirer la clé). MIGRATION.md, section
« Upgrading to 2.1.0 », détaille les deux ruptures. Retour arrière : réinstaller la version précédente ; aucune donnée
persistée n'est concernée.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`  ← ce change

Pour ce change (11/11) : en dernier : reprend la version de « Rendu du body_template » de `harden-notifier-payloads`.
