# Design

## Context

Voir `proposal.md` (section Why) pour la motivation. État du code vérifié avant planification :

- `src/notify/webhook.rs` : `from_config` construit un `HeaderMap` à partir de `headers` uniquement ; `send` envoie
  `body.clone()` sans jamais ajouter `Content-Type`. Le `body_template` est validé puis rendu par un
  `Environment::new()` minijinja. La feature `json` de minijinja est déjà activée dans `Cargo.toml`, donc `tojson` est
  disponible mais n'est utilisé ni documenté nulle part.
- `docs/notifiers.md` et `config/config.example.yaml` : exemples PagerDuty/Slack/Discord/Custom API écrits avec
  `"{{ body }}"` entre guillemets (JSON invalide dès qu'un `"`, un `\` ou un saut de ligne apparaît), PagerDuty avec
  `"routing_key": "${PAGERDUTY_ROUTING_KEY}"` envoyé littéralement et un en-tête `Authorization` inutile pour l'Events
  API v2, Slack/Discord sans `Content-Type`.
- `src/notify/telegram.rs` : `truncate_text` coupe aux 4095 premiers `char` puis ajoute `…`, sans tenir compte du
  `parse_mode` ; une coupure dans `<b>`, `</code>` ou `&amp;` produit un HTML que l'API Bot rejette en 400. Un
  `body_template` personnalisé non échappé (`{{ body }}` contenant `a < b`) provoque le même rejet. `send_to_chat`
  abandonne sur tout 4xx autre que 429 (`client error: <statut>`), donc l'alerte est perdue pour cette discussion.
- `src/notify/email.rs` : le trait `EmailTransport::send_email` renvoie `Result<(), String>` (`e.to_string()` sur
  l'erreur lettre), puis `is_permanent_error` cherche `authentication`, `invalid credentials` ou les codes
  `535/550–554` dans ce texte. Conséquences : un 4xx dont le texte mentionne « authentication » n'est jamais relancé,
  un `503`, `530`, `541`… est relancé trois fois. `MockEmailTransport` pilote déjà les échecs par appel.
- `docs/notifiers.md` (Mattermost) : la section « Timestamp in Footer » annonce `Log time: <ts>` alors que le pied de
  page réel (conforme à la spec) est `valerter | <rule> | <source> | <ts>`.

## Goals / Non-Goals

**Goals:**
- Aucune alerte perdue à cause d'une charge utile mal formée produite par valerter lui-même (`Content-Type` manquant,
  troncature Telegram) ou par un template personnalisé HTML Telegram, ni à cause d'un exemple de la documentation.
- Décisions de relance SMTP fondées sur des données structurées, testables sans dépendre du libellé des erreurs.
- Aucune rupture de compatibilité de configuration.

**Non-Goals:**
- Résolution des `${VAR}` dans le `body_template` webhook et application de `notify.mattermost_channel` : ruptures de
  compatibilité, traitées par le change `apply-notifier-overrides`.
- Rendu d'essai des `body_template` au démarrage, validation de `parse_mode`, noms d'en-têtes (change
  `harden-config-validation`).
- Sémantique des métriques des notifiers (change `fix-metrics-consistency`) : aucun requirement de métrique n'est
  modifié ici.
- Troncature consciente du HTML (pile de balises) ou de `MarkdownV2` : voir décision 3.
- Échappement JSON automatique des variables du `body_template` webhook (voir décision 2).
- Partie `text/plain` des emails : évolution fonctionnelle, hors durcissement.

## Decisions

### 1. `Content-Type: application/json` ajouté à la construction du notifier

Dans `from_config`, après la boucle sur `headers`, insérer `CONTENT_TYPE: application/json` si
`!headers.contains_key(CONTENT_TYPE)` (`HeaderMap` est insensible à la casse, ce qui couvre `content-type`). Le corps
par défaut étant toujours du JSON et l'usage documenté du `body_template` l'étant aussi, `application/json` est le bon
défaut. Alternative écartée : ne l'ajouter que pour le corps par défaut — les exemples Slack/Discord resteraient cassés
et le comportement serait moins prévisible.

### 2. JSON sûr : `tojson` documenté plutôt qu'un auto-escape JSON

minijinja propose `AutoEscape::Json`, mais il sérialise chaque `{{ x }}` en JSON (guillemets compris) : tous les
templates existants `"{{ title }}"` deviendraient `""…""`, une rupture silencieuse et massive. On garde donc le rendu
sans échappement et on fait de `{{ var | tojson }}` (sans guillemets autour) la forme documentée ; tous les exemples
sont réécrits ainsi. `tojson` de minijinja échappe aussi `<`, `>`, `&`, `'` en `\u00XX`, ce qui reste du JSON valide.
Filet de sécurité : après rendu, si le `Content-Type` effectif est JSON (`application/json` ou suffixe `+json`, insensible
à la casse, paramètres ignorés), valider le corps avec `serde_json::from_str::<serde::de::IgnoredAny>` et journaliser
`Webhook body is not valid JSON` en `warn` (champs `notifier_name`, `rule_name`, position de l'erreur serde ; jamais le
corps, qui peut contenir des secrets ou des données de log). La requête part quand même : certains endpoints tolèrent
du JSON approximatif et refuser l'envoi transformerait un avertissement en perte d'alerte.

Exemple PagerDuty : tant que les `${VAR}` du `body_template` ne sont pas résolus (change `apply-notifier-overrides`),
l'exemple porte `"routing_key": "<your-integration-key>"` avec une note indiquant de remplacer la valeur (et que la
clé figure alors en clair dans le fichier de configuration), sans en-tête `Authorization`. Le change
`apply-notifier-overrides` réécrit cet exemple avec `${PAGERDUTY_ROUTING_KEY}`.

### 3. Telegram : repli en texte brut sur 400 en mode HTML, troncature simple conservée

Dans `send_to_chat`, lorsque `parse_mode` vaut `HTML` (insensible à la casse) et que la réponse est un 400, renvoyer une
seule fois la même requête sans le champ `parse_mode` (Telegram traite alors `text` comme du texte brut) et journaliser
en `warn` `Telegram rejected HTML message, resending as plain text` (champs `notifier_name`, `rule_name`, statut ; ni
jeton, ni URL, ni texte). Le renvoi est soumis à la même politique que tout envoi (5xx, 429 et erreurs réseau relancés
dans la limite de 3 tentatives pour ce renvoi) ; un nouveau 4xx sur le renvoi est un échec définitif `client error`. Les
autres 4xx (401, 403, 404) et les autres `parse_mode` gardent le comportement actuel : abandon immédiat.

Pourquoi ce repli plutôt qu'une troncature HTML à pile de balises (approche initialement prévue, abandonnée) :
- la troncature n'est qu'une des causes de 400 ; un `body_template` personnalisé qui insère `{{ body }}` sans `|e`
  produit aussi un HTML invalide dès qu'un log contient `<` ou `&`, et la pile n'y peut rien ;
- reproduire le parseur HTML de Telegram (balises autorisées, attributs, entités nommées et numériques, longueur
  mesurée après parsing) est coûteux et fragile, pour un cas rare (texte > 4096 points de code) ;
- le repli garantit la livraison quelle que soit la cause, pour le prix d'une requête supplémentaire et d'une mise en
  forme dégradée (balises affichées littéralement) uniquement sur les messages déjà rejetés.
La troncature reste donc la coupe simple existante à 4096 points de code (4095 + `…`) ; le texte renvoyé en brut est le
même texte, déjà ≤ 4096 points de code, donc dans la limite.
Coût accepté : un 400 dû à une autre cause (par exemple `chat not found`) entraîne un renvoi inutile, lui aussi rejeté.
Distinguer les causes imposerait d'analyser le champ `description` de la réponse, ce que l'on évite précisément pour
SMTP.

### 4. Erreur de transport email structurée

Remplacer `Result<(), String>` par `Result<(), EmailSendError>` avec `EmailSendError { permanent: bool, message: String }`.
`SmtpTransport` classe l'erreur lettre (`lettre::transport::smtp::Error`) via `is_permanent()` (réponse de classe 5xx) ;
tout le reste (`is_transient()`, timeout, TLS, réseau, erreurs côté client) est transitoire. `is_permanent_error` et sa
recherche de sous-chaînes sont supprimés. La classification est isolée dans une fonction pure
(`classify_smtp_error(&lettre::transport::smtp::Error) -> EmailSendError`, ou à défaut sur le code de réponse extrait),
testée directement. `MockEmailTransport::fail_next` reçoit une `EmailSendError` pour piloter explicitement le cas dans
les tests de la boucle de relance. Vérifier à l'implémentation la présence de `is_permanent()` dans lettre 0.11.23 ; à
défaut, utiliser `status()` et la classe du code (`Severity::PermanentNegativeCompletion`).
Pas de serveur SMTP scripté : la frontière testée est l'abstraction `EmailTransport` existante (boucle de relance) plus
la fonction de classification (décision par code), ce qui couvre la logique sans maintenir un faux serveur.
Alternative écartée : extraire le code des trois premiers chiffres du texte — reste dépendant du format d'affichage de
lettre, exactement ce que l'on veut supprimer.

### 5. Doc Mattermost : pied de page

Correction documentaire seule : la section « Timestamp in Footer » de `docs/notifiers.md` décrit le format réel. Le code
et la spec ne changent pas.

## Risks / Trade-offs

- [Endpoint qui refuse `Content-Type: application/json`] → l'opérateur déclare son propre `Content-Type`, prioritaire ;
  signalé dans le CHANGELOG.
- [Repli Telegram : balises affichées littéralement] → mise en forme dégradée uniquement pour les messages qui auraient
  été perdus ; l'avertissement permet de corriger le template.
- [Repli Telegram : requête supplémentaire sur un 400 sans rapport avec le HTML] → une requête de plus, rejetée à son
  tour ; coût négligeable.
- [Avertissement JSON à chaque alerte pour un template cassé] → bruit volontaire ; il disparaît dès que le template
  utilise `tojson`.
- [Classification SMTP plus stricte sur les 5xx] → un `503`/`530` n'est plus relancé ; c'est le comportement correct
  d'un code permanent.

## Migration Plan

Déploiement par mise à jour du binaire/.deb, sans nouvelle clé ni rupture. Le CHANGELOG (section 2.1.0) signale le
`Content-Type` par défaut, le repli Telegram et recommande la réécriture des templates JSON avec `tojson`. Retour
arrière : réinstaller la version précédente ; aucune donnée persistée n'est concernée.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`  ← ce change
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (8/11) : précède `fix-metrics-consistency` (mêmes fichiers de notifiers) et `apply-notifier-overrides`, qui modifie à son tour « Rendu du body_template » en reprenant cette version.
