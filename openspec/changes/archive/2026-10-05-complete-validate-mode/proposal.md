# Proposal

## Why

`valerter --validate` est présenté (docs/configuration.md, docs/architecture.md, README, MIGRATION.md) comme le
contrôle à lancer avant tout déploiement et censé vérifier « Notifier configuration », « Rule destinations exist » et
« Email templates have `email_body_html` ». En réalité il s'arrête après `Config::validate()` : une configuration
dont une règle cible un notifier inexistant, dont un notifier référence une `${VAR}` non définie, dont le
`body_template_file` est absent ou dont un template e-mail n'a pas d'`email_body_html` passe `--validate` avec le
code 0 puis fait échouer le démarrage réel (code 1). Pire, le récapitulatif affiche l'URL de chaque source
VictoriaLogs telle quelle après résolution des variables : `http://user:s3cret@vl:9428?token=abc` sort en clair sur
la sortie standard, souvent capturée par la CI. Les deux constats ont été reproduits sur le binaire actuel.

## What Changes

- `--validate` exécute, en plus du chargement et de la validation, **tous** les contrôles bloquants du démarrage :
  compilation de la configuration, construction de tous les notifiers (résolution des `${VAR}` des secrets de
  notifier, lecture et contrôle de taille/UTF-8 de `body_template_file`, adresses e-mail, en-têtes, méthode HTTP,
  `chat_ids`, templates de notifier…), existence des destinations des règles et présence d'`email_body_html`
  pour les destinations e-mail. Il émet aussi l'avertissement `mattermost_channel ignored …`. Toujours sans démarrer
  le démon, sans serveur de métriques et sans aucun appel réseau.
- Une seule fonction de « pré-vol » partagée par le démarrage du démon et par `--validate`, pour que les deux chemins
  ne puissent plus diverger. Elle collecte les erreurs de toutes les étapes (notifiers, destinations, templates
  e-mail) au lieu de s'arrêter à la première étape en échec ; les messages et le code de sortie (1) restent ceux du
  démarrage actuel.
- Le récapitulatif de `--validate` masque les parties sensibles des URL de sources : identifiants (`userinfo`)
  remplacés par `***`, chaîne de requête remplacée par `***`, fragment supprimé. Il gagne une ligne
  `  Notifiers: <n> [<nom>=<type>, ...]`.
- **BREAKING** (comportement visible, pas de format de configuration) : une configuration qui passait `--validate`
  peut désormais échouer. En particulier, les variables d'environnement référencées par les notifiers doivent être
  définies au moment de `--validate` (pipelines CI qui validaient sans secrets). Documenté dans MIGRATION.md et
  CHANGELOG.md.

Hors périmètre : les nouveaux contrôles de validation au chargement (rendu d'essai des templates, `defaults.throttle`,
revérification du schéma après résolution…) relèvent de `harden-config-validation` ; le masquage de l'URL dans le log
`debug` de connexion du tail n'est pas traité ici.

## Capabilities

### New Capabilities

_Aucune._

### Modified Capabilities

- `cli` : « Mode validation » (contrôles complets, URL masquées, ligne Notifiers) ; suppression de « Périmètre limité
  du mode validation » ; ajout d'un requirement de parité validation/démarrage et d'un requirement de masquage des
  URL de sources dans le récapitulatif.
- `configuration` : « Variables d'environnement dans les notifiers » et « Validations de démarrage dépendant des
  notifiers » ne disent plus que ces contrôles sont exclus de `--validate`.
- `message-templating` : « Corps HTML obligatoire pour les destinations email » est aussi vérifié par `--validate`.
- `notification-dispatch` : « Construction du registre au démarrage avec collecte des erreurs » s'applique aussi à
  `--validate` (le scénario « Mode validation » s'inverse).

## Impact

- Code : `src/main.rs` (chemin `--validate`, extraction des contrôles post-compilation), nouveau module de pré-vol
  (ex. `src/preflight.rs`) exporté par `src/lib.rs`, fonction de masquage d'URL (ex. dans `src/config/secret.rs`).
  Aucune nouvelle dépendance (`reqwest::Url` suffit).
- Tests : `tests/integration_validate.rs` + nouvelles fixtures dans `tests/fixtures/`, tests unitaires du pré-vol et
  du masquage.
- Docs : `docs/configuration.md` (section Validation, options CLI), `docs/architecture.md` (Fail-Fast Validation),
  `docs/getting-started.md`, `examples/multi-source/{README.md,config.yaml}` (commentaire désormais faux sur
  `${WEBHOOK_URL}`), CHANGELOG.md, MIGRATION.md.
- Démon : ordre de démarrage inchangé ; seule différence observable, toutes les erreurs de pré-vol sont journalisées
  avant l'arrêt au lieu de celles de la première étape en échec.
