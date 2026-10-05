# Design

## Context

Voir proposal.md (Why). État actuel dans `src/main.rs` :

- `main()` : `Config::load` → `config.validate()` → si `--validate`, affichage du récapitulatif et `return` ;
  sinon `config.compile()` → création du runtime Tokio multi-thread → `run()`.
- `run()` : client HTTP partagé (timeout 10 s) → file → `create_notifier_registry()` (collecte déjà toutes les
  erreurs d'instanciation) → `validate_rule_destinations()` (noms du **registre**) → `validate_email_templates()`
  (types lus dans le **registre**) → `warn_unused_mattermost_channels()` → métriques, moteur, worker.
  Chaque étape en échec fait `return Err(...)` : les étapes suivantes ne sont pas évaluées.
- Les constructeurs de notifiers (`*::from_config`) ne font aucun appel réseau : `resolve_env_vars`,
  `resolve_body_template` (lecture de fichier), parsing d'adresses, `AsyncSmtpTransport::builder_dangerous(...)`
  (lettre sans la feature `pool`, donc sans tâche de fond), construction d'URL. Vérifié en lançant le démon sur
  les fixtures et exemples livrés : tous passent ces étapes.
- Les URL de sources sont résolues au chargement (`Config::resolve_source_env_vars`) et affichées brutes par le
  récapitulatif.

## Goals / Non-Goals

**Goals:**

- Un seul code de « pré-vol » appelé par les deux chemins, de sorte qu'un contrôle ajouté plus tard au démarrage
  soit automatiquement couvert par `--validate`.
- Rapport complet : toutes les erreurs de toutes les étapes de pré-vol en une passe.
- Aucun secret sur stdout/stderr en mode `--validate`.

**Non-Goals:**

- Modifier l'ordre de démarrage du démon décrit dans `rule-engine` (« Séquence de démarrage ») : le pré-vol reste
  appelé au même endroit dans `run()`.
- Tester la joignabilité des sources ou des notifiers (pas d'option `--check-connectivity`).
- Ajouter des contrôles nouveaux au chargement (périmètre de `harden-config-validation`).
- Masquer l'URL dans le log `debug` « Connecting to VictoriaLogs tail endpoint » de `src/tail.rs`.

## Decisions

### D1. Module de pré-vol partagé dans la bibliothèque

Nouveau module `src/preflight.rs` (exporté par `lib.rs`) exposant, en substance :

```rust
pub struct PreflightReport { pub registry: NotifierRegistry }
pub enum PreflightError { Notifiers(usize), Destinations(usize), EmailTemplates(usize) }
pub fn build_http_client() -> reqwest::Result<reqwest::Client>; // timeout 10 s, partagé
pub fn run_preflight(cfg: &RuntimeConfig, http: reqwest::Client) -> Result<PreflightReport, PreflightError>;
```

`run_preflight` déplace dans la bibliothèque `create_notifier_registry`, `validate_email_templates` et
`warn_unused_mattermost_channels` (aujourd'hui privés dans `main.rs`, donc non testables unitairement) et appelle
`RuntimeConfig::validate_rule_destinations`. Il journalise chaque erreur avec les messages actuels
(`Notifier configuration error`, `Destination validation error`, `Email template validation error`).
`PreflightError` implémente `Display` en reproduisant exactement les messages actuels de fin
(`Failed to create notifiers: N errors`, `Destination validation failed: N errors`,
`Email template validation failed: N errors`) ; quand plusieurs étapes échouent, c'est la première dans cet ordre qui
est retournée, ce qui garde intacts les scénarios existants de `rule-engine`.

*Alternative écartée* : dupliquer les appels dans la branche `--validate` de `main()`. Rapide mais c'est exactement
la divergence qui a produit le bug.

### D2. Les contrôles de destinations et d'e-mail s'appuient sur les notifiers **déclarés**

Pour pouvoir évaluer toutes les étapes même si un notifier échoue à se construire, la liste des noms valides et le
type de chaque destination sont lus dans `RuntimeConfig.notifiers` (`NotifierConfig::Email`, `::Mattermost`, …) et
non plus dans le registre. Effet : un notifier déclaré mais en échec ne produit pas de faux « unknown notifier », et
l'erreur `email_body_html` reste signalée pour lui. Le résultat est identique au comportement actuel quand tous les
notifiers se construisent (le registre contient exactement les noms déclarés). Une petite méthode
`NotifierConfig::type_name()` (`"mattermost"`, `"webhook"`, `"email"`, `"telegram"`) aligne les chaînes sur
`Notifier::notifier_type()`.

*Alternative écartée* : s'arrêter à la première étape en échec (comportement actuel) ; acceptable pour le démon
mais contraire à l'usage de `--validate` (un aller-retour par erreur).

### D3. Chemin `--validate`

```
load → validate → compile → runtime current_thread → block_on(run_preflight(build_http_client()))
     → récapitulatif → exit 0        (toute erreur → exit 1, rien sur stdout)
```

`config.compile()` est maintenant exécuté aussi en validation (il était sauté). Le pré-vol tourne dans un runtime
Tokio `current_thread` léger plutôt qu'en contexte synchrone pur : cela reproduit les conditions du démon et évite
une panique si une dépendance future venait à exiger un runtime à la construction (par ex. activation de la feature
`pool` de lettre). Aucun serveur de métriques n'est démarré, aucun moteur ni worker n'est créé ; le compteur
`valerter_notifier_config_errors_total` incrémenté par le registre est un no-op faute de recorder.

Le démon garde sa séquence : dans `run()`, les trois appels actuels sont remplacés par `run_preflight` avec le client
partagé (créé par `build_http_client()`), puis `Arc::new(report.registry)`.

En cas d'échec en mode validation, aucun nouveau message n'est introduit (en particulier pas de
`Configuration validation failed`, réservé aux erreurs de `Config::validate`) : on garde exactement les messages du
démarrage et on retourne l'erreur, qu'`anyhow` affiche (`Error: <message>`), avec le code 1, comme le démon.

### D4. Masquage des URL de sources

Fonction pure `redact_url(&str) -> String` (dans `src/config/secret.rs`, à côté de `SecretString`) :

- parse avec `reqwest::Url` (pas de nouvelle dépendance) ;
- si l'URL n'a ni `username`, ni `password`, ni `query`, ni `fragment` → renvoie la chaîne d'origine inchangée
  (pas de normalisation visible, ex. pas de `/` ajouté) ;
- sinon : `set_username("***")`, `set_password(None)`, `set_query(Some("***"))` si une requête existait,
  `set_fragment(None)`, puis `to_string()` (forme normalisée, ex. `http://***@vl.example.com:9428/?***`) ;
- si le parsing échoue (impossible après `validate()`, défensif) → `<invalid URL>`.

Le récapitulatif utilise `redact_url(&src.url)`. Les `basic_auth` et `headers` des sources ne sont pas affichés
(inchangé).

### D5. Ligne `Notifiers` dans le récapitulatif

`  Notifiers: <n> [<nom>=<type>, ...]`, triée par nom, insérée après `Templates`. Les noms viennent du registre
construit (donc seulement en cas de succès). Pas d'URL ni de destination affichée.

## Risks / Trade-offs

- [Pipelines CI qui lançaient `--validate` sans secrets] → **rupture visible** documentée dans MIGRATION.md et
  CHANGELOG.md, avec la consigne d'exporter des valeurs factices (comme le fait déjà
  `tests/integration_validate.rs::shipped_examples_pass_validate`).
- [Scripts qui analysent la sortie du récapitulatif] → une ligne `Notifiers` est ajoutée et le format des URL
  sensibles change ; documenté dans CHANGELOG.md. L'ordre des lignes existantes est conservé.
- [Lecture de `body_template_file` avec des droits différents] → `--validate` lancé par un autre utilisateur que
  `valerter` peut échouer sur un fichier lisible par le service ; c'est la même lecture que le démarrage, le
  message d'erreur indique le chemin. Mentionné dans la doc.
- [Démon : rapport d'erreurs plus long] → seul changement observable côté démon ; messages et code de sortie
  inchangés.
- [`redact_url` normalise l'URL quand il masque] → acceptable : seule la forme affichée change, jamais l'URL utilisée.

## Migration Plan

Pas de changement de format de configuration. Livraison en 2.1.0 (entrées dans la section `## [2.1.0]` du
CHANGELOG et dans la section « Upgrading to 2.1.0 » de MIGRATION.md). Retour arrière : réinstaller la version
précédente ; aucune donnée persistante n'est touchée.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`
3. `complete-validate-mode`  ← ce change
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (3/11) : précède `harden-config-validation`, qui s'appuie sur le pré-vol introduit ici.
