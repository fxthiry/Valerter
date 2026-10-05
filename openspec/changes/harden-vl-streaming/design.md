# Design

## Context

Voir proposal.md (Why). État actuel vérifié dans le code :

- `StreamBuffer::push` refuse un fragment dès que `tampon + fragment > 1 Mio` et vide le tampon : le fragment entier est perdu (lignes complètes qu'il contenait comprises) et rien ne mémorise qu'une ligne est en cours d'abandon, donc la fin de cette ligne, au fragment suivant, est émise comme une ligne à part entière.
- `StreamBuffer::drain_complete_lines` décode d'un bloc tout ce qui précède le dernier `\n` (`String::from_utf8`) ; en cas d'erreur, `drain_lines_lenient` (`src/tail.rs`) vide tout le tampon. Le découpage sur l'octet `0x0A` est pourtant sûr en UTF-8 (cet octet n'apparaît jamais dans une séquence multi-octets) : seul le fragment final non terminé peut contenir un caractère incomplet, et `find_safe_utf8_boundary` est inutile dès lors qu'on ne décode que des lignes complètes.
- Le traitement des fragments (push, gestion `oversized`, drain, filtrage des lignes vides) est dupliqué entre `connect_and_receive` (utilisée par les tests d'intégration) et `stream_with_reconnect`.
- `build_url` concatène `base_url` tel quel ; `build_request` utilise `RequestBuilder::header`, qui ajoute (`append`) sans remplacer, et `basic_auth` ajoute lui aussi un `Authorization`.
- Branches « erreur de connexion » et « erreur en cours de flux » : `log_reconnection_attempt` → `sleep` → `warn!("Connection failed" | "Stream read error")`. `log_reconnection_attempt` journalise `delay_secs = delay.as_secs()`.
- Fin de flux vide : `empty_eof_streak` est incrémenté avant `backoff_delay_with_jitter(empty_eof_streak)`, d'où un premier délai de 2 s.
- `TailClient::new` peut déjà échouer (`StreamError::ConnectionFailed`), ce qui fait échouer la tâche via `RuleError::Stream` (erreur fatale comptée dans `valerter_rule_errors_total`).

## Goals / Non-Goals

**Goals:**
- Un seul chemin de traitement des fragments, testable unitairement sans réseau.
- Perte de données limitée à la ligne fautive ; aucune ligne tronquée émise.
- Mémoire par connexion bornée à la limite de ligne (plus le fragment en cours de traitement).

**Non-Goals:**
- Validation des noms et valeurs d'en-têtes au chargement de la configuration et dans `--validate` : c'est `harden-config-validation`, implémenté après ce change, qui refuse un en-tête invalide au chargement. Ce change n'en garde qu'une garde défensive au démarrage de la tâche (D4).
- Masquage des URL dans les journaux (change `complete-validate-mode`) ; sémantique de `valerter_reconnections_total` sur EOF propre et initialisation de la série `reason="invalid_utf8"` (change `fix-metrics-consistency`).
- Rendre la limite de 1 Mio configurable.
- Normaliser une `url` contenant une requête (`?`) ou un fragment (`#`) : hors périmètre, l'URL est supposée être une base sans paramètres.

## Decisions

### D1. Nouvelle API de `StreamBuffer` : un seul appel par fragment

`StreamBuffer::process_chunk(&mut self, chunk: &[u8]) -> ChunkOutcome` remplace le couple `push` + `drain_complete_lines` :

```rust
pub struct ChunkOutcome {
    pub lines: Vec<String>,          // lignes valides non vides, dans l'ordre
    pub invalid_utf8: usize,         // lignes abandonnées pour UTF-8 invalide
    pub oversized: Vec<usize>,       // une entrée par ligne trop longue détectée (taille observée)
}
```

Algorithme (un passage sur le fragment, sans copier les octets abandonnés) :
1. Si l'état `discarding` est actif : chercher le premier `\n` du fragment ; absent → tout ignorer et retourner ; présent → ignorer jusqu'à lui inclus, sortir de `discarding`, continuer avec le reste.
2. Pour chaque segment terminé par `\n` du reste : ligne = tampon + segment. Si sa longueur dépasse `MAX_LINE_SIZE`, l'enregistrer dans `oversized` et l'ignorer ; sinon retirer un `\r` final, ignorer si vide, décoder avec `std::str::from_utf8` (échec → `invalid_utf8 += 1`), puis vider le tampon.
3. Pour le reste non terminé : si `tampon + reste > MAX_LINE_SIZE`, vider le tampon, enregistrer la taille dans `oversized` et passer en `discarding` ; sinon l'ajouter au tampon.

`clear()` vide le tampon et remet `discarding` à faux (appelé à chaque nouvelle connexion). `find_safe_utf8_boundary` et `StreamError::LineTooLarge` / `StreamError::Utf8Error` deviennent inutiles : ils sont supprimés s'ils ne servent plus ailleurs (`src/error.rs` et ses tests). `StreamBuffer` est `pub` mais n'est utilisé que dans le crate : la rupture d'API interne est acceptée.

*Alternatives écartées* : garder `push`/`drain` et ajouter un drapeau — deux appels dont l'ordre et les erreurs sont faciles à mal combiner ; `String::from_utf8_lossy` — introduirait des caractères de remplacement, interdit par la spec.

*Longueur de ligne* : octets avant le `\n`, `\r` compris (règle simple et vérifiable ; l'écart d'un octet est sans importance pratique).

### D2. Helper unique dans `tail.rs`

`fn process_chunk_logged(buffer, chunk, rule_name, vl_source) -> Vec<String>` appelle `process_chunk`, puis :
- pour chaque entrée de `oversized` : `warn!("Discarding oversized log line, buffer cleared", size_bytes, max_bytes)` et `valerter_lines_discarded_total{reason="oversized"}` +1 (message conservé pour ne pas casser les filtres existants ; une ligne trop longue produit au plus une entrée, donc pas de rafale) ;
- si `invalid_utf8 > 0` : un seul `warn!("Discarding log data with invalid UTF-8", discarded_lines)` et le compteur `reason="invalid_utf8"` + `invalid_utf8`.

Utilisé par `connect_and_receive` et `stream_with_reconnect` ; `drain_lines_lenient` disparaît. L'avertissement UTF-8 est agrégé par fragment pour éviter qu'un flux binaire inonde les journaux.

### D3. Normalisation de l'URL dans `build_url`

`self.config.base_url.trim_end_matches('/')` dans `build_url` plutôt que dans `TailConfig::from_source`, pour couvrir aussi les `TailConfig` construits directement (tests, exemple de doc). Pas de modification de la valeur en configuration ni de la validation.

### D4. En-têtes pré-construits dans `TailClient::new`

`TailClient::new` construit une fois un `reqwest::header::HeaderMap` : `Accept`, `Connection`, puis `Authorization` Basic (encodage base64 identique à reqwest, valeur marquée `set_sensitive(true)`), puis les en-têtes personnalisés via `HeaderMap::insert` (remplacement, noms normalisés en minuscules par `HeaderName`, donc insensible à la casse ; valeurs marquées sensibles). Les en-têtes personnalisés sont appliqués dans l'ordre alphabétique de leur nom pour qu'un doublon de casse dans la configuration (`X-Tenant` et `x-tenant`) donne un résultat déterministe (le cas sera rejeté au chargement par `harden-config-validation`, si ce change le couvre). `build_request` passe la map via `RequestBuilder::headers` (qui remplace les clés présentes).

Si un en-tête personnalisé `authorization` remplace celui de `basic_auth`, un `warn!` est journalisé avec `rule_name` et `vl_source` (aucun nom d'utilisateur ni valeur). `TailClient` ne connaissant pas le nom de la source, `TailConfig` expose un prédicat `custom_authorization_overrides_basic_auth()` que `src/engine.rs` consulte juste avant `TailClient::new` pour émettre l'avertissement. Il est émis une fois par tâche (règle, source), acceptable car au démarrage seulement.

Nom ou valeur invalide (garde défensive) : en régime nominal, un en-tête invalide n'atteint jamais `TailClient::new`, car `harden-config-validation` (implémenté après ce change) le refuse au chargement de la configuration et dans `--validate`. Les deux mécanismes sont complémentaires : la validation au chargement donne l'erreur à l'opérateur avant tout démarrage, la garde ci-dessous protège le chemin d'exécution si un en-tête invalide passe malgré tout (configuration construite sans passer par le chargement, tests, régression de la validation) et couvre la période où ce change est livré sans l'autre. `TailClient::new` retourne `StreamError::ConnectionFailed("invalid header '<nom>' in VictoriaLogs source configuration")` (jamais la valeur ; pour un nom invalide, le nom est tronqué à 64 caractères). Aujourd'hui la même configuration produit une boucle de reconnexion infinie sans qu'aucune requête ne parte ; échouer tôt rend l'erreur visible (`Rule task failed fatally`, `valerter_rule_errors_total`). Ce change ne formule pas de règle de validation de configuration, pour ne pas chevaucher `harden-config-validation`.

*Alternatives écartées* : construire la map à chaque requête — coût inutile et erreur répétée à chaque tentative ; ignorer l'en-tête invalide avec un avertissement — enverrait des requêtes sans authentification (boucle de 401 moins lisible).

### D5. Ordre des journaux et délai en millisecondes

Dans les branches « erreur de connexion » et « erreur en cours de flux », le `warn!` de cause est déplacé avant `log_reconnection_attempt` et le `sleep`. `log_reconnection_attempt` journalise `delay_ms = delay.as_millis()` à la place de `delay_secs` (pas de double champ : un seul nom évite l'ambiguïté ; la rupture est documentée dans `MIGRATION.md`).

### D6. Premier EOF vide à 1 s

Le délai après une fin de flux vide devient `backoff_delay_with_jitter(empty_eof_streak - 1)` après incrément (soit 1 s, 2 s, 4 s…) ; après une connexion avec données, `empty_eof_streak = 0` et le délai reste `backoff_delay_with_jitter(0)` (≈ 1 s). Le champ debug `empty_eof_streak` et le compteur `valerter_reconnections_total` sont inchangés.

## Risks / Trade-offs

- [Une ligne de taille proche de la limite reste en mémoire jusqu'à 1 Mio par tâche] → inchangé par rapport à aujourd'hui ; la mémoire n'est plus doublée par la copie d'un fragment voué à l'abandon.
- [Un `Authorization` personnalisé masque désormais `basic_auth` alors qu'aujourd'hui les deux partaient (et le serveur choisissait)] → avertissement au démarrage, mention dans `MIGRATION.md` et `docs/configuration.md`.
- [En-tête invalide qui atteindrait malgré tout le démarrage d'une tâche : la tâche passe de « boucle infinie » à « erreur fatale »] → garde défensive seulement, le refus nominal ayant lieu au chargement (`harden-config-validation`) ; message explicite ; en pratique ces requêtes n'aboutissaient jamais. La politique de sortie du démon quand des tâches meurent relève de `fix-daemon-exit-codes`.
- [Renommage `delay_secs` → `delay_ms` casse un éventuel filtre de journaux] → `MIGRATION.md` et `CHANGELOG.md`.
- [Le compteur `invalid_utf8` compte désormais des lignes et non des lots : sa valeur augmente plus vite pour un même flux] → conforme à la définition d'observability (« pour une ligne non UTF-8 ») ; noté dans `CHANGELOG.md`.

## Migration Plan

Aucune action de configuration requise. Livraison dans la version 2.1.0. Retour arrière : réinstaller la version précédente, aucun état persistant.

## Ordre d'implémentation

Les 11 changes sont livrés ensemble dans la version **2.1.0** (une seule section CHANGELOG et MIGRATION). Ordre d'implémentation et d'archivage :

1. `fix-daemon-exit-codes`
2. `harden-vl-streaming`  ← ce change
3. `complete-validate-mode`
4. `fix-cross-source-throttle-dedup`
5. `isolate-notifier-delivery`
6. `drain-notification-queue-on-shutdown`
7. `nonblocking-panic-supervision`
8. `harden-notifier-payloads`
9. `harden-config-validation`
10. `fix-metrics-consistency`
11. `apply-notifier-overrides`

Pour ce change (2/11) : s'archive avant `fix-metrics-consistency`, qui modifie à son tour « Fin de flux propre avec backoff » en reprenant cette version.
