# Tasks

## 1. Webhook : Content-Type par défaut

- [ ] 1.1 Dans `WebhookNotifier::from_config` (`src/notify/webhook.rs`), insérer `Content-Type: application/json` quand `headers` ne contient pas déjà `CONTENT_TYPE` ; vérifier par des tests unitaires que le `HeaderMap` contient une seule valeur `application/json` sans en-tête configuré, et la valeur configurée (`content-type: text/plain`, casse différente) sinon
- [ ] 1.2 Ajouter dans `tests/integration_notify.rs` des tests wiremock vérifiant l'en-tête `Content-Type: application/json` pour le corps par défaut et pour un `body_template`, et l'absence de doublon quand l'opérateur fournit `Content-Type: text/plain`

## 2. Webhook : `tojson`, avertissement JSON et exemples

- [ ] 2.1 Après rendu, si le `Content-Type` effectif est JSON (`application/json` ou suffixe `+json`, insensible à la casse, paramètres ignorés), valider le corps avec `serde_json::from_str::<serde::de::IgnoredAny>` et journaliser `Webhook body is not valid JSON` en `warn` sans le corps ; l'envoi a toujours lieu ; tests : avertissement présent pour `{"text": "{{ body }}"}` avec un guillemet dans le corps (fonction de détection extraite et testée isolément, aucune dépendance de capture de logs n'étant présente), absent avec `Content-Type: text/plain`, requête émise dans les deux cas
- [ ] 2.2 Test unitaire et wiremock : `{"text": {{ body | tojson }}}` avec un corps contenant `"`, `\` et un saut de ligne produit un JSON valide dont `text` est égal au corps d'origine ; un `body_template` contenant le texte `${ROUTING_KEY}` est toujours envoyé littéralement (comportement inchangé dans ce change)
- [ ] 2.3 Réécrire dans `docs/notifiers.md` les exemples Slack, Discord, PagerDuty et Custom API avec `{{ var | tojson }}` sans guillemets ; PagerDuty sans en-tête `Authorization` et avec `"routing_key": "<your-integration-key>"` (valeur à remplacer, en clair dans la configuration ; aucun `${VAR}` dans le corps, la variante `${PAGERDUTY_ROUTING_KEY}` relevant du change `apply-notifier-overrides`) ; documenter le `Content-Type` par défaut, le filtre `tojson` et l'avertissement JSON ; même correction dans `config/config.example.yaml` ; test unitaire qui rend les exemples de la doc (copiés dans le test) et vérifie que chaque corps rendu est du JSON valide, et vérification que chaque exemple YAML se charge avec `cargo run -- --validate -c <fichier>` sur un fichier de test temporaire

## 3. Telegram : repli en texte brut sur 400 en mode HTML

- [ ] 3.1 Dans `send_to_chat` (`src/notify/telegram.rs`), sur une réponse 400 alors que `parse_mode` vaut `HTML` (insensible à la casse), journaliser `Telegram rejected HTML message, resending as plain text` en `warn` (notifier, règle, statut ; ni jeton, ni URL, ni texte) et renvoyer une seule fois la même requête sans `parse_mode` (champ omis à la sérialisation), soumise à la politique de relance habituelle ; un 4xx au renvoi est un échec définitif `client error: <statut>` ; les autres 4xx et les autres `parse_mode` restent sans repli. La troncature `truncate_text` (4095 points de code + `…`) est conservée telle quelle
- [ ] 3.2 Tests wiremock : 400 puis 200 en mode HTML → 2 requêtes, la seconde sans `parse_mode` et avec le même `text`, discussion réussie ; 400 puis 400 → 2 requêtes et échec ; 400 en `MarkdownV2` → 1 requête ; 403 en HTML → 1 requête ; 400 puis 500 puis 200 → succès (le renvoi suit la politique de relance) ; texte de plus de 4096 points de code avec `<pre>` ouvert, rejeté 400 puis accepté → livré en texte brut et métrique de troncature incrémentée une seule fois ; les tests existants `truncate_text_*` et d'envoi passent toujours
- [ ] 3.3 Mettre à jour `docs/notifiers.md` (section Telegram, « Message length » et gestion des erreurs) : repli en texte brut sur 400 en mode HTML, balises alors affichées littéralement, recommandation d'échapper les valeurs avec `|e` dans les templates personnalisés

## 4. Email : classification SMTP par code de réponse

- [ ] 4.1 Introduire `EmailSendError { permanent: bool, message: String }` et changer `EmailTransport::send_email` en `Result<(), EmailSendError>` ; extraire une fonction pure de classification de l'erreur lettre (`is_permanent()` → 5xx permanent, tout le reste transitoire ; vérifier l'API dans lettre 0.11.23, repli sur `status()`/sévérité du code) utilisée par `SmtpTransport` ; supprimer `is_permanent_error`
- [ ] 4.2 Tests unitaires de la fonction de classification : codes `535`, `550`, `503` permanents ; `454` dont le texte contient `authentication`, `451`, code 4xx dont le texte contient `15501` transitoires ; erreur sans réponse SMTP (réseau, TLS, délai) dont le texte contient `550` transitoire
- [ ] 4.3 Adapter `MockEmailTransport::fail_next` pour recevoir une `EmailSendError` et mettre à jour les tests unitaires existants de la boucle d'envoi (`535`, `550`, partiel, retries) ; ajouter : erreur permanente → 1 tentative, erreur transitoire dont le texte contient `authentication` ou `550` → 3 tentatives (aucun serveur SMTP scripté : la frontière testée est l'abstraction `EmailTransport` existante)
- [ ] 4.4 Documenter dans `docs/notifiers.md` (section Email) la règle de relance : 5xx sans relance, 4xx/réseau/TLS/délai relancés ; corriger au passage la section « Retry Behavior » qui annonce une base de 500 ms pour tous les notifiers alors que l'email utilise 1 s / plafond 30 s

## 5. Mattermost : doc du pied de page

- [ ] 5.1 Corriger la section « Timestamp in Footer » de `docs/notifiers.md` avec le format réel `valerter | <rule_name> | <vl_source> | <log_timestamp_formatted>` (aucun changement de code)

## 6. CHANGELOG et vérification finale

- [ ] 6.1 Ajouter à la section `## [2.1.0]` de `CHANGELOG.md` (la créer si elle n'existe pas) : Fixed — repli Telegram en texte brut sur 400 en mode HTML, classification SMTP par code de réponse, `Content-Type: application/json` par défaut du webhook, exemples JSON de la doc réécrits avec `tojson`, doc du pied de page Mattermost ; Added — avertissement `Webhook body is not valid JSON`
- [ ] 6.2 Vérification finale : `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` et `cargo test` passent
