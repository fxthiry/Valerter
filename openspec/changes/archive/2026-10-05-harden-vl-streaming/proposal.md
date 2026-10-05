# Proposal

## Why

La lecture du flux `/select/logsql/tail` perd ou corrompt des données dans des cas limites vérifiés dans `src/stream_buffer.rs` et `src/tail.rs` : une seule ligne non UTF-8 fait jeter tout le lot (lignes valides comprises) ; une ligne de plus de 1 Mio fait jeter le fragment réseau entier (avec les lignes valides qu'il contient) puis la fin de cette ligne est émise comme une ligne tronquée, qui part au parsing et peut produire une alerte sur un JSON partiel ou un `invalid_json` trompeur. S'y ajoutent des défauts d'ergonomie qui gênent le diagnostic : `url` terminée par `/` qui produit `//select/...`, en-têtes personnalisés qui s'ajoutent en double aux en-têtes standard ou à la Basic Auth au lieu de les remplacer, journal de la cause d'échec écrit après l'attente du backoff (jusqu'à 60 s de retard), délai journalisé en secondes entières (`delay_secs=0` pour 900 ms) et premier EOF vide attendu 2 s au lieu de 1 s.

## What Changes

- Découpage ligne par ligne : chaque ligne complète est décodée en UTF-8 indépendamment ; une ligne invalide est seule abandonnée (comptée une fois dans `valerter_lines_discarded_total{reason="invalid_utf8"}`), les lignes valides du même lot et le fragment non terminé sont conservés.
- Lignes trop longues : la limite de 1 Mio s'applique à la longueur d'une ligne, pas au tampon augmenté du fragment reçu ; une ligne qui la dépasse est abandonnée en entier, y compris sa fin reçue plus tard (mode « ignorer jusqu'au prochain `\n` »), sans jamais émettre de ligne tronquée ni perdre les lignes valides voisines ; un seul incrément `reason="oversized"` par ligne.
- URL de source : les `/` finaux de `victorialogs.<source>.url` sont retirés avant la concaténation de `/select/logsql/tail`.
- En-têtes : les en-têtes de `victorialogs.<source>.headers` remplacent (comparaison insensible à la casse) les en-têtes standard (`Accept`, `Connection`) et l'en-tête `Authorization` issu de `basic_auth` au lieu de les dupliquer ; un avertissement (sans valeur) signale qu'un `Authorization` personnalisé masque `basic_auth`. Garde défensive : un en-tête invalide sera refusé dès le chargement de la configuration par `harden-config-validation` (implémenté après ce change) ; si un nom ou une valeur invalide parvient malgré tout au démarrage d'une tâche, celle-ci échoue avec une erreur nommant l'en-tête sans sa valeur, au lieu d'une boucle de reconnexion sans fin.
- Journaux de reconnexion : la cause (`Connection failed` / `Stream read error`) est journalisée avant `Connection failed, retrying` et avant l'attente ; le champ `delay_secs` est remplacé par `delay_ms` (**BREAKING** mineur pour qui filtre les journaux sur ce champ).
- Fin de flux vide : délai d'environ 1 s, 2 s, 4 s… (au lieu de 2 s, 4 s, 8 s…) selon le nombre de fins de flux vides consécutives.
- Tests unitaires et wiremock, `docs/`, `CHANGELOG.md` et `MIGRATION.md` mis à jour.

## Capabilities

### New Capabilities

_Aucune._

### Modified Capabilities

- `victorialogs-streaming` : requirements « Requête vers l'endpoint tail » (normalisation du `/` final), « En-têtes personnalisés par source » (remplacement au lieu de duplication), « Journalisation et comptage des tentatives de reconnexion » (ordre et délai en ms), « Fin de flux propre avec backoff » (premier EOF vide à 1 s), « UTF-8 invalide non fatal » (seule la ligne fautive est abandonnée), « Lignes trop longues » (limite par ligne, fin de ligne ignorée).

## Impact

- Code : `src/stream_buffer.rs` (nouvelle API de découpage avec état « abandon en cours » et décodage par ligne), `src/tail.rs` (helper commun de traitement des fragments pour `connect_and_receive` et `stream_with_reconnect`, `build_url`, en-têtes pré-construits dans `TailClient::new`, ordre des journaux, délai EOF), `src/engine.rs` (avertissement `Authorization` masquant `basic_auth`, avec le nom de la source), `src/error.rs` si des variantes deviennent inutiles.
- Tests : `src/stream_buffer.rs` (tests unitaires, couverture 100 % visée par AD-01), `src/tail.rs`, `tests/integration_streaming.rs` (wiremock).
- Docs : `docs/configuration.md` (section sources VictoriaLogs : `url`, `headers`), `docs/metrics.md` (sémantique de `valerter_lines_discarded_total`), `docs/architecture.md` (stratégie de reconnexion), `CHANGELOG.md`, `MIGRATION.md`.
- Aucune dépendance nouvelle (`reqwest::header` déjà disponible). Aucun changement de schéma de configuration.
