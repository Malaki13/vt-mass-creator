<div align="center">

# VirusTotal Mass Account Creator

**Création de comptes VirusTotal Community en pur Python — aucun navigateur, aucun Selenium/Playwright.**

Chaque compte récupère sa propre clé API ; les clés servent ensuite à voter et commenter sur un hash.

[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![requests](https://img.shields.io/badge/HTTP-requests-2E8B57)](https://requests.readthedocs.io/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF)](https://developers.virustotal.com/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

</div>

---

## Aperçu

`vt_mass_creator.py` automatise tout le cycle de vie d'un compte VirusTotal Community :

1. **Identité** aléatoire crédible (prénom, nom, username, mot de passe fort) ;
2. **Logo** attribué à chaque compte (dossier local ou génération DiceBear) ;
3. **Email** temporaire mail.tm ou catch-all IMAP d'un domaine perso ;
4. **Captcha** reCAPTCHA Enterprise résolu par 2captcha ;
5. **Inscription**, lecture de l'email d'activation, activation ;
6. **Connexion**, récupération de la clé API personnelle ;
7. **Photo de profil** uploadée sur VirusTotal.

Le résultat est un fichier `accounts.jsonl` + `accounts.csv` contenant email, mot de passe, clé API, cookies de session et statut.

Trois modes complémentaires utilisent ensuite ces comptes :

| Mode | Rôle |
|---|---|
| `vote` | un vote par compte sur un hash (score communautaire) |
| `comment` | commentaires en masse répartis sur tous les comptes |
| `signin` | récupère les clés API des comptes activés mais non connectés |

---

## Installation

```bash
git clone https://github.com/Malaki13/vt-mass-creator.git
cd vt-mass-creator
python -m pip install -r requirements.txt
```

Prérequis : Python 3.10+ et une clé [2captcha](https://2captcha.com/).

---

## Démarrage rapide

```bash
python vt_mass_creator.py --count 5 --captcha-key TA_CLE_2CAPTCHA
```

Ou via variable d'environnement :

```bash
export CAPTCHA_API_KEY="TA_CLE_2CAPTCHA"   # PowerShell : $env:CAPTCHA_API_KEY="..."
python vt_mass_creator.py --count 10
```

Chaque compte coûte **2 à 8 captchas** (inscription + connexion), soit environ
**0,006 à 0,025 $ par compte**. VirusTotal peut refuser un token : l'outil re-solve
automatiquement (7 essais à l'inscription, 5 à la connexion).

---

## Options

| Option | Défaut | Description |
|---|---|---|
| `--count` | `5` | nombre de comptes à créer |
| `--workers` | `3` | comptes traités en parallèle |
| `--captcha-key` | `$CAPTCHA_API_KEY` | clé 2captcha |
| `--logo-dir` | `logos/` | dossier d'images (png/jpg/webp/gif) |
| `--no-avatar` | — | ne pas uploader de photo de profil |
| `--output` | `accounts.jsonl` | fichier de sortie JSONL |
| `--csv` | `accounts.csv` | fichier de sortie CSV |
| `--mail-provider` | `mailtm-pool` | `mailtm-pool`, `mailtm` ou `imap` |
| `--mailtm-batch` | `40` | comptes par boîte mail.tm mutualisée |
| `--email-domain` | domaine mail.tm | domaine email |
| `--activation-timeout` | `240` | attente max de l'email d'activation (s) |
| `--signup-retries` | `7` | essais captcha à l'inscription |
| `--signin-retries` | `5` | essais captcha à la connexion |
| `--proxy-file` | — | un proxy HTTP par ligne |
| `--delay` | `0` | pause avant chaque compte (s) |
| `--request-timeout` | `60` | timeout HTTP (s) |

Exemple avec logos personnalisés et plus de parallélisme :

```bash
python vt_mass_creator.py --count 20 --workers 4 --logo-dir logos --delay 2
```

---

## Email

VirusTotal refuse beaucoup de domaines jetables. Testés en conditions réelles :
`inboxkitten.com`, `maildrop.cc`, `guerrillamailblock.com`, `gmeenramy.com`
(temp-mail.io), `fexpost.com` et `merepost.com` (tempmail.plus) renvoient
**HTTP 400 « The email you used is not valid »**. Les domaines mail.tm
(`euploading.com`) passent.

### Pool mail.tm (recommandé)

Le mode `mailtm-pool` crée **une seule boîte** et distribue des alias illimités :

```text
base+username@euploading.com
```

Tous les emails arrivent dans la boîte de base ; l'outil décode le token
d'activation pour le rattacher au bon compte. Une boîte suffit pour
`--mailtm-batch` comptes (40 par défaut), ce qui évite le rate limit `429` de
création. Aucun captcha supplémentaire.

### Catch-all IMAP

```bash
python vt_mass_creator.py --count 20 \
  --mail-provider imap \
  --email-domain mondomaine.com \
  --imap-host imap.mondomaine.com --imap-port 993 \
  --imap-user contact@mondomaine.com --imap-pass "MOT_DE_PASSE"
```

Chaque adresse générée (`prenomnom12345@mondomaine.com`) doit arriver dans la
boîte IMAP indiquée (catch-all ou alias). L'outil cherche l'email
`VirusTotal Community account activation` et extrait le lien.

Pour l'ancien comportement (une boîte par compte) : `--mail-provider mailtm`.

---

## Proxies

```text
# proxies.txt
http://user:pass@1.2.3.4:8080
http://5.6.7.8:3128
```

```bash
python vt_mass_creator.py --count 50 --proxy-file proxies.txt
```

Les proxies sont répartis en round-robin. Privilégier des proxies
**résidentiels / propres** : un proxy datacenter déjà flaggé par VirusTotal peut
renvoyer `RecaptchaRequiredError` même avec un token valide.

---

## Résultat

`accounts.jsonl` (une ligne JSON par compte) et `accounts.csv` :

| Champ | Contenu |
|---|---|
| `user_id` | username VirusTotal |
| `email`, `password` | identifiants du compte |
| `apikey` | clé API personnelle (vide si échec) |
| `cookies` | cookies de session VT |
| `mail_base` | boîte mail.tm de base (mode pool) |
| `mail_token` | token mail.tm pour relire la boîte |
| `avatar`, `avatar_uploaded` | logo local et statut d'upload |
| `status` | `active`, `pending_activation`, `duplicate`, `error` |
| `error` | détail en cas d'échec |

---

## Voter sur un hash

```bash
python vt_mass_creator.py --mode vote \
  --hash 976e1b0821ef888a57cfca3143a31683a1a5b02408c55430df754648058e1789 \
  --verdict harmless
```

Options : `--accounts accounts.jsonl`, `--workers 8`, `--verdict malicious`.

Pour joindre un commentaire crédible à chaque vote, fournir un fichier de
messages pré-écrits (un par ligne, un est tiré au hasard par compte) :

```bash
python vt_mass_creator.py --mode vote \
  --hash 7759f6c527c201b2b8f9a54dc9f5f70e9f0dc558e274675e298fbd23d55c4aa8 \
  --verdict harmless --comments-file comments.txt
```

`--comment "texte"` poste le même message avec tous les comptes.

Chaque compte ne peut voter qu'une fois par fichier ; un `409` signifie
« déjà voté ». Le score communautaire est la somme des votes.

---

## Commentaires en masse

`comments_500.txt` contient **500 commentaires uniques et variés** (court,
technique, casual, faux positif, usage, français, question, vérification de
hash), générés par `generate_comments.py`.

```bash
python vt_mass_creator.py --mode comment \
  --hash 7759f6c527c201b2b8f9a54dc9f5f70e9f0dc558e274675e298fbd23d55c4aa8 \
  --comments-file comments_500.txt --total-comments 500 --workers 12
```

Chaque compte poste plusieurs commentaires (répartition round-robin). Les
commentaires et votes passent d'abord par l'endpoint **UI avec la session
cookie** du compte, ce qui évite le quota de l'API publique
(`QuotaExceededError` sur les commentaires) ; fallback API si la session a
expiré. `--total-comments` permet de n'en poster qu'une partie.

---

## Récupérer les clés API manquantes

Après un run de masse, certains comptes peuvent être activés mais avoir échoué
au login (403 / captcha). Pour ne relancer que cette étape :

```bash
python vt_mass_creator.py --mode signin
```

Le script reprend tous les comptes de `accounts.jsonl` qui ont un email et un
mot de passe mais pas encore de clé API, refait le login et met à jour les
fichiers JSONL/CSV.

---

## Endpoints utilisés

- `POST https://www.virustotal.com/ui/signup`
- `POST https://www.virustotal.com/ui/signup/confirm`
- `POST https://www.virustotal.com/ui/signin`
- `POST https://www.virustotal.com/ui/users/{id}/avatar`
- `POST https://www.virustotal.com/api/v3/files/{hash}/votes`
- `POST https://www.virustotal.com/api/v3/files/{hash}/comments`
- `https://2captcha.com/in.php` / `res.php` (inscription, `action=checkbox`)
- `https://api.2captcha.com/createTask` / `getTaskResult` (connexion v3)
- `https://api.mail.tm/*`

### Notes techniques

1. Le captcha d'inscription est un reCAPTCHA **Enterprise checkbox** : il faut
   `action=checkbox` **sur l'API legacy `in.php`** (l'API JSON `createTask`
   transmet mal ce champ) **et** le paramètre dynamique `data-s` récupéré sur
   l'anchor Google. Sans `data-s`, VT répond `RecaptchaRequiredError` malgré un
   token valide.
2. Même avec le bon token, VT peut refuser un essai (score Enterprise) :
   l'outil re-solve jusqu'à 7 fois à l'inscription et 5 fois à la connexion.

---

## Dépannage

| Symptôme | Piste |
|---|---|
| `RecaptchaRequiredError` | re-solve automatique ; si tout échoue, tester sans proxy puis vérifier le solde 2captcha |
| `mail.tm rate limit` | mode `mailtm-pool` : une boîte par lot de 40 comptes, lectures throttlées à ~1/s, 429 rejoués |
| `pending_activation` | email non reçu dans le délai ; le compte existe, relancer l'activation via `mail_token` ou augmenter `--activation-timeout` |
| `duplicate` | email ou username déjà utilisé ; relancer |

---

## Structure du dépôt

```text
vt-mass-creator/
├── vt_mass_creator.py     # outil principal (création, vote, commentaire, signin)
├── generate_comments.py   # génère comments_500.txt
├── comments.txt           # messages d'exemple pour --comments-file
├── comments_500.txt       # 500 commentaires prêts à l'emploi
├── requirements.txt
└── README.md
```

> Les identifiants, clés API et dumps de comptes ne sont pas versionnés ici.
> Ils sont conservés dans le dépôt privé **`vt-keys`**.

---

## Licence

[MIT](LICENSE)
