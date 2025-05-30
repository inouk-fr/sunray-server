# Spécification de développement — Projet Muppy Sunray (v2)

## 🌞 Nom du projet : Muppy Sunray

**Muppy Sunray** est un système léger et sécurisé d’accès HTTP à des serveurs protégés, permettant de traverser le cloud sans exposition publique. Le nom évoque un rayon de soleil capable de traverser les nuages — une métaphore pour un accès contrôlé et filtré à travers les barrières réseau.

---

## 🎯 Objectif

Permettre un accès HTTP distant à certains services (par exemple sur Kubernetes) :
- **sans ouverture publique** à Internet,
- **sans dépendre d'une IP source fixe** (mobilité),
- **sans dépendre de solutions tierces** (type VPN, Cloudflare Access, Tailscale),
- tout en **assurant la sécurité** (signature, protection contre le replay),
- et en restant **open source et auto-hébergé**.

---

## 🧩 Architecture générale

### 1. Cloudflare Worker (open source)

Un Worker Cloudflare protège les accès HTTP par une vérification de signature cryptographique. Il :
- lit la configuration des utilisateurs autorisés (clés publiques, domaines) depuis un fichier YAML intégré ;
- valide une signature injectée dans l’en-tête `X-MPY-SUNRAY` de chaque requête entrante.

### 2. Extension Chrome (open source)

Une extension Chrome dédiée :
- génère une paire de clés publique/privée à l’installation (clé privée stockée localement) ;
- injecte automatiquement l’en-tête d’authentification dans les requêtes HTTP vers les domaines autorisés ;
- affiche une interface utilisateur pour visualiser la clé publique et saisir son identifiant (`username`).

---

## 🔐 Modes d’authentification

### 1. Mode Extension (signature ED25519)

### Format de l’en-tête envoyé :
```
X-MPY-SUNRAY: <username>:<timestamp>:<signature>
```

- `username` : identifiant public côté Worker
- `timestamp` : en secondes (Unix time), pour limiter le risque de replay
- `signature` : signature de la chaîne `<username>:<timestamp>` par la clé privée ED25519

### Vérifications côté Worker :
- `username` figure dans le fichier de configuration ;
- `timestamp` est valide (fenêtre temporelle ±30s) ;
- `signature` ED25519 est correcte via la clé publique de l’utilisateur.

---

### 2. Mode sans extension — Scénario Toctoc

Permettre un accès sécurisé à une application protégée par Sunray **sans nécessiter d’extension navigateur**, au moyen d’un workflow d’autorisation par e‑mail + code PIN, inspiré de Cloudflare Access mais renforcé.

#### Déroulement

1. **Interception de la requête**  
   La requête est capturée par le **Worker Route Sunray** sur Cloudflare.

2. **Vérification de l’AccessToken**  
   Le Worker cherche un cookie `AccessToken` signé ; si absent, invalide ou expiré (60 s), il redirige vers la page d’authentification.

3. **Page d’authentification**  
   - Saisie de l’email.  
   - Création d’un **AccessRequest** (IP source, email, site cible).  
   - Envoi d’un e‑mail contenant des liens : *Refuser*, *Autoriser 1 h / 4 h / 12 h*.

4. **Validation par e‑mail + PIN**  
   - L’utilisateur clique sur le lien.  
   - Le Worker affiche un formulaire demandant le **code PIN** (ou PIN sous contrainte).  
   - Trois échecs consécutifs ⇒ alerte + révocation + blocage temporel.

5. **Émission et renouvellement du token**  
   - PIN valide ⇒ le Worker émet un `AccessToken` (JWT signé) de 60 s, stocké en cookie `Secure` + `HttpOnly`.  
   - Tant que la *session autorisée* (1 h / 4 h / 12 h) est valide et l’IP inchangée, le Worker renouvelle automatiquement le token (rolling token).

#### Synthèse des garanties

- Domaine, IP et fenêtre temporelle strictement contrôlés.  
- Second facteur PIN, avec variante sous contrainte pour signaler la coercition.  
- Aucun logiciel à installer côté utilisateur.

#### Comparatif de robustesse et de sécurité

| Critère                                 | Cloudflare Access                     | Sunray (mode sans extension)                                              | Sunray (avec extension)                                                  |
|----------------------------------------|---------------------------------------|---------------------------------------------------------------------------|---------------------------------------------------------------------------|
| **Type d’authentification initiale**   | Basée sur IdP externe (SSO)           | Email + validation par code PIN                                          | Authentification par clé privée (extension)                              |
| **Jeton autoporteur**                  | Oui (JWT)                             | Oui (JWT ou token signé), durée courte                                   | Non (requêtes signées à la volée)                                        |
| **Durée de validité du jeton**         | Jusqu’à 24 h                          | 60 s, renouvelé automatiquement                                          | N/A (chaque requête est validée par signature)                           |
| **Renouvellement du jeton**            | Aucun, nécessite reconnexion          | Rolling token tant que la session reste valide                           | N/A                                                                       |
| **Vérification de l’IP source**        | Non                                   | Oui                                                                       | Optionnelle                                                               |
| **Ciblage par domaine (`aud`)**        | Oui                                   | Oui                                                                       | Implémenté via filtrage d’URL dans l’extension                           |
| **Stockage côté client**               | Cookie sécurisé (`HttpOnly`, `Secure`)| Identique                                                                 | Clé privée stockée dans l’extension (localStorage ou WebCrypto)          |
| **Protection contre vol de jeton**     | Faible (jeton utilisable tel quel)    | Renforcée (IP + durée courte)                                            | Très forte (aucun jeton exposé, clé privée non exportable)               |
| **Protection contre vol de lien d’accès**| Non (lien suffit)                    | Oui (code PIN requis pour valider l’accès)                               | N/A                                                                       |
| **Protection contre phishing actif**   | Dépend du SSO                         | Partielle : code PIN protège, mais page fausse peut le voler             | Forte (authentification silencieuse, sans interaction manuelle)          |
| **Mécanisme de signal de détresse**    | Non                                   | Oui (code PIN sous contrainte)                                           | Optionnel (via UI de l’extension)                                        |
| **Détection de tentatives d’intrusion**| Non intégré                           | Oui (PIN erroné → alerte + blocage)                                      | Forte (tentatives de signature anormales détectables localement)         |
| **Indépendance vis-à-vis d’un IdP**    | Non (dépend d’un fournisseur SSO)     | Oui (base de données interne, profils locaux)                            | Oui                                                                       |
| **Matériel ou extension requis**       | Non                                   | Non                                                                       | Oui (extension navigateur installée)                                     |
| **Simplicité d’usage utilisateur**     | Très fluide (SSO, peu d’interactions) | Fluide, mais nécessite une validation par mail et saisie de PIN          | Très fluide (aucune interaction utilisateur après installation)          |
| **Souveraineté et maîtrise des données** | Faible (Cloudflare centralise tout) | Forte (clé privée et validation locale dans le Worker)                   | Très forte (clé privée sur le poste utilisateur, contrôle total local)   |

## 🗂 Exemple de fichier de configuration YAML côté Worker

```yaml
# yaml-language-server: $schema=./muppy_sunray_worker_config_schema.json
version: 1
users:
  alice:
    pubkey: |
      # ED25519 public key (base64, 32 bytes)
      MCowBQYDK2VwAyEA2s+hGBZhCrd0HV9tSzw8j2CEnskVtM0tEz0+kUsAbl4=
  bob:
    pubkey: |
      # ED25519 public key
      MCowBQYDK2VwAyEAvNnX59YBlEG+LqpRAAnz2zPtSNiNNouhFDpGSpKXv4A=
  charlie:
    pubkey: |
      # ED25519 public key
      MCowBQYDK2VwAyEAZxM9pX0qWZB9hFJ1L3QkV7yX+vNfYz3JvT0Q5Z8Wc=

hosts:
  - domain: "mpy13c-k8s-dev-cyril.muppy.cloud"
    protected: true
    authorized_users:
      - alice
      - bob
    allowed_ips:
      - "192.168.0.1"
      - "2001:db8::1"
    allowed_paths:
      - pattern: "^/webhook/gitlab$"
        auth:
          type: "open"
      - pattern: "^/webhook/github$"
        auth:
          type: "header"
          name: "X-GitHub-Token"
          value: "mysecretgithubtoken"
      - pattern: "^/api/data$"
        auth:
          type: "query_param"
          name: "access_key"
          value: "apikey123"
```

---

## 🔧 Extensions de configuration

Le fichier YAML peut contenir :

- Une section `allowed_ips` par domaine, pour accorder un accès inconditionnel à certaines IP v4/v6.
- Une section `allowed_paths` avec des règles `open`, `header`, ou `query_param`.

Le Worker :
- fait matcher `request.url.pathname` avec `allowed_paths`,
- et/ou valide que `request.headers.get(name)` ou `URLSearchParams.get(name)` correspond à la valeur attendue,
- ou vérifie que `request.cf?.connectingIp` est dans `allowed_ips`.

Si aucune exception ne s’applique, la vérification de signature ED25519 est requise.

---

## ✅ Avantages de la solution

| Aspect | Avantage |
|--------|----------|
| **Sécurité** | Signature courte durée, asymétrique, pas de secret partagé |
| **Simplicité** | Pas de backend, tout est statique côté Worker |
| **Open Source** | Tous les composants peuvent être publiés et maintenus publiquement |
| **Ergonomie** | Une extension facile à déployer, sans configuration manuelle complexe |
| **Révocabilité** | Une simple suppression de la clé publique désactive un utilisateur |

---

## 📌 Prochaines étapes

1. Définir le format exact du fichier YAML (version, options futures…).
2. Prototyper le Worker Cloudflare avec parsing YAML (via `yaml` npm module).
3. Prototyper l’extension Chrome :
   - génération de la clé privée/publique,
   - stockage sécurisé dans `chrome.storage.local`,
   - injection du header,
   - UI de configuration simple.
4. Ajouter un outil CLI pour générer un fichier YAML à partir d’une clé publique.