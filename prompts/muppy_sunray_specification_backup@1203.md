

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

## 🔐 Mécanisme d’authentification

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

## 🗂 Exemple de fichier de configuration YAML côté Worker

```yaml
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