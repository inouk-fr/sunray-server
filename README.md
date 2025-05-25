# Muppy Sunray

**Muppy Sunray** est une solution légère, sécurisée et auto-hébergée pour autoriser l’accès HTTP à des services cloud privés, sans VPN ni dépendance à des IP fixes. Elle repose sur :

- 🔐 Un Worker Cloudflare qui valide les requêtes par signature ED25519
- 🧩 Une extension Chrome qui signe les requêtes sortantes
- 🗂️ Un fichier de configuration YAML versionné et validé via JSON Schema

## ✨ Fonctionnalités principales

- Signature asymétrique courte durée (`X-MPY-SUNRAY`)
- Contrôle d'accès par domaine, IP, et token statique (header ou query param)
- Configuration dynamique stockée dans KV Cloudflare
- Extension Chrome dédiée
- Open source, CI/CD et validation via JSON Schema

## 📂 Structure du projet

```
.
├── worker/           # Code du Worker Cloudflare
├── extension/        # Code de l’extension Chrome
├── config/           # Exemples de configuration YAML
├── schema/           # Schéma JSON pour validation
├── docs/             # Documentation technique
├── .gitignore
├── README.md
```

## 🚀 Démarrer

1. Cloner le dépôt
2. Installer Wrangler (`npm install -g wrangler`)
3. Configurer votre `wrangler.toml`
4. Déployer le Worker

## 📄 Licence

MIT — Conçu pour être forké, adapté et amélioré.