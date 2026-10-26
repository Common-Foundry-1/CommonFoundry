# Notices tierces

## Common Foundry

Les formats protocolaires et l’icône sont dérivés de Common Foundry v1.0.16,
commit `e5f0cda2be60b9f7ee8d7f13bbeb9856d2edcf17`, distribué sous licence MIT.
Le texte de licence à la racine est conservé.

## Rust et JavaScript

Les dépendances sont verrouillées dans `Cargo.lock`, `app/src-tauri/Cargo.lock`
et `app/pnpm-lock.yaml`. Elles incluent notamment Tauri, React, k256, Argon2,
XChaCha20-Poly1305, BLAKE3, Reqwest/Rustls, Zeroize et QRCode React.

Avant distribution publique, générer un inventaire complet (par exemple avec
`cargo about` et un outil de licences npm/pnpm), vérifier chaque licence et
inclure les textes exigés dans l’APK. Ce fichier n’est pas encore un rapport de
conformité de livraison.
