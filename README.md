# audit-vps

Collection de scripts pour **auditer la sécurité et la santé d'un VPS** (Ubuntu). Chaque script analyse un aspect de l'infrastructure. Il indique ce qui est bien configuré, ce qu'il faut corriger, et donne les commandes de correction.

## Scripts disponibles

| Script | Description | Où le lancer |
|---|---|---|
| [`audit_interne_vps`](audit_interne_vps/) | Audit complet depuis le serveur : système, mises à jour, comptes, SSH, pare-feu, ports exposés, noyau, fichiers, services, web et TLS, bases de données, Docker, sauvegardes, supervision. Génère un **rapport PDF** avec un score, un plan d'action priorisé et un inventaire. | Sur le VPS, en root |

D'autres scripts viendront compléter ce dépôt (par exemple un audit externe, lancé depuis une autre machine pour voir le serveur tel qu'Internet le voit).

## Démarrage rapide

Sur le VPS :

```bash
curl -fsSLO https://raw.githubusercontent.com/kaeldevpy/audit-vps/main/audit_interne_vps/audit_vps.py
sudo python3 audit_vps.py
```

La documentation complète de chaque script se trouve dans son dossier.

## Principes

- **Lecture seule** : les scripts observent et recommandent, ils ne modifient pas la configuration du serveur.
- **Rapports sensibles** : un rapport d'audit décrit les failles et la topologie de votre serveur. Ne le publiez pas : le `.gitignore` du dépôt exclut les rapports générés.
- **Complément, pas remplacement** : ces scripts ne voient pas tout (pare-feu et snapshots de l'hébergeur, code des applications). Les limites de chaque audit sont détaillées dans sa documentation.

## Licence

[MIT](LICENSE)
