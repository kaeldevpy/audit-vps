# audit-vps

Collection de scripts pour **auditer la sécurité et la santé d'un VPS** (Ubuntu). Chaque script analyse un aspect de l'infrastructure. Il indique ce qui est bien configuré, ce qu'il faut corriger, et donne les commandes de correction.

## Scripts disponibles

| Script | Description | Où le lancer |
|---|---|---|
| [`audit_interne_vps`](audit_interne_vps/) | Audit complet **depuis le serveur** : système, mises à jour, comptes, SSH, pare-feu, ports exposés, noyau, fichiers, services, web et TLS, bases de données, Docker, sauvegardes, supervision. Génère un **rapport PDF** avec un score, un plan d'action priorisé et un inventaire. | Sur le VPS, en root |
| [`audit_externe_vps`](audit_externe_vps/) | Audit **non intrusif** de la surface d'exposition, **vue depuis Internet** : ports joignables, services sensibles exposés, TLS et certificats, en-têtes HTTP, DNS et messagerie. Génère un **rapport PDF**. | Depuis une autre machine, vers le domaine ou l'IP publique |
| [`audit_docker`](audit_docker/) | Audit des **vulnérabilités (CVE) des images Docker**, via Trivy : vulnérabilités par image, lesquelles sont corrigeables, images à mettre à jour en priorité. Génère un **rapport PDF**. | Sur le VPS (ou toute machine avec Trivy/Docker) |

Ces audits sont complémentaires : l'interne voit la configuration réelle des services, l'externe voit ce qui est réellement joignable depuis Internet, et l'audit Docker voit les failles connues embarquées dans les images.

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
