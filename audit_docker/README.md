# audit_docker

Audit des **vulnérabilités connues (CVE) des images Docker**, via [Trivy](https://trivy.dev). Les audits interne et externe regardent la *configuration* des conteneurs et ce qui est *exposé* ; celui-ci regarde les failles embarquées **dans les images elles-mêmes**. Il produit un **rapport PDF** : combien de vulnérabilités par image, lesquelles sont corrigeables, quelles images mettre à jour en priorité.

Le script est en **lecture seule** : il analyse les images, il ne modifie ni les conteneurs ni le système.

## Utilisation

Sur le VPS (scanne les images des conteneurs **en cours d'exécution**) :

```bash
python3 audit_docker.py
```

Autres usages :

```bash
python3 audit_docker.py --all                 # inclure les conteneurs arrêtés
python3 audit_docker.py nginx:1.25 redis:7    # images précises
python3 audit_docker.py --secrets             # chercher aussi des secrets dans les images
python3 audit_docker.py --json -o rapport.pdf
```

### Options

| Option | Effet |
|---|---|
| `--all` | Inclure les conteneurs arrêtés (`docker ps -a`) |
| `--secrets` | Chercher aussi des secrets (mots de passe, clés) intégrés dans les images |
| `--timeout 10` | Délai maximum par image, en minutes |
| `--no-db-update` | Ne pas mettre à jour la base de vulnérabilités Trivy avant le scan |
| `-o rapport.pdf` | Chemin du rapport (défaut : `./audit-docker-<hôte>-<date>.pdf`) |
| `--json` | Exporter aussi les résultats en JSON |

## Dépendances

- **Trivy.** S'il est absent mais que **Docker** est présent, le script l'utilise automatiquement via l'image officielle `aquasec/trivy` — aucune installation nécessaire. Pour l'installer en binaire (plus rapide) :
  ```bash
  sudo apt-get install -y wget gnupg
  wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee /etc/apt/sources.list.d/trivy.list
  sudo apt-get update && sudo apt-get install -y trivy
  ```
- **python3-reportlab** (optionnel) pour le PDF ; sinon un rapport HTML est produit.

Trivy télécharge sa base de vulnérabilités au premier lancement (connexion Internet requise).

## Lire le rapport

- **Page de garde** : score sur 100, note et nombre de **contrôles** par sévérité. ⚠️ Les cases comptent les contrôles (par image et par gravité), **pas** le nombre total de CVE : une image peut cumuler des centaines de CVE sous un seul contrôle « critique ».
- **Synthèse par image** : un score par image, pour repérer les plus à risque.
- **Ce qu'il faut corriger** : pour chaque image, les vulnérabilités, combien sont corrigeables, et la commande de mise à jour.
- **Annexes** : la liste détaillée des CVE par image (CVE, paquet, version installée, version corrigée).

Une vulnérabilité « corrigeable » dispose déjà d'un correctif : mettre à jour l'image (ou la reconstruire sur une base récente) la supprime.

## Limites

L'analyse dépend de la fraîcheur de la base Trivy ; elle ne couvre pas le code applicatif que vous avez vous-même ajouté dans l'image, ni les erreurs de configuration à l'exécution (voir l'audit interne pour la configuration des conteneurs).

## Licence

[MIT](../LICENSE)
