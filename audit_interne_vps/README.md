# audit-vps

Script d'audit complet d'un VPS Ubuntu. Il produit un **rapport PDF** qui indique ce qu'il faut corriger, classé par priorité avec la commande correspondante, et ce qui est déjà bien configuré.

Le script est **en lecture seule** : il ne modifie aucune configuration. Les seules actions qui touchent au système sont `apt-get update` (désactivable) et l'installation de `python3-reportlab`, si tu l'acceptes.

## Utilisation

Télécharge le script directement sur le VPS :

```bash
curl -fsSLO https://raw.githubusercontent.com/kaeldevpy/audit-vps/main/audit_interne_vps/audit_vps.py
```

Ou copie-le depuis un clone du repo sur ton PC :

```bash
scp audit_interne_vps/audit_vps.py utilisateur@ip-du-vps:~
```

Puis, sur le VPS :

```bash
sudo python3 audit_vps.py
```

Au premier lancement, le script propose d'installer `python3-reportlab` (le générateur de PDF) et `fonts-dejavu-core`. Si tu refuses, il produit un rapport HTML à la place, que tu peux imprimer en PDF depuis un navigateur.

Pour récupérer le rapport sur ton PC (le fichier appartient à ton utilisateur, avec les droits 600) :

```bash
scp utilisateur@ip-du-vps:~/audit-*.pdf .
```

### Options

| Option | Effet |
|---|---|
| `-o /chemin/rapport.pdf` | Chemin du rapport (par défaut : `./audit-<hôte>-<date>.pdf`) |
| `--quick` | Saute le scan complet du disque (fichiers modifiables par tous, SUID, fichiers orphelins) |
| `--no-apt-update` | Ne rafraîchit pas la liste des paquets avant de compter les mises à jour |
| `--install-deps` | Installe `python3-reportlab` sans poser de question (pratique en cron) |
| `--domain exemple.fr` | Ajoute un domaine à tester en HTTPS (option répétable) |
| `--json` | Exporte aussi les résultats bruts en JSON (utile pour comparer deux audits) |

Les domaines sont détectés automatiquement depuis Nginx, Apache, Caddy et les labels Traefik / `VIRTUAL_HOST` des conteneurs. `--domain` sert pour ceux qui ne seraient pas détectés.

## Ce qui est analysé

| Domaine | Contrôles |
|---|---|
| Système et mises à jour | Fin de support d'Ubuntu, Ubuntu Pro, mises à jour de sécurité en attente, unattended-upgrades, redémarrage requis, services à redémarrer (needrestart), NTP, paquets orphelins |
| Ressources | CPU, RAM, swap, espace disque, inodes, processus tués par manque de mémoire (OOM), services en échec, taille des journaux |
| Comptes | Comptes UID 0, mots de passe vides ou hachés en MD5, root verrouillé, sudo NOPASSWD, permissions des dossiers personnels et des `authorized_keys`, clés SSH faibles |
| SSH | Configuration effective (`sshd -T`) : connexion root, mots de passe, algorithmes faibles, MaxAuthTries, redirections X11 et agent, AllowUsers, tentatives échouées, IP les plus actives |
| Pare-feu et réseau | UFW / nftables / iptables, IPv6, ports en écoute, services sensibles exposés (bases de données, Redis, API Docker…), en tenant compte des règles UFW |
| Anti-intrusion | Fail2ban / CrowdSec, rkhunter / AIDE, `ld.so.preload`, mineurs connus, processus lancés depuis `/tmp` |
| Noyau | Paramètres sysctl de durcissement (réseau, ASLR, ptrace, protection des liens…), modules rarement utilisés |
| Fichiers | Permissions de `shadow`, `sudoers`…, options de montage de `/tmp` et `/dev/shm`, fichiers modifiables par tous, binaires SUID non standards, fichiers sans propriétaire |
| Services | Services superflus (telnet, FTP, rpcbind, avahi…), AppArmor, auditd, persistance des journaux, permissions des tâches cron |
| Web et TLS | Nginx, Apache, PHP : versions affichées, TLS 1.0/1.1, listage des répertoires ; pour chaque domaine : validité et expiration du certificat, redirection HTTPS, en-têtes de sécurité |
| Bases de données | MySQL/MariaDB (écoute réseau, comptes anonymes, root distant), PostgreSQL (`trust`, `md5`, accès ouvert à toutes les adresses), Redis, MongoDB |
| Docker | API exposée, conteneurs privilégiés, socket monté dans un conteneur, montages sensibles, capacités dangereuses, ports qui contournent UFW, rotation des journaux, ancienneté des images |
| Sauvegardes, supervision, messagerie | Détection de restic, borg et autres, des agents de supervision, relais Postfix ouvert |

## Lire le rapport

- **Page de garde** : score sur 100, note de A à F et nombre de points par sévérité.
- **Synthèse** : score par domaine et liste des 15 actions prioritaires.
- **Plan d'action** : pour chaque problème, le constat, ce qu'il faut faire et la commande de correction.
- **Points conformes** : tout ce qui est déjà bien configuré.
- **Annexes** : inventaire complet (ports, services, comptes, conteneurs, tâches cron, règles du pare-feu…).

Le score est plafonné à 50 dès qu'il reste un point critique, et à 80 dès qu'il reste un point élevé.

> Avant de modifier la configuration SSH ou d'activer le pare-feu, garde une deuxième session SSH ouverte pour pouvoir revenir en arrière si tu perds l'accès.

## Audit mensuel automatique (optionnel)

```bash
echo '0 6 1 * * root /usr/bin/python3 /root/audit_vps.py --install-deps --json -o /root/audits/audit-$(date +\%Y\%m).pdf' | sudo tee /etc/cron.d/audit-vps
```

Crée d'abord le dossier : `sudo mkdir -p /root/audits`.

## Limites

Depuis le serveur, le script ne peut pas voir le pare-feu de l'hébergeur ni ses snapshots. Il ne teste pas la restauration des sauvegardes et n'audite pas le code des applications web. Pour compléter l'audit :

- `nmap` lancé depuis une autre machine, pour confirmer les ports réellement joignables ;
- Lynis, pour un audit système ;
- Trivy, pour les vulnérabilités des images Docker ;
- SSL Labs, pour le TLS vu de l'extérieur.

Compatibilité : Ubuntu 20.04 et versions suivantes (Python 3.8 minimum). Testé sur Ubuntu 24.04.

## Licence

[MIT](../LICENSE)
