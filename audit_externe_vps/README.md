# audit_externe_vps

Audit **non intrusif** de la surface d'exposition d'un VPS, **vu depuis Internet**. C'est le pendant de l'audit interne : au lieu d'analyser le serveur de l'intérieur, ce script observe ce qu'un visiteur d'Internet peut voir, à partir d'un nom de domaine, d'une URL ou de l'adresse IP publique. Il produit un **rapport PDF** avec un score, les points à corriger et ceux déjà bien configurés.

> ⚠️ **Cadre d'utilisation.** N'utilisez ce script que sur une infrastructure qui vous appartient ou que vous êtes explicitement autorisé à auditer. Scanner un serveur tiers sans autorisation écrite est illégal dans la plupart des pays. Vous êtes seul responsable de l'usage que vous en faites. Au lancement, le script demande une confirmation.

## Ce que « non intrusif » veut dire

Le script se contente d'**observer**, comme le ferait un navigateur ou un outil de diagnostic. Il n'exécute aucune attaque, n'envoie aucune charge utile et ne tente aucune authentification.

- **Ports** : il ouvre une connexion TCP normale pour voir si le port répond, puis la referme.
- **TLS** : il effectue des poignées de main pour lister les versions acceptées et lire le certificat.
- **HTTP** : il envoie des requêtes GET/HEAD standard et lit les réponses.
- **DNS** : il interroge les enregistrements publics (SPF, DMARC, DKIM, MX, CAA, PTR…).

## Utilisation

```bash
python3 audit_externe.py exemple.fr
python3 audit_externe.py 203.0.113.10
python3 audit_externe.py https://exemple.fr
```

Le mieux est de le lancer **depuis une autre machine que le serveur** (votre PC, un autre VPS), pour voir le serveur comme Internet le voit — un pare-feu peut filtrer selon l'adresse source.

### Options

| Option | Effet |
|---|---|
| `-o rapport.pdf` | Chemin du rapport (défaut : `./audit-externe-<cible>-<date>.pdf`) |
| `--ports common` | Jeu de ports : `common` (défaut, ~90 services courants), `top1000`, `all`, ou une liste (`22,80,443,8000-8100`) |
| `-4`, `--ipv4` | N'auditer que les adresses IPv4 (utile si votre connexion n'a pas de route IPv6) |
| `--timeout 2` | Délai par connexion, en secondes |
| `--workers 100` | Nombre de connexions simultanées |
| `--no-paths` | Ne pas tester les chemins sensibles (`.git`, `.env`…) |
| `--json` | Exporter aussi les résultats en JSON |
| `--yes` | Confirmer sans question que vous êtes autorisé (pour une exécution automatisée) |

Dépendance optionnelle : `python3-reportlab` pour le PDF (sinon un rapport HTML est produit). `dig` (paquet `dnsutils`) et `openssl` améliorent les contrôles DNS et certificats.

## Ce qui est analysé

| Domaine | Contrôles |
|---|---|
| Cible & résolution | Résolution DNS (A/AAAA), DNS inverse (PTR), vérification que les adresses visées sont bien publiques |
| Ports exposés | Ports TCP qui répondent, détection des services sensibles joignables (bases de données, Redis, API Docker, Telnet, SMB…), bannières de version, surface d'exposition globale |
| Chiffrement TLS | Versions acceptées (alerte sur TLS 1.0/1.1), disponibilité de TLS 1.3, validité et expiration du certificat, correspondance avec le domaine, certificat auto-signé |
| Web (HTTP/HTTPS) | Redirection HTTP→HTTPS, en-têtes de sécurité (HSTS, CSP, X-Frame-Options…), divulgation de versions, fichiers sensibles laissés accessibles (`.git`, `.env`, sauvegardes, `phpinfo`…) |
| DNS & messagerie | SPF, DMARC, DKIM, enregistrements MX et NS, CAA |

## Lien avec l'audit interne

Les deux audits sont complémentaires :

- **`audit_externe_vps`** (ce script) voit ce qui est *réellement joignable* depuis Internet, pare-feu de l'hébergeur compris.
- **`audit_interne_vps`** voit la *configuration réelle* des services (SSH, Docker, bases de données…) depuis le serveur.

Un service peut apparaître sécurisé côté configuration mais rester exposé par un port oublié — ou inversement. Lancez les deux.

## Limites

Le résultat dépend du réseau depuis lequel vous lancez l'audit (un pare-feu filtrant par IP source peut masquer des ports) ; l'hébergeur peut brider le débit des connexions ; le contenu applicatif des sites n'est pas audité. Pour compléter : [SSL Labs](https://www.ssllabs.com/ssltest/) (TLS détaillé), [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) (en-têtes web), MXToolbox (DNS et messagerie).

## Licence

[MIT](../LICENSE)
