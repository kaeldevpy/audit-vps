#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_externe.py - Audit de la surface d'exposition publique d'un VPS, vu depuis Internet.

Complément de l'audit interne : au lieu d'analyser le serveur depuis l'intérieur, ce script
observe ce qu'un visiteur d'Internet peut voir de votre serveur, à partir de son adresse IP
publique ou de l'URL d'un de ses sites. Il produit un rapport PDF listant ce qui est exposé,
ce qu'il faut corriger et ce qui est déjà bien.

  IMPORTANT - CADRE D'UTILISATION
  Ce script ne doit être utilisé QUE sur une infrastructure qui vous appartient ou que vous
  êtes explicitement autorisé à auditer. Scanner un serveur tiers sans autorisation écrite
  est illégal dans la plupart des pays. Vous êtes seul responsable de l'usage que vous en faites.

Le script est NON INTRUSIF : il se contente d'observer.
  - Ports : il ouvre une connexion TCP normale (comme un navigateur) pour voir si le port
    répond, puis la referme. Aucune exploitation, aucune charge utile, aucune force brute.
  - TLS : il effectue des poignées de main pour lister les versions et le certificat.
  - HTTP : il envoie des requêtes GET/HEAD standard et lit les réponses.
  - DNS : il interroge les enregistrements publics (SPF, DMARC, MX, PTR...).

Usage :
    python3 audit_externe.py exemple.fr
    python3 audit_externe.py 203.0.113.10
    python3 audit_externe.py https://exemple.fr --ports top1000
    python3 audit_externe.py exemple.fr -o rapport.pdf --json
    python3 audit_externe.py exemple.fr --yes          # saute la confirmation d'autorisation

Dépendance optionnelle : python3-reportlab (pour le PDF). Sinon un rapport HTML est produit.
"""

import argparse
import concurrent.futures
import datetime
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from xml.sax.saxutils import escape

VERSION = "1.0.0"

CRIT, HIGH, MED, LOW, INFO, OK = "critique", "eleve", "moyen", "faible", "info", "ok"
SEV_WEIGHT = {CRIT: 10, HIGH: 6, MED: 3, LOW: 1}
SEV_LABEL = {CRIT: "CRITIQUE", HIGH: "ÉLEVÉ", MED: "MOYEN", LOW: "FAIBLE", INFO: "INFO", OK: "OK"}
SEV_RANK = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4, OK: 5}
SEV_COLOR = {CRIT: "#B91C1C", HIGH: "#EA580C", MED: "#D97706", LOW: "#2563EB", INFO: "#6B7280", OK: "#15803D"}

# Services courants. {port: (nom, chiffré)}
COMMON_PORTS = {
    20: ("FTP-data", False), 21: ("FTP", False), 22: ("SSH", True), 23: ("Telnet", False),
    25: ("SMTP", False), 53: ("DNS", False), 80: ("HTTP", False), 110: ("POP3", False),
    111: ("rpcbind", False), 135: ("MS-RPC", False), 139: ("NetBIOS", False), 143: ("IMAP", False),
    161: ("SNMP", False), 389: ("LDAP", False), 443: ("HTTPS", True), 445: ("SMB", False),
    465: ("SMTPS", True), 587: ("SMTP (soumission)", True), 636: ("LDAPS", True), 993: ("IMAPS", True),
    995: ("POP3S", True), 1433: ("MS SQL Server", False), 1521: ("Oracle DB", False),
    2049: ("NFS", False), 2082: ("cPanel", False), 2083: ("cPanel (TLS)", True), 2086: ("WHM", False),
    2087: ("WHM (TLS)", True), 2375: ("API Docker (non chiffrée)", False), 2376: ("API Docker (TLS)", True),
    2379: ("etcd", False), 2483: ("Oracle DB", False), 3000: ("application web (dev)", False),
    3128: ("proxy Squid", False), 3306: ("MySQL/MariaDB", False), 3389: ("RDP", False),
    4243: ("API Docker", False), 4444: ("service divers", False), 5000: ("application web", False),
    5432: ("PostgreSQL", False), 5601: ("Kibana", False), 5672: ("RabbitMQ", False),
    5900: ("VNC", False), 5984: ("CouchDB", False), 6379: ("Redis", False), 6443: ("API Kubernetes", True),
    7001: ("WebLogic", False), 8000: ("application web", False), 8008: ("application web", False),
    8080: ("application web (HTTP alt)", False), 8086: ("InfluxDB", False), 8088: ("application web", False),
    8443: ("HTTPS alt", True), 8500: ("Consul", False), 8888: ("application web", False),
    8983: ("Solr", False), 9000: ("application web / PHP-FPM", False), 9042: ("Cassandra", False),
    9090: ("Prometheus", False), 9100: ("node_exporter", False), 9200: ("Elasticsearch", False),
    9300: ("Elasticsearch (transport)", False), 9418: ("Git", False), 10000: ("Webmin", False),
    10250: ("Kubelet", True), 11211: ("Memcached", False), 15672: ("RabbitMQ (admin)", False),
    27017: ("MongoDB", False), 27018: ("MongoDB", False), 50070: ("Hadoop", False), 61616: ("ActiveMQ", False),
}

# Ports qui ne devraient quasiment jamais être joignables depuis Internet.
# {port: (sévérité, pourquoi)}
RISKY = {
    23: (CRIT, "Telnet transmet tout en clair, mots de passe compris."),
    2375: (CRIT, "L'API Docker sans TLS donne un accès root complet à l'hôte à quiconque."),
    4243: (CRIT, "L'API Docker donne un accès root complet à l'hôte."),
    2379: (CRIT, "etcd contient souvent des secrets (Kubernetes)."),
    6379: (CRIT, "Redis exposé est régulièrement compromis en quelques minutes."),
    9200: (CRIT, "Elasticsearch exposé est une cause fréquente de fuites de données."),
    11211: (CRIT, "Memcached exposé sert à des attaques DDoS par amplification."),
    27017: (CRIT, "MongoDB exposé est une cause majeure de fuites et de rançons de données."),
    27018: (CRIT, "MongoDB exposé est une cause majeure de fuites et de rançons de données."),
    10250: (CRIT, "Le kubelet exposé permet d'exécuter des commandes dans les pods."),
    21: (HIGH, "FTP transmet identifiants et données en clair. Préférez SFTP."),
    135: (HIGH, "Service RPC Windows/Samba à ne jamais exposer."),
    139: (HIGH, "NetBIOS ne doit jamais être exposé sur Internet."),
    445: (HIGH, "SMB est une cible majeure (rançongiciels, vers)."),
    1433: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    1521: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    2049: (HIGH, "NFS exposé permet souvent de monter les partages à distance."),
    3306: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    5432: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    5984: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    9042: (HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    9300: (HIGH, "Le port de transport Elasticsearch doit rester privé."),
    5900: (HIGH, "VNC est souvent peu protégé et très ciblé."),
    61616: (HIGH, "ActiveMQ a fait l'objet de failles critiques exploitées."),
    111: (MED, "rpcbind divulgue les services RPC et sert à des amplifications."),
    161: (MED, "SNMP divulgue la configuration du serveur."),
    389: (MED, "Un annuaire LDAP ne devrait pas être exposé publiquement."),
    3389: (MED, "Le bureau à distance est une cible majeure de force brute."),
    5601: (MED, "Interface Kibana à protéger derrière un VPN ou une authentification."),
    5672: (MED, "Un broker de messages ne devrait pas être public."),
    8086: (MED, "Une base de données ne devrait pas être publique."),
    8500: (MED, "L'interface Consul ne devrait pas être publique."),
    8983: (MED, "Solr exposé a déjà été massivement exploité."),
    9090: (MED, "Prometheus expose vos métriques et la topologie de l'infrastructure."),
    9100: (MED, "Les métriques système ne devraient pas être publiques."),
    10000: (MED, "Webmin est une interface d'administration très ciblée."),
    15672: (MED, "Interface d'administration RabbitMQ à ne pas exposer."),
    2082: (MED, "Interface cPanel à protéger."), 2086: (MED, "Interface WHM à protéger."),
}

# Chemins sensibles parfois laissés accessibles par erreur (contrôle de posture, lecture seule).
SENSITIVE_PATHS = [
    ("/.git/config", HIGH, "Dépôt Git exposé : tout le code source (et parfois des secrets) est téléchargeable."),
    ("/.env", HIGH, "Fichier d'environnement exposé : contient souvent mots de passe et clés d'API."),
    ("/.env.local", HIGH, "Fichier d'environnement exposé : contient souvent mots de passe et clés d'API."),
    ("/config.php.bak", HIGH, "Sauvegarde de configuration exposée : peut contenir des identifiants."),
    ("/wp-config.php.bak", HIGH, "Sauvegarde de configuration WordPress exposée."),
    ("/.DS_Store", LOW, "Fichier macOS exposé : révèle la liste des fichiers du dossier."),
    ("/server-status", MED, "Page d'état Apache exposée : révèle les requêtes et adresses IP des visiteurs."),
    ("/.well-known/security.txt", INFO, "Fichier security.txt présent (bonne pratique de contact sécurité)."),
    ("/phpinfo.php", MED, "phpinfo() exposé : divulgue toute la configuration PHP et des chemins serveur."),
    ("/adminer.php", MED, "Adminer (gestion de bases de données) exposé publiquement."),
    ("/.git/HEAD", HIGH, "Dépôt Git exposé : tout le code source est potentiellement téléchargeable."),
]

SEC_HEADERS = {
    "strict-transport-security": ("HSTS", MED, "Force les navigateurs à utiliser HTTPS et empêche la rétrogradation en HTTP."),
    "content-security-policy": ("Content-Security-Policy", LOW, "Limite les sources de scripts et réduit les risques d'injection (XSS)."),
    "x-content-type-options": ("X-Content-Type-Options", LOW, "Empêche le navigateur de deviner le type des fichiers (nosniff)."),
    "x-frame-options": ("X-Frame-Options", LOW, "Empêche l'inclusion du site dans une iframe (clickjacking)."),
    "referrer-policy": ("Referrer-Policy", LOW, "Limite les informations envoyées aux sites tiers."),
}

TLS_VERSIONS = [
    ("SSLv3", getattr(ssl, "PROTOCOL_SSLv23", None), CRIT),
    ("TLSv1.0", None, MED), ("TLSv1.1", None, MED), ("TLSv1.2", None, OK), ("TLSv1.3", None, OK),
]


# --------------------------------------------------------------------------- utilitaires

def log(msg, color=None):
    codes = {"blue": "34", "green": "32", "yellow": "33", "red": "31", "gray": "90", "bold": "1"}
    if color and sys.stderr.isatty():
        msg = "\033[%sm%s\033[0m" % (codes[color], msg)
    print(msg, file=sys.stderr, flush=True)


def human_port(port):
    name = COMMON_PORTS.get(port, ("?", False))[0]
    return "%d/%s" % (port, name) if name != "?" else str(port)


def plural(n, word, word_pl=None):
    return "%d %s" % (n, word if n <= 1 else (word_pl or word + "s"))


def shorten(items, n=15, sep=", "):
    items = list(items)
    s = sep.join(str(i) for i in items[:n])
    if len(items) > n:
        s += "%s... (+%d)" % (sep, len(items) - n)
    return s


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return 1, "", ""


def dns_query(name, rtype):
    """Interroge un enregistrement DNS via dnspython, puis dig, puis socket. Renvoie une liste de chaînes."""
    try:
        import dns.resolver  # type: ignore
        try:
            return [r.to_text().strip('"') for r in dns.resolver.resolve(name, rtype, lifetime=8)]
        except Exception:  # noqa: BLE001
            return []
    except ImportError:
        pass
    if _has("dig"):
        rc, o, _ = run(["dig", "+short", "+time=3", "+tries=1", rtype, name], 12)
        if rc == 0:
            lines = []
            for l in o.splitlines():
                l = l.strip().strip('"')
                # dig écrit parfois ses erreurs (timeout, SERVFAIL...) sur stdout : on les ignore.
                if not l or l.startswith(";") or re.search(r"timed out|error|no servers|connection", l, re.I):
                    continue
                if rtype in ("A", "AAAA") and not _is_ip(l):
                    continue
                lines.append(l)
            if lines:
                return lines
    if rtype in ("A", "AAAA"):
        try:
            fam = socket.AF_INET if rtype == "A" else socket.AF_INET6
            return sorted(set(ai[4][0] for ai in socket.getaddrinfo(name, None, fam) if _is_ip(ai[4][0])))
        except Exception:  # noqa: BLE001
            return []
    return []


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _has(cmd):
    from shutil import which
    return which(cmd) is not None


def tcp_open(ip, port, timeout):
    """Ouvre une connexion TCP et la referme aussitôt. Renvoie (ouvert, bannière éventuelle)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = ""
            try:
                data = s.recv(256)
                banner = data.decode("iso-8859-1", "replace").strip()
            except Exception:  # noqa: BLE001
                pass
            return True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False, ""


def http_request(ip, port, host, tls, method="HEAD", path="/", timeout=8):
    """Requête HTTP(S) simple. Renvoie (statut, en-têtes, début du corps)."""
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=host)
        else:
            sock = raw
        req = ("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: audit-externe/%s\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n" % (method, path, host, VERSION))
        sock.sendall(req.encode())
        data = b""
        while len(data) < 65536:
            try:
                chunk = sock.recv(4096)
            except Exception:  # noqa: BLE001
                break
            if not chunk:
                break
            data += chunk
            if method == "HEAD" and b"\r\n\r\n" in data:
                break
        sock.close()
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        first = lines[0].split()
        status = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
        headers = {}
        for l in lines[1:]:
            if ":" in l:
                k, v = l.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return status, headers, body[:4096].decode("iso-8859-1", "replace")
    except Exception:  # noqa: BLE001
        return None, {}, ""


def parse_cert(der):
    """Analyse un certificat DER avec openssl si présent, sinon renvoie des infos minimales."""
    info = {}
    if _has("openssl"):
        try:
            p = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-enddate", "-startdate",
                                "-issuer", "-subject", "-ext", "subjectAltName"],
                               input=der, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            o = p.stdout.decode("utf-8", "replace")
            for line in o.splitlines():
                if line.startswith("notAfter="):
                    info["end"] = _parse_openssl_date(line.split("=", 1)[1])
                elif line.startswith("notBefore="):
                    info["start"] = _parse_openssl_date(line.split("=", 1)[1])
                elif line.startswith("issuer="):
                    m = re.search(r"CN\s*=\s*([^,/]+)", line) or re.search(r"O\s*=\s*([^,/]+)", line)
                    info["issuer"] = m.group(1).strip() if m else line[7:].strip()
                elif line.startswith("subject="):
                    m = re.search(r"CN\s*=\s*([^,/]+)", line)
                    info["subject"] = m.group(1).strip() if m else ""
            m = re.search(r"DNS:([^\n]+)", o)
            if m:
                info["sans"] = [x.strip().replace("DNS:", "") for x in m.group(1).split(",")]
        except Exception:  # noqa: BLE001
            pass
    return info


def _parse_openssl_date(s):
    try:
        return datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(s), datetime.timezone.utc).replace(tzinfo=None)
    except Exception:  # noqa: BLE001
        return None


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- audit

class ExternalAudit:
    def __init__(self, args):
        self.args = args
        self.findings = []
        self.inventory = []
        self.facts = OrderedDict()
        self.cat = "Général"
        self.now = datetime.datetime.now()
        self.started = time.time()
        self.target = args.target
        self.domain = None
        self.ips = []
        self.open_ports = {}   # ip -> {port: banner}
        self.working_https = []
        self.timeout = args.timeout

    def check(self, title, ok, sev, detail="", reco="", fix=""):
        self.findings.append(dict(cat=self.cat, title=title, status=OK if ok else sev, sev=sev,
                                  detail=detail, reco="" if ok else reco, fix="" if ok else fix))

    def info(self, title, detail):
        self.findings.append(dict(cat=self.cat, title=title, status=INFO, sev=INFO, detail=detail, reco="", fix=""))

    def table(self, title, headers, rows, note=""):
        if rows:
            self.inventory.append(dict(cat=self.cat, title=title, headers=headers,
                                       rows=[[str(c) for c in r] for r in rows], note=note))

    def resolve(self):
        self.cat = "Cible & résolution"
        raw = self.target.strip()
        m = re.match(r"^\w+://([^/:]+)", raw)
        hostpart = m.group(1) if m else raw.split("/")[0].split(":")[0]
        try:
            ip = ipaddress.ip_address(hostpart)
            self.ips = [str(ip)]
            self.facts["Cible"] = "%s (adresse IP)" % hostpart
        except ValueError:
            self.domain = hostpart.lower()
            self.facts["Cible"] = self.domain
            a = [x for x in dns_query(self.domain, "A") if _is_ip(x)]
            aaaa = [x for x in dns_query(self.domain, "AAAA") if _is_ip(x)]
            self.ips = a + aaaa
            if not self.ips:
                self.check("Résolution DNS", False, HIGH, "Le nom %s ne résout vers aucune adresse IP." % self.domain,
                           "Vérifiez la configuration DNS du domaine.")
                return False
            self.table("Enregistrements A / AAAA", ["Type", "Adresse"],
                       [["A", x] for x in a] + [["AAAA", x] for x in aaaa])
            if self.args.ipv4:
                self.ips = a
            self.facts["Adresses IP résolues"] = shorten(self.ips, 6) or "(aucune)"
        non_public = [ip for ip in self.ips if not self._public(ip)]
        if non_public:
            self.check("Adresses visées publiques", False, HIGH,
                       "Adresse(s) non publique(s) parmi les cibles : %s." % ", ".join(non_public),
                       "Ce script doit viser l'adresse publique du serveur, pas une adresse interne.")
            # On n'audite que les adresses réellement publiques.
            self.ips = [ip for ip in self.ips if self._public(ip)]
        self.facts["Date de l'audit"] = self.now.strftime("%d/%m/%Y %H:%M")
        return bool(self.ips)

    @staticmethod
    def _public(ip):
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast)
        except ValueError:
            return False

    def run_all(self):
        if not self.resolve():
            return
        self.reverse_dns()
        self.scan_ports()
        self.audit_exposure()
        self.audit_tls()
        self.audit_http()
        self.audit_email_dns()
        self.duration = time.time() - self.started

    def reverse_dns(self):
        self.cat = "Cible & résolution"
        rows = []
        for ip in self.ips:
            try:
                ptr = socket.gethostbyaddr(ip)[0]
            except Exception:  # noqa: BLE001
                ptr = "(aucun)"
            rows.append([ip, ptr])
        self.table("DNS inverse (PTR)", ["Adresse IP", "Nom PTR"], rows)
        if self.domain:
            miss = [ip for ip, ptr in rows if ptr == "(aucun)"]
            self.info("DNS inverse", "PTR manquant pour : %s. Un PTR cohérent améliore la délivrabilité des e-mails." % ", ".join(miss)
                      if miss else "Tous les PTR sont définis.")

    def _port_list(self):
        if self.args.ports == "all":
            return list(range(1, 65536))
        if self.args.ports == "top1000":
            base = set(COMMON_PORTS) | set(range(1, 1025))
            return sorted(base)
        if re.match(r"^[\d,\-]+$", self.args.ports or ""):
            ports = set()
            for part in self.args.ports.split(","):
                if "-" in part:
                    a, b = part.split("-")
                    ports.update(range(int(a), int(b) + 1))
                elif part:
                    ports.add(int(part))
            return sorted(p for p in ports if 1 <= p <= 65535)
        return sorted(COMMON_PORTS)  # "common" par défaut

    def scan_ports(self):
        self.cat = "Ports exposés"
        ports = self._port_list()
        log("    vérification de %d ports sur %d adresse(s)..." % (len(ports), len(self.ips)), "gray")
        for ip in self.ips:
            found = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.workers) as ex:
                futs = {ex.submit(tcp_open, ip, p, self.timeout): p for p in ports}
                for fut in concurrent.futures.as_completed(futs):
                    port = futs[fut]
                    try:
                        is_open, banner = fut.result()
                    except Exception:  # noqa: BLE001
                        is_open, banner = False, ""
                    if is_open:
                        found[port] = banner
            self.open_ports[ip] = found

    def audit_exposure(self):
        self.cat = "Ports exposés"
        rows, banners = [], []
        all_open = set()
        for ip in self.ips:
            for port, banner in sorted(self.open_ports.get(ip, {}).items()):
                all_open.add(port)
                name = COMMON_PORTS.get(port, ("inconnu", False))[0]
                rows.append([ip, port, name, "oui" if RISKY.get(port) else "-", (banner or "")[:60]])
                if banner and re.search(r"\d", banner):
                    banners.append("%s:%d → %s" % (ip, port, banner[:80]))
        self.table("Ports TCP ouverts", ["Adresse IP", "Port", "Service", "Sensible", "Bannière"], rows,
                   "Un port « ouvert » répond à une connexion TCP. Vérifié depuis cette machine : un pare-feu "
                   "filtrant par adresse IP source peut donner un résultat différent ailleurs.")
        self.facts["Ports ouverts"] = str(len(all_open)) if all_open else "0 (aucun port TCP ne répond)"

        risky_found = []
        for port in sorted(all_open):
            if port in RISKY:
                sev, why = RISKY[port]
                name = COMMON_PORTS.get(port, ("?", False))[0]
                ips_with = [ip for ip in self.ips if port in self.open_ports.get(ip, {})]
                self.check("Port sensible exposé : %s" % human_port(port), False, sev,
                           "Le port %d (%s) répond publiquement sur %s." % (port, name, ", ".join(ips_with)),
                           why + " Fermez ce port au pare-feu ou faites écouter le service sur 127.0.0.1 uniquement.",
                           "# sur le serveur (UFW)\nsudo ufw deny %d\n# ou faire écouter le service en local dans sa configuration (bind 127.0.0.1)" % port)
                risky_found.append(port)
        if not risky_found:
            self.check("Services sensibles exposés", True, HIGH,
                       "Aucun service sensible (base de données, cache, API d'administration, Telnet...) ne répond publiquement.")

        web = sorted(p for p in all_open if p in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000))
        admin = sorted(p for p in all_open if p in (10000, 2082, 2083, 2086, 2087, 9000, 8080) and p not in (80, 443))
        n = len(all_open)
        self.check("Surface d'exposition", n <= 5, LOW if n <= 10 else MED,
                   "%s ouvert(s)%s." % (plural(n, "port"), " : " + ", ".join(human_port(p) for p in sorted(all_open)) if all_open else ""),
                   "Chaque port ouvert est une porte d'entrée potentielle. Ne laissez ouverts que SSH et les ports web réellement nécessaires ; "
                   "tout le reste devrait être fermé au pare-feu ou accessible uniquement par VPN.",
                   "# n'exposer que l'essentiel\nsudo ufw default deny incoming\nsudo ufw allow 22/tcp\nsudo ufw allow 80,443/tcp")
        if 22 in all_open:
            self.info("SSH", "Le port SSH 22 répond publiquement. C'est courant, mais vérifiez côté serveur : "
                             "authentification par clé uniquement et protection anti-force-brute (Fail2ban). "
                             "Restreindre l'accès SSH à votre IP ou via VPN réduit fortement l'exposition.")
        if banners:
            self.table("Bannières de service (versions visibles)", ["Service → bannière"], [[b] for b in banners],
                       "Ces bannières révèlent des numéros de version exploitables pour cibler des failles connues.")

    def _tls_handshake(self, ip, port, version_name):
        """Tente une poignée de main TLS avec une version précise. Renvoie (supporté, infos certificat, cipher)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        mapping = {
            "TLSv1.0": (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            "TLSv1.1": (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            "TLSv1.2": (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            "TLSv1.3": (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
        }
        if version_name not in mapping:
            return False, {}, None
        lo, hi = mapping[version_name]
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version, ctx.maximum_version = lo, hi
        except ValueError:
            return None, {}, None  # version non supportée par cette installation d'OpenSSL
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as raw:
                sni = self.domain or ip
                with ctx.wrap_socket(raw, server_hostname=sni) as ss:
                    der = ss.getpeercert(True)
                    return True, (parse_cert(der) if der else {}), ss.cipher()
        except Exception:  # noqa: BLE001
            return False, {}, None

    def audit_tls(self):
        self.cat = "Chiffrement TLS"
        # Ports servant du TLS « direct » (poignée de main dès la connexion).
        # On exclut SSH (22, ce n'est pas du TLS) et les ports STARTTLS (25, 587, 143...),
        # qui exigent une négociation propre au protocole non couverte ici.
        direct_tls = {443, 8443, 465, 993, 995, 636, 2083, 2087, 6443, 10250, 2376}
        tls_ports = sorted(set(p for ip in self.ips for p in self.open_ports.get(ip, {}) if p in direct_tls))
        if not tls_ports:
            self.info("TLS", "Aucun port chiffré (HTTPS, etc.) ne répond : contrôle TLS non applicable.")
            return
        ip = self.ips[0]
        cert_checked = False
        for port in tls_ports:
            if port not in self.open_ports.get(ip, {}):
                continue
            log("    analyse TLS du port %d..." % port, "gray")
            supported, weak, cert = [], [], {}
            for name in ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
                ok, info, cipher = self._tls_handshake(ip, port, name)
                if ok:
                    supported.append(name)
                    if info and not cert:
                        cert = info
                    if name in ("TLSv1.0", "TLSv1.1"):
                        weak.append(name)
            if not supported:
                self.info("TLS port %d" % port, "Le port répond mais aucune version TLS standard n'a abouti.")
                continue
            self.working_https.append(port)
            self.check("Protocoles TLS obsolètes (port %d)" % port, not weak, MED,
                       "Versions acceptées : %s." % ", ".join(supported),
                       "TLS 1.0 et 1.1 sont vulnérables et rejetés par les navigateurs récents.",
                       "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\nsudo nginx -t && sudo systemctl reload nginx")
            self.check("TLS 1.3 disponible (port %d)" % port, "TLSv1.3" in supported, LOW,
                       "TLS 1.3 %s." % ("supporté" if "TLSv1.3" in supported else "non supporté"),
                       "Activez TLS 1.3 pour de meilleures performances et sécurité.",
                       "ssl_protocols TLSv1.2 TLSv1.3;")
            if cert and not cert_checked and port in (443, 8443):
                self._check_cert(cert, port)
                cert_checked = True

    def _check_cert(self, cert, port):
        end = cert.get("end")
        issuer = cert.get("issuer", "?")
        subject = cert.get("subject", "")
        sans = cert.get("sans", [])
        self.table("Certificat TLS (port %d)" % port, ["Champ", "Valeur"], [
            ["Sujet (CN)", subject or "?"], ["Émetteur", issuer],
            ["Valide jusqu'au", end.strftime("%d/%m/%Y") if end else "?"],
            ["Noms couverts (SAN)", shorten(sans, 12)],
        ])
        if end:
            days = (end - utcnow()).days
            sev = CRIT if days < 0 else HIGH if days < 14 else MED if days < 30 else OK
            self.check("Expiration du certificat", days >= 30, MED if days < 30 else MED,
                       ("Le certificat a expiré depuis %d jours." % -days) if days < 0
                       else "Le certificat expire dans %d jours (%s)." % (days, end.strftime("%d/%m/%Y")),
                       "Renouvelez le certificat et vérifiez le renouvellement automatique (certbot).",
                       "sudo certbot renew --dry-run")
            if days < 0:
                self.findings[-1]["status"] = CRIT
            elif days < 14:
                self.findings[-1]["status"] = HIGH
        # Correspondance du nom
        if self.domain:
            names = [subject] + sans
            match = any(self._name_matches(self.domain, n) for n in names if n)
            self.check("Nom du certificat", match, HIGH,
                       "Le certificat couvre : %s." % shorten([n for n in names if n], 8) if match
                       else "Le certificat ne couvre pas %s (sujet : %s)." % (self.domain, subject),
                       "Les visiteurs voient une alerte de sécurité. Émettez un certificat pour ce domaine.",
                       "sudo certbot --nginx -d %s" % self.domain)
        if issuer and re.search(r"(self|auto).?sign|^%s$" % re.escape(subject or "x"), issuer, re.I):
            self.check("Certificat signé par une autorité reconnue", False, MED,
                       "Le certificat semble auto-signé (émetteur = sujet).",
                       "Utilisez un certificat Let's Encrypt gratuit, reconnu par tous les navigateurs.",
                       "sudo apt install certbot python3-certbot-nginx && sudo certbot --nginx")

    @staticmethod
    def _name_matches(domain, pattern):
        pattern = pattern.lower().strip()
        domain = domain.lower().strip()
        if pattern.startswith("*."):
            return domain.split(".", 1)[-1] == pattern[2:] or domain == pattern[2:]
        return domain == pattern

    def audit_http(self):
        self.cat = "Web (HTTP/HTTPS)"
        ip = self.ips[0]
        host = self.domain or ip
        open_here = self.open_ports.get(ip, {})
        http_ports = [p for p in (80, 8080, 8000, 8888, 3000, 5000) if p in open_here]
        https_ports = [p for p in (443, 8443) if p in open_here]
        if not http_ports and not https_ports:
            self.info("Web", "Aucun service web (HTTP/HTTPS) ne répond : contrôles web non applicables.")
            return

        # Redirection HTTP -> HTTPS
        if 80 in open_here:
            status, headers, _ = http_request(ip, 80, host, False, "HEAD", "/")
            loc = headers.get("location", "")
            redir = status in (301, 302, 307, 308) and loc.startswith("https://")
            self.check("Redirection HTTP vers HTTPS", redir, MED,
                       ("HTTP répond %s → %s." % (status, loc)) if status else "Pas de réponse en HTTP.",
                       "Redirigez tout le trafic HTTP vers HTTPS pour éviter les échanges en clair.",
                       "# Nginx, bloc server port 80\nreturn 301 https://$host$request_uri;")

        # Choix d'un port web qui répond réellement : on privilégie un HTTPS dont la poignée
        # de main TLS a abouti, puis les autres HTTPS, puis le HTTP. On bascule si la requête échoue.
        candidates = ([(p, True) for p in https_ports if p in self.working_https]
                      + [(p, True) for p in https_ports if p not in self.working_https]
                      + [(p, False) for p in http_ports])
        target_port, tls, status, headers, body = None, False, None, {}, ""
        for port, use_tls in candidates:
            st, hd, bd = http_request(ip, port, host, use_tls, "GET", "/")
            if st:
                target_port, tls, status, headers, body = port, use_tls, st, hd, bd
                break
        if status:
            scheme = "https" if tls else "http"
            self.facts["Page d'accueil"] = "%s://%s:%d → HTTP %s" % (scheme, host, target_port, status)
            missing = []
            for key, (label, sev, _) in SEC_HEADERS.items():
                present = key in headers or (key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""))
                if not present:
                    missing.append(label)
            self.check("En-têtes de sécurité HTTP", not missing, LOW,
                       ("En-têtes manquants : %s." % ", ".join(missing)) if missing else "Tous les en-têtes de sécurité recommandés sont présents.",
                       "Ces en-têtes protègent les visiteurs (clickjacking, détournement de type MIME, rétrogradation HTTPS).",
                       'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
                       'add_header X-Content-Type-Options "nosniff" always;\n'
                       'add_header X-Frame-Options "SAMEORIGIN" always;\n'
                       'add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
            # Divulgation de versions
            leak = []
            for h in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
                if h in headers and re.search(r"\d", headers[h]):
                    leak.append("%s: %s" % (h, headers[h]))
            self.check("Divulgation de versions logicielles", not leak, LOW,
                       ("En-têtes révélateurs : %s." % "; ".join(leak)) if leak else "Aucun numéro de version divulgué dans les en-têtes.",
                       "Masquez les versions pour compliquer le ciblage de failles connues.",
                       "# Nginx : server_tokens off;   |  PHP : expose_php = Off")
            rows = [[k, v] for k, v in sorted(headers.items())]
            self.table("En-têtes de réponse HTTP", ["En-tête", "Valeur"], rows)

        # Chemins sensibles (lecture seule, liste restreinte)
        if not self.args.no_paths and target_port is not None:
            exposed = []
            for path, sev, why in SENSITIVE_PATHS:
                st, _, _ = http_request(ip, target_port, host, tls, "GET", path, timeout=6)
                if st == 200:
                    exposed.append((path, sev, why))
            real = [(p, s, w) for p, s, w in exposed if s != INFO]
            self.check("Fichiers et pages sensibles accessibles", not real,
                       min((s for _, s, _ in real), key=lambda x: SEV_RANK[x]) if real else HIGH,
                       ("Accessibles publiquement : %s" % "; ".join("%s (%s)" % (p, w) for p, s, w in real)) if real
                       else "Aucun des fichiers sensibles testés (.git, .env, sauvegardes, phpinfo...) n'est accessible.",
                       "Bloquez l'accès à ces fichiers au niveau du serveur web et retirez-les de la racine publique.",
                       "# Nginx\nlocation ~ /\\.(git|env) { deny all; return 404; }")
            for p, s, w in exposed:
                if s == INFO:
                    self.info("security.txt", "Fichier %s présent : bonne pratique pour être contacté en cas de faille." % p)

    def audit_email_dns(self):
        self.cat = "DNS & messagerie"
        if not self.domain:
            self.info("DNS & messagerie", "Cible fournie sous forme d'adresse IP : contrôles DNS non applicables (fournissez le domaine).")
            return
        mx = dns_query(self.domain, "MX")
        txt = dns_query(self.domain, "TXT")
        self.table("Enregistrements MX", ["Serveur de messagerie"], [[m] for m in mx] or [["(aucun)"]])

        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        self.check("Enregistrement SPF", bool(spf), MED if mx else LOW,
                   spf[0] if spf else "Aucun enregistrement SPF.",
                   "SPF indique quels serveurs peuvent envoyer des e-mails pour votre domaine et limite l'usurpation.",
                   '# TXT à la racine du domaine\n"v=spf1 mx -all"')
        if spf and re.search(r"[~+]all", spf[0]):
            self.check("SPF strict", False, LOW, "SPF se termine par '%s' au lieu de '-all'." % re.search(r"[~+?-]all", spf[0]).group(0),
                       "Un '-all' rejette fermement les expéditeurs non listés.", '"v=spf1 mx -all"')

        dmarc = dns_query("_dmarc." + self.domain, "TXT")
        dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
        policy = re.search(r"p=(\w+)", dmarc[0]) if dmarc else None
        self.check("Enregistrement DMARC", bool(dmarc) and policy and policy.group(1) != "none", MED if mx else LOW,
                   (dmarc[0] if dmarc else "Aucun enregistrement DMARC.") if not (dmarc and policy and policy.group(1) == "none")
                   else "DMARC présent mais en p=none (surveillance seule, sans protection).",
                   "DMARC protège contre l'usurpation de votre domaine dans les e-mails.",
                   '# TXT sur _dmarc.%s\n"v=DMARC1; p=quarantine; rua=mailto:postmaster@%s"' % (self.domain, self.domain))

        dkim_found = []
        for sel in ("default", "google", "mail", "selector1", "selector2", "k1", "dkim", "s1"):
            r = dns_query("%s._domainkey.%s" % (sel, self.domain), "TXT")
            if any("v=dkim1" in t.lower() or "p=" in t.lower() for t in r):
                dkim_found.append(sel)
        if mx:
            self.check("Clé DKIM", bool(dkim_found), LOW,
                       ("Sélecteur(s) DKIM trouvé(s) : %s." % ", ".join(dkim_found)) if dkim_found
                       else "Aucun sélecteur DKIM courant trouvé (il peut exister sous un autre nom).",
                       "DKIM signe vos e-mails et renforce leur authenticité.",
                       "# dépend du serveur de messagerie (OpenDKIM, serveur mail managé...)")

        caa = dns_query(self.domain, "CAA")
        self.check("Enregistrement CAA", bool(caa), LOW,
                   ("CAA : %s" % "; ".join(caa)) if caa else "Aucun enregistrement CAA.",
                   "CAA limite les autorités de certification autorisées à émettre un certificat pour votre domaine.",
                   '# TXT/CAA à la racine\n%s. CAA 0 issue "letsencrypt.org"' % self.domain)

        ns = dns_query(self.domain, "NS")
        self.table("Serveurs de noms (NS)", ["Serveur DNS"], [[n] for n in ns])
        if mx and 25 in self.open_ports.get(self.ips[0], {}):
            self.info("Serveur SMTP", "Le port 25 répond : si ce serveur envoie du courrier, vérifiez qu'il n'est pas un relais ouvert (audit interne).")

    # ------- synthèse
    def score(self, findings=None):
        findings = self.findings if findings is None else findings
        tot = sum(SEV_WEIGHT[f["sev"]] for f in findings if f["status"] != INFO and f["sev"] in SEV_WEIGHT)
        good = sum(SEV_WEIGHT[f["sev"]] for f in findings if f["status"] == OK and f["sev"] in SEV_WEIGHT)
        return None if tot == 0 else int(round(100.0 * good / tot))

    def global_score(self):
        s = self.score() or 0
        sts = [f["status"] for f in self.findings]
        if CRIT in sts:
            s = min(s, 50)
        elif HIGH in sts:
            s = min(s, 80)
        return s

    def counts(self, findings=None):
        c = Counter(f["status"] for f in (self.findings if findings is None else findings))
        return {k: c.get(k, 0) for k in (CRIT, HIGH, MED, LOW, OK, INFO)}

    def categories(self):
        cats = OrderedDict()
        for f in self.findings:
            cats.setdefault(f["cat"], []).append(f)
        return cats

    def actions(self):
        return sorted([f for f in self.findings if f["status"] in SEV_WEIGHT], key=lambda f: (SEV_RANK[f["status"]], f["cat"]))


def grade_of(score):
    for limit, g in ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (40, "E")):
        if score >= limit:
            return g
    return "F"


def score_color(score):
    if score is None:
        return "#9CA3AF"
    return "#15803D" if score >= 85 else "#65A30D" if score >= 70 else "#D97706" if score >= 50 else "#B91C1C"


def verdict(score, counts):
    if counts[CRIT]:
        return ("La surface exposée présente %s. Un service sensible est joignable depuis Internet : "
                "traitez ces points en priorité absolue." % plural(counts[CRIT], "problème critique", "problèmes critiques"))
    if counts[HIGH]:
        return ("Aucun problème critique, mais %s à corriger rapidement côté exposition réseau ou certificats."
                % plural(counts[HIGH], "point de sévérité élevée", "points de sévérité élevée"))
    if counts[MED]:
        return "Bonne posture d'exposition. Il reste %s pour durcir la configuration vue de l'extérieur." % plural(counts[MED], "point moyen", "points moyens")
    return "Excellente posture : la surface exposée est réduite et bien configurée. Maintenez la veille et les certificats à jour."


# --------------------------------------------------------------------------- PDF

def build_pdf(a, path):
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate,
                                    PageBreak, PageTemplate, Paragraph, Spacer, Table, TableStyle)

    F, FB, FM, unicode_ok = "Helvetica", "Helvetica-Bold", "Courier", False
    for base in ("/usr/share/fonts/truetype/dejavu/", "/usr/share/fonts/dejavu/"):
        files = [base + f for f in ("DejaVuSans.ttf", "DejaVuSans-Bold.ttf", "DejaVuSansMono.ttf")]
        if all(os.path.exists(f) for f in files):
            try:
                pdfmetrics.registerFont(TTFont("DV", files[0]))
                pdfmetrics.registerFont(TTFont("DVB", files[1]))
                pdfmetrics.registerFont(TTFont("DVM", files[2]))
                pdfmetrics.registerFontFamily("DV", normal="DV", bold="DVB", italic="DV", boldItalic="DVB")
                F, FB, FM, unicode_ok = "DV", "DVB", "DVM", True
                break
            except Exception:  # noqa: BLE001
                pass

    def clean(s):
        s = str(s)
        return s if unicode_ok else s.encode("cp1252", "replace").decode("cp1252")

    def t(s):
        return escape(clean(s)).replace("\n", "<br/>")

    def tm(s):
        lines = escape(clean(s)).split("\n")
        return "<br/>".join(re.sub(r"^( +)", lambda m: "&nbsp;" * len(m.group(1)), l) for l in lines)

    C = lambda h: colors.HexColor(h)  # noqa: E731
    DARK, ACCENT, GRAY, LINE, LIGHT = C("#111827"), C("#1D4ED8"), C("#6B7280"), C("#E5E7EB"), C("#F9FAFB")
    W = A4[0] - 36 * mm

    S = {
        "h1": ParagraphStyle("h1", fontName=FB, fontSize=17, leading=22, spaceAfter=8, textColor=DARK),
        "h2": ParagraphStyle("h2", fontName=FB, fontSize=12.5, leading=16, spaceBefore=10, spaceAfter=5, textColor=ACCENT),
        "body": ParagraphStyle("body", fontName=F, fontSize=9.5, leading=13.5, textColor=DARK),
        "lead": ParagraphStyle("lead", fontName=F, fontSize=10.5, leading=15, textColor=DARK),
        "small": ParagraphStyle("small", fontName=F, fontSize=8, leading=10.5, textColor=GRAY),
        "cell": ParagraphStyle("cell", fontName=F, fontSize=7.8, leading=9.8, textColor=DARK),
        "cellb": ParagraphStyle("cellb", fontName=FB, fontSize=7.8, leading=9.8, textColor=DARK),
        "cellh": ParagraphStyle("cellh", fontName=FB, fontSize=7.8, leading=9.8, textColor=colors.white),
        "mono": ParagraphStyle("mono", fontName=FM, fontSize=7.3, leading=9.4, textColor=DARK),
        "badge": ParagraphStyle("badge", fontName=FB, fontSize=7.5, leading=9, textColor=colors.white, alignment=TA_CENTER),
        "count": ParagraphStyle("count", fontName=FB, fontSize=7.5, leading=9, textColor=colors.white, alignment=TA_CENTER),
        "countn": ParagraphStyle("countn", fontName=FB, fontSize=20, leading=24, textColor=colors.white, alignment=TA_CENTER),
        "label": ParagraphStyle("label", fontName=FB, fontSize=8, leading=10.5, textColor=GRAY),
    }

    score, grade, counts = a.global_score(), grade_of(a.global_score()), a.counts()
    date_str = a.now.strftime("%d/%m/%Y %H:%M")
    target = a.facts.get("Cible", a.target)

    def on_page(c, doc):
        c.saveState()
        w, h = A4
        c.setStrokeColor(LINE); c.setLineWidth(0.5)
        c.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
        c.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
        c.setFont(F, 7.5); c.setFillColor(GRAY)
        c.drawString(18 * mm, h - 11.5 * mm, clean("Audit externe - %s" % target))
        c.drawRightString(w - 18 * mm, h - 11.5 * mm, date_str)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : décrit la surface d'attaque exposée du serveur"))
        c.drawRightString(w - 18 * mm, 9.5 * mm, "Page %d" % doc.page)
        c.restoreState()

    def on_cover(c, doc):
        c.saveState()
        w, h = A4
        c.setFillColor(DARK); c.rect(0, h - 72 * mm, w, 72 * mm, fill=1, stroke=0)
        c.setFillColor(C("#3B82F6")); c.rect(0, h - 73.5 * mm, w, 1.5 * mm, fill=1, stroke=0)
        c.setFillColor(colors.white); c.setFont(FB, 26)
        c.drawString(18 * mm, h - 32 * mm, clean("Audit externe du VPS"))
        c.setFont(F, 14); c.drawString(18 * mm, h - 43 * mm, clean(target))
        c.setFont(F, 9.5); c.setFillColor(C("#CBD5E1"))
        c.drawString(18 * mm, h - 52 * mm, clean("Surface d'exposition vue depuis Internet  |  %s" % date_str))
        c.drawString(18 * mm, h - 59 * mm, clean("Analyse non intrusive (observation uniquement)  |  audit_externe.py v%s" % VERSION))
        c.setFont(F, 7.5); c.setFillColor(GRAY)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : décrit la surface d'attaque exposée du serveur"))
        c.restoreState()

    def gauge(value, color):
        d = Drawing(46 * mm, 46 * mm)
        cx = cy = 23 * mm; r = 22 * mm
        d.add(Circle(cx, cy, r, fillColor=LINE, strokeColor=None))
        if value >= 100:
            d.add(Circle(cx, cy, r, fillColor=C(color), strokeColor=None))
        elif value > 0:
            d.add(Wedge(cx, cy, r, 90 - 360.0 * value / 100, 90, fillColor=C(color), strokeColor=None))
        d.add(Circle(cx, cy, r - 4.5 * mm, fillColor=colors.white, strokeColor=None))
        d.add(String(cx, cy - 1 * mm, str(value), fontName=FB, fontSize=30, textAnchor="middle", fillColor=DARK))
        d.add(String(cx, cy - 8 * mm, "/ 100", fontName=F, fontSize=9.5, textAnchor="middle", fillColor=GRAY))
        return d

    def bar(value, width=38 * mm, height=3.2 * mm):
        d = Drawing(width, height)
        d.add(Rect(0, 0, width, height, fillColor=LINE, strokeColor=None))
        if value:
            d.add(Rect(0, 0, width * value / 100.0, height, fillColor=C(score_color(value)), strokeColor=None))
        return d

    def grid(data, widths, header=True, zebra=True, extra=None):
        tbl = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        st = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]
        if header:
            st += [("BACKGROUND", (0, 0), (-1, 0), DARK)]
        if zebra:
            for i in range(1 if header else 0, len(data)):
                if i % 2 == 0:
                    st.append(("BACKGROUND", (0, i), (-1, i), LIGHT))
        tbl.setStyle(TableStyle(st + (extra or [])))
        return tbl

    def P(text, style="cell"):
        return Paragraph(text, S[style])

    story = [NextPageTemplate("page")]
    gcolor = score_color(score)
    grade_block = [P("<font size=9 color='#6B7280'>POSTURE EXTERNE</font>", "body"),
                   Paragraph("<font size=40 color='%s'><b>%s</b></font>" % (gcolor, grade),
                             ParagraphStyle("g", fontName=FB, fontSize=40, leading=46)),
                   Spacer(1, 2 * mm), P(t(verdict(score, counts)), "body")]
    story.append(Table([[gauge(score, gcolor), grade_block]], colWidths=[52 * mm, W - 52 * mm],
                       style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(Spacer(1, 6 * mm))
    cells, st = [], []
    for i, sev in enumerate((CRIT, HIGH, MED, LOW, OK)):
        cells.append([P(str(counts[sev]), "countn"), P(SEV_LABEL[sev], "count")])
        st.append(("BACKGROUND", (i, 0), (i, 0), C(SEV_COLOR[sev])))
    story.append(Table([cells], colWidths=[W / 5.0] * 5, style=st + [
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LINEAFTER", (0, 0), (-2, -1), 2, colors.white)]))
    story.append(Spacer(1, 7 * mm))
    story.append(P("Cible de l'audit", "h2"))
    story.append(grid([[P(t(k), "cellb"), P(t(v))] for k, v in a.facts.items()], [48 * mm, W - 48 * mm], header=False))
    story.append(P("Rappel : analyse non intrusive, réalisée depuis cette machine. Un pare-feu filtrant par adresse IP source "
                   "peut faire apparaître des ports fermés ici alors qu'ils sont ouverts pour d'autres réseaux, et inversement.", "small"))
    if not unicode_ok:
        story.append(Spacer(1, 2 * mm))
        story.append(P("Police DejaVu absente : certains caractères spéciaux peuvent être remplacés (sudo apt install fonts-dejavu-core).", "small"))
    story.append(PageBreak())

    # synthèse
    story.append(P("Synthèse par domaine", "h1"))
    data = [[P(h, "cellh") for h in ("Domaine", "Score", "", "Crit.", "Élevé", "Moyen", "Faible", "OK")]]
    for cat, fs in a.categories().items():
        s = a.score(fs); c = a.counts(fs)
        row = [P(t(cat), "cellb"), P("<b>%s</b>" % ("-" if s is None else "%d %%" % s)), bar(s or 0)]
        for sev in (CRIT, HIGH, MED, LOW, OK):
            row.append(P("<font color='%s'><b>%d</b></font>" % (SEV_COLOR[sev], c[sev]) if c[sev] else "<font color='#D1D5DB'>0</font>"))
        data.append(row)
    story.append(grid(data, [50 * mm, 14 * mm, 42 * mm] + [(W - 106 * mm) / 5.0] * 5, extra=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    acts = a.actions()
    story.append(Spacer(1, 6 * mm))
    story.append(P("Actions prioritaires", "h2"))
    if acts:
        data = [[P(h, "cellh") for h in ("#", "Sévérité", "Domaine", "Point à corriger")]]
        extra = []
        for i, f in enumerate(acts[:15], 1):
            data.append([P(str(i)), P(SEV_LABEL[f["status"]], "badge"), P(t(f["cat"])), P(t(f["title"]), "cellb")])
            extra.append(("BACKGROUND", (1, i), (1, i), C(SEV_COLOR[f["status"]])))
        story.append(grid(data, [8 * mm, 20 * mm, 42 * mm, W - 70 * mm], zebra=False, extra=extra + [("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    else:
        story.append(P("Aucune action corrective nécessaire.", "body"))
    story.append(PageBreak())

    # plan d'action
    story.append(P("Ce qu'il faut changer : plan d'action", "h1"))
    story.append(P("Les correctifs s'appliquent sur le serveur (pare-feu, serveur web, DNS). Gardez une session SSH ouverte "
                   "avant de modifier les règles de pare-feu.", "small"))
    story.append(Spacer(1, 4 * mm))
    for i, f in enumerate(acts, 1):
        col = C(SEV_COLOR[f["status"]])
        head = Table([[P(SEV_LABEL[f["status"]], "badge"),
                       P("<b>%d. %s</b>  <font size=7 color='#6B7280'>%s</font>" % (i, t(f["title"]), t(f["cat"])), "body")]],
                     colWidths=[22 * mm, W - 22 * mm],
                     style=[("BACKGROUND", (0, 0), (0, 0), col), ("BACKGROUND", (1, 0), (1, 0), LIGHT),
                            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])
        rows = []
        if f["detail"]:
            rows.append([P("Constat", "label"), P(t(f["detail"]))])
        if f["reco"]:
            rows.append([P("À faire", "label"), P(t(f["reco"]))])
        if f["fix"]:
            box = Table([[P(tm(f["fix"]), "mono")]], colWidths=[W - 32 * mm],
                        style=[("BACKGROUND", (0, 0), (-1, -1), C("#F3F4F6")), ("BOX", (0, 0), (-1, -1), 0.3, C("#D1D5DB")),
                               ("LEFTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)])
            rows.append([P("Correctif", "label"), box])
        body = Table(rows, colWidths=[28 * mm, W - 28 * mm],
                     style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBEFORE", (0, 0), (0, -1), 2, col),
                            ("LEFTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]) if rows else Spacer(1, 1)
        story.append(KeepTogether([head, body, Spacer(1, 4 * mm)]))
    if not acts:
        story.append(P("Aucun point à corriger.", "body"))
    story.append(PageBreak())

    # points conformes
    story.append(P("Ce qui est déjà bien", "h1"))
    oks = [f for f in a.findings if f["status"] == OK]
    if oks:
        data = [[P(h, "cellh") for h in ("Domaine", "Contrôle", "Constat")]]
        for f in oks:
            data.append([P(t(f["cat"])), P("<font color='#15803D'><b>OK</b></font>  " + t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [36 * mm, 58 * mm, W - 94 * mm]))
    else:
        story.append(P("Aucun contrôle entièrement conforme.", "body"))
    infos = [f for f in a.findings if f["status"] == INFO]
    if infos:
        story.append(Spacer(1, 6 * mm))
        story.append(P("Informations complémentaires", "h1"))
        data = [[P(h, "cellh") for h in ("Domaine", "Élément", "Détail")]]
        for f in infos:
            data.append([P(t(f["cat"])), P(t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [36 * mm, 48 * mm, W - 84 * mm]))
    story.append(PageBreak())

    # annexes
    story.append(P("Annexes : détail de la collecte", "h1"))
    current = None
    for inv in a.inventory:
        if inv["cat"] != current:
            current = inv["cat"]
            story.append(CondPageBreak(30 * mm))
            story.append(Paragraph(t(current), ParagraphStyle("cat", parent=S["h2"], fontSize=11, textColor=GRAY, spaceBefore=12)))
        story.append(CondPageBreak(25 * mm))
        story.append(P("<b>%s</b>" % t(inv["title"]), "body"))
        story.append(Spacer(1, 1.5 * mm))
        hdr, rows = inv["headers"], inv["rows"][:300]
        lens = [max([len(h)] + [min(len(r[i]) if i < len(r) else 0, 70) for r in rows]) for i, h in enumerate(hdr)]
        lens = [max(l, 4) for l in lens]
        widths = [W * l / float(sum(lens)) for l in lens]
        data = [[P(t(h), "cellh") for h in hdr]] + [[P(t(r[i]) if i < len(r) else "") for i in range(len(hdr))] for r in rows]
        story.append(grid(data, widths))
        if inv.get("note"):
            story.append(P(t(inv["note"]), "small"))
        story.append(Spacer(1, 4 * mm))

    story.append(PageBreak())
    story.append(P("Méthodologie et limites", "h1"))
    for para in (
        "Cet audit observe le serveur depuis Internet, sans y être connecté. Il est non intrusif : il établit des connexions "
        "TCP normales pour voir quels ports répondent, lit les certificats et les en-têtes, et interroge les enregistrements DNS "
        "publics. Il n'exécute aucune attaque, aucune force brute et n'envoie aucune charge utile.",
        "Le score est la part des contrôles réussis pondérée par leur sévérité. Il est plafonné à 50 en présence d'un point "
        "critique et à 80 en présence d'un point élevé.",
        "Limites : le résultat dépend du réseau depuis lequel l'audit est lancé (un pare-feu filtrant par adresse IP source peut "
        "masquer des ports) ; un hébergeur peut limiter le débit des connexions ; le contenu applicatif des sites n'est pas audité. "
        "Cet audit externe complète l'audit interne (exécuté sur le serveur), qui voit la configuration réelle des services.",
        "Pour aller plus loin depuis l'extérieur : SSL Labs (note TLS détaillée), Mozilla Observatory (en-têtes web), "
        "Hardenize ou MXToolbox (DNS et messagerie).",
    ):
        story.append(P(t(para), "lead")); story.append(Spacer(1, 3 * mm))

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
                          title="Audit externe - %s" % target, author="audit_externe.py", subject="Audit de surface d'exposition")
    cover_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 72 * mm - 30 * mm, id="cover", leftPadding=0, rightPadding=0)
    page_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 40 * mm, id="page", leftPadding=0, rightPadding=0)
    doc.addPageTemplates([PageTemplate(id="cover", frames=[cover_frame], onPage=on_cover),
                          PageTemplate(id="page", frames=[page_frame], onPage=on_page)])
    doc.build(story)


def build_html(a, path):
    e = lambda s: escape(str(s)).replace("\n", "<br>")  # noqa: E731
    score, counts = a.global_score(), a.counts()
    h = ["<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>Audit externe - %s</title><style>"
         "body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#111827}"
         "h2{border-bottom:2px solid #e5e7eb;padding-bottom:4px;margin-top:32px}"
         "table{border-collapse:collapse;width:100%%;font-size:13px;margin:8px 0}td,th{border-bottom:1px solid #e5e7eb;padding:5px;text-align:left;vertical-align:top}"
         "th{background:#111827;color:#fff}.b{color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold}"
         "pre{background:#f3f4f6;padding:8px;white-space:pre-wrap;font-size:12px}.card{border:1px solid #e5e7eb;border-left:5px solid;padding:8px 12px;margin:10px 0}"
         "@media print{h2{page-break-before:always}.card{page-break-inside:avoid}}</style></head><body>" % e(a.target)]
    h.append("<h1>Audit externe : %s</h1><p>%s</p>" % (e(a.facts.get("Cible", a.target)), a.now.strftime("%d/%m/%Y %H:%M")))
    h.append("<p style='font-size:28px'><b style='color:%s'>%d/100 (note %s)</b></p><p>%s</p>" % (score_color(score), score, grade_of(score), e(verdict(score, counts))))
    h.append("<p>" + " ".join("<span class='b' style='background:%s'>%s : %d</span>" % (SEV_COLOR[s], SEV_LABEL[s], counts[s]) for s in (CRIT, HIGH, MED, LOW, OK)) + "</p>")
    h.append("<table>" + "".join("<tr><th style='width:30%%'>%s</th><td>%s</td></tr>" % (e(k), e(v)) for k, v in a.facts.items()) + "</table>")
    h.append("<h2>Ce qu'il faut changer</h2>")
    for i, f in enumerate(a.actions(), 1):
        h.append("<div class='card' style='border-left-color:%s'><span class='b' style='background:%s'>%s</span> <b>%d. %s</b> <small>(%s)</small>"
                 % (SEV_COLOR[f["status"]], SEV_COLOR[f["status"]], SEV_LABEL[f["status"]], i, e(f["title"]), e(f["cat"])))
        h.append("<p><b>Constat :</b> %s</p><p><b>À faire :</b> %s</p>" % (e(f["detail"]), e(f["reco"])))
        if f["fix"]:
            h.append("<pre>%s</pre>" % escape(f["fix"]))
        h.append("</div>")
    h.append("<h2>Ce qui est déjà bien</h2><table><tr><th>Domaine</th><th>Contrôle</th><th>Constat</th></tr>")
    h += ["<tr><td>%s</td><td><b>%s</b></td><td>%s</td></tr>" % (e(f["cat"]), e(f["title"]), e(f["detail"])) for f in a.findings if f["status"] == OK]
    h.append("</table><h2>Informations</h2><table><tr><th>Domaine</th><th>Élément</th><th>Détail</th></tr>")
    h += ["<tr><td>%s</td><td><b>%s</b></td><td>%s</td></tr>" % (e(f["cat"]), e(f["title"]), e(f["detail"])) for f in a.findings if f["status"] == INFO]
    h.append("</table><h2>Annexes</h2>")
    for inv in a.inventory:
        h.append("<h3>%s : %s</h3>" % (e(inv["cat"]), e(inv["title"])))
        h.append("<table><tr>%s</tr>%s</table>" % ("".join("<th>%s</th>" % e(x) for x in inv["headers"]),
                                                    "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % e(c) for c in r) for r in inv["rows"])))
    h.append("</body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(h))


# --------------------------------------------------------------------------- main

def ensure_reportlab():
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        log("[!] python3-reportlab absent : rapport HTML (imprimable en PDF depuis un navigateur).", "yellow")
        log("    Pour le PDF : sudo apt install python3-reportlab fonts-dejavu-core", "gray")
        return False


def confirm_authorization(a):
    log("")
    log("  AUDIT EXTERNE - %s" % a.target, "bold")
    log("  Ce script observe la surface exposée d'un serveur depuis Internet (non intrusif).", "gray")
    log("  Ne l'utilisez QUE sur une infrastructure qui vous appartient ou que vous êtes", "yellow")
    log("  explicitement autorisé à auditer. Vous êtes responsable de cet usage.", "yellow")
    log("")
    if a.args.yes:
        log("  Autorisation confirmée via --yes.", "gray")
        return True
    if not sys.stdin.isatty():
        log("[!] Entrée non interactive : relancez avec --yes pour confirmer que vous êtes autorisé.", "red")
        return False
    try:
        ans = input("  Confirmez-vous être autorisé à auditer cette cible ? [o/N] ")
    except EOFError:
        return False
    return ans.strip().lower() in ("o", "oui", "y", "yes")


def main():
    p = argparse.ArgumentParser(description="Audit non intrusif de la surface d'exposition publique d'un VPS (vu depuis Internet).")
    p.add_argument("target", help="domaine, URL ou adresse IP publique du serveur à auditer")
    p.add_argument("-o", "--output", help="chemin du rapport (défaut : ./audit-externe-<cible>-<date>.pdf)")
    p.add_argument("--ports", default="common", help="'common' (défaut), 'top1000', 'all', ou une liste (ex: 22,80,443,8000-8100)")
    p.add_argument("--timeout", type=float, default=2.0, help="délai par connexion en secondes (défaut : 2)")
    p.add_argument("--workers", type=int, default=100, help="nombre de connexions simultanées (défaut : 100)")
    p.add_argument("-4", "--ipv4", action="store_true", help="n'auditer que les adresses IPv4 (utile sans route IPv6)")
    p.add_argument("--no-paths", action="store_true", help="ne pas tester les chemins sensibles (.git, .env...)")
    p.add_argument("--json", action="store_true", help="exporter aussi les résultats en JSON")
    p.add_argument("--yes", action="store_true", help="confirmer sans question que vous êtes autorisé à auditer la cible")
    p.add_argument("--version", action="version", version="audit_externe.py " + VERSION)
    args = p.parse_args()

    a = ExternalAudit(args)
    if not confirm_authorization(a):
        sys.exit("Audit annulé.")

    pdf_ok = ensure_reportlab()
    log("[*] Audit externe de %s (%s)" % (a.target, a.now.strftime("%d/%m/%Y %H:%M")), "bold")
    a.run_all()
    if not a.ips:
        sys.exit("Impossible de résoudre ou d'atteindre la cible.")

    safe = re.sub(r"[^\w.-]", "_", a.target)[:40]
    base = args.output or os.path.join(os.getcwd(), "audit-externe-%s-%s.pdf" % (safe, a.now.strftime("%Y%m%d-%H%M")))
    if not pdf_ok:
        base = os.path.splitext(base)[0] + ".html"
    outputs = []
    try:
        (build_pdf if pdf_ok else build_html)(a, base)
        outputs.append(base)
    except Exception as e:  # noqa: BLE001
        log("[!] Échec de la génération du PDF (%s) : rapport HTML de secours." % e, "red")
        base = os.path.splitext(base)[0] + ".html"
        build_html(a, base)
        outputs.append(base)
    if args.json:
        jp = os.path.splitext(base)[0] + ".json"
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(dict(target=a.target, date=a.now.isoformat(), version=VERSION, score=a.global_score(),
                           grade=grade_of(a.global_score()), facts=a.facts, findings=a.findings, inventory=a.inventory),
                      f, ensure_ascii=False, indent=2)
        outputs.append(jp)
    for o in outputs:
        try:
            os.chmod(o, 0o600)
        except OSError:
            pass

    score, counts = a.global_score(), a.counts()
    col = "green" if score >= 80 else "yellow" if score >= 55 else "red"
    log("")
    log("Posture externe : %d/100 (note %s)" % (score, grade_of(score)), col)
    log("Critiques : %d | Élevés : %d | Moyens : %d | Faibles : %d | Conformes : %d"
        % (counts[CRIT], counts[HIGH], counts[MED], counts[LOW], counts[OK]))
    for f in a.actions()[:5]:
        log("  - [%s] %s" % (SEV_LABEL[f["status"]], f["title"]), "red" if f["status"] in (CRIT, HIGH) else "yellow")
    for o in outputs:
        log("Rapport : %s" % o, "bold")


if __name__ == "__main__":
    main()
