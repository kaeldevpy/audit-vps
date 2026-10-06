#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_vps.py - Audit complet d'un VPS Ubuntu avec génération d'un rapport PDF.

Domaines analysés : système et mises à jour, ressources, comptes et authentification,
SSH, pare-feu et ports exposés, anti-intrusion, paramètres noyau, système de fichiers,
services, serveurs web et certificats TLS, PHP, bases de données, Docker, sauvegardes,
supervision, messagerie et réseau.

Usage :
    sudo python3 audit_vps.py                        # rapport PDF dans le dossier courant
    sudo python3 audit_vps.py -o /root/audit.pdf     # chemin de sortie personnalisé
    sudo python3 audit_vps.py --quick                # saute le scan complet du disque
    sudo python3 audit_vps.py --install-deps         # installe python3-reportlab sans demander
    sudo python3 audit_vps.py --domain exemple.fr    # domaines supplémentaires à tester (répétable)
    sudo python3 audit_vps.py --json                 # exporte aussi les résultats en JSON

Le script est en lecture seule : il ne modifie aucune configuration. Seules exceptions :
« apt-get update » pour rafraîchir la liste des paquets (désactivable avec --no-apt-update)
et l'installation optionnelle de python3-reportlab pour produire le PDF.
"""

import argparse
import datetime
import glob
import grp
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from collections import Counter, OrderedDict
from xml.sax.saxutils import escape

VERSION = "1.0.0"

os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/local/sbin:/usr/sbin:/sbin"
ENV = dict(os.environ, LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")

CRIT, HIGH, MED, LOW, INFO, OK = "critique", "eleve", "moyen", "faible", "info", "ok"
SEV_WEIGHT = {CRIT: 10, HIGH: 6, MED: 3, LOW: 1}
SEV_LABEL = {CRIT: "CRITIQUE", HIGH: "ÉLEVÉ", MED: "MOYEN", LOW: "FAIBLE", INFO: "INFO", OK: "OK"}
SEV_RANK = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3, INFO: 4, OK: 5}
SEV_COLOR = {CRIT: "#B91C1C", HIGH: "#EA580C", MED: "#D97706", LOW: "#2563EB", INFO: "#6B7280", OK: "#15803D"}

UBUNTU_EOL = {
    "14.04": datetime.date(2019, 4, 30), "16.04": datetime.date(2021, 4, 30),
    "18.04": datetime.date(2023, 5, 31), "20.04": datetime.date(2025, 5, 31),
    "22.04": datetime.date(2027, 6, 1), "24.04": datetime.date(2029, 5, 31),
    "26.04": datetime.date(2031, 5, 31),
    "21.04": datetime.date(2022, 1, 20), "21.10": datetime.date(2022, 7, 14),
    "22.10": datetime.date(2023, 7, 20), "23.04": datetime.date(2024, 1, 25),
    "23.10": datetime.date(2024, 7, 11), "24.10": datetime.date(2025, 7, 10),
    "25.04": datetime.date(2026, 1, 15), "25.10": datetime.date(2026, 7, 9),
    "26.10": datetime.date(2027, 7, 15),
}

# Port -> (service, sévérité si exposé publiquement, explication)
RISKY_PORTS = {
    21: ("FTP", HIGH, "FTP transmet identifiants et données en clair. Utilisez SFTP (fourni par SSH)."),
    23: ("Telnet", CRIT, "Telnet transmet tout en clair, mots de passe compris. Désinstallez-le."),
    53: ("DNS", MED, "Vérifiez qu'il ne s'agit pas d'un résolveur ouvert, exploitable pour des attaques par amplification."),
    69: ("TFTP", HIGH, "TFTP n'a aucune authentification."),
    111: ("rpcbind", MED, "rpcbind divulgue les services RPC et sert à des attaques par amplification."),
    135: ("MS-RPC", HIGH, "Service RPC Windows/Samba à ne jamais exposer."),
    137: ("NetBIOS", HIGH, "NetBIOS ne doit jamais être exposé sur Internet."),
    139: ("NetBIOS/SMB", HIGH, "SMB ne doit jamais être exposé sur Internet."),
    445: ("SMB", HIGH, "SMB est une cible majeure (rançongiciels, vers)."),
    161: ("SNMP", MED, "SNMP (v1/v2c surtout) divulgue la configuration du serveur."),
    389: ("LDAP", MED, "Un annuaire LDAP ne devrait pas être exposé publiquement."),
    873: ("rsync", MED, "Un démon rsync exposé peut permettre la lecture ou l'écriture de fichiers."),
    1433: ("MS SQL Server", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    1521: ("Oracle DB", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    2049: ("NFS", HIGH, "NFS exposé permet souvent de monter les partages à distance."),
    2375: ("API Docker (non chiffrée)", CRIT, "L'API Docker sans TLS donne un accès root complet à n'importe qui."),
    2376: ("API Docker (TLS)", MED, "N'exposez l'API Docker que si c'est indispensable, avec authentification par certificat client."),
    2379: ("etcd", CRIT, "etcd contient souvent des secrets (Kubernetes) et doit rester privé."),
    2380: ("etcd (peer)", HIGH, "Le port peer d'etcd doit rester privé."),
    3306: ("MySQL/MariaDB", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    33060: ("MySQL X Protocol", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    3389: ("RDP", MED, "Le bureau à distance est une cible majeure de bruteforce."),
    4243: ("API Docker", CRIT, "L'API Docker donne un accès root complet à l'hôte."),
    5432: ("PostgreSQL", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    5601: ("Kibana", MED, "Interface d'administration à protéger derrière une authentification ou un VPN."),
    5672: ("RabbitMQ (AMQP)", MED, "Un broker de messages ne devrait pas être public."),
    5900: ("VNC", HIGH, "VNC est souvent peu protégé et très ciblé."),
    5984: ("CouchDB", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    6379: ("Redis", CRIT, "Redis exposé est régulièrement compromis (exécution de code, minage)."),
    6443: ("API Kubernetes", MED, "L'API Kubernetes devrait être filtrée par IP."),
    8086: ("InfluxDB", MED, "Une base de données ne devrait pas être publique."),
    8500: ("Consul", MED, "L'interface Consul ne devrait pas être publique."),
    8983: ("Solr", MED, "Solr exposé a déjà été massivement exploité."),
    9042: ("Cassandra", HIGH, "Une base de données ne doit pas être joignable depuis Internet."),
    9090: ("Prometheus", MED, "Prometheus expose vos métriques et la topologie de l'infrastructure."),
    9100: ("node_exporter", MED, "Les métriques système ne devraient pas être publiques."),
    9200: ("Elasticsearch", CRIT, "Elasticsearch exposé est une cause fréquente de fuites de données."),
    9300: ("Elasticsearch (transport)", HIGH, "Le port de transport Elasticsearch doit rester privé."),
    10250: ("Kubelet", CRIT, "Le kubelet exposé permet l'exécution de commandes dans les pods."),
    11211: ("Memcached", CRIT, "Memcached exposé sert à des attaques DDoS par amplification massives."),
    15672: ("RabbitMQ (admin)", MED, "Interface d'administration à ne pas exposer publiquement."),
    27017: ("MongoDB", CRIT, "MongoDB exposé est une cause majeure de fuites et de rançons de données."),
    27018: ("MongoDB", CRIT, "MongoDB exposé est une cause majeure de fuites et de rançons de données."),
    61616: ("ActiveMQ", HIGH, "ActiveMQ exposé a fait l'objet de failles critiques exploitées."),
}

# Binaires SUID/SGID livrés en standard par Ubuntu (noms de fichiers).
KNOWN_SUID = {
    "passwd", "chsh", "chfn", "gpasswd", "newgrp", "su", "sudo", "sudoedit", "mount", "umount",
    "pkexec", "fusermount", "fusermount3", "at", "crontab", "chage", "expiry", "ssh-agent",
    "wall", "write", "bsd-write", "write.ul", "dotlockfile", "plocate", "mlocate", "locate",
    "staprun", "ntfs-3g", "sg", "newuidmap", "newgidmap", "unix_chkpwd", "pam_extrausers_chkpwd",
    "mail-lock", "mail-touchlock", "mail-unlock", "traceroute6.iputils", "ping", "ping6",
    "dbus-daemon-launch-helper", "ssh-keysign", "polkit-agent-helper-1", "dmcrypt-get-device",
    "snap-confine", "utempter", "pppd", "Xorg.wrap", "postdrop", "postqueue", "lxc-user-nic",
    "vmware-user-suid-wrapper", "apt-update", "chromium-sandbox", "chrome-sandbox", "exim4", "procmail",
    "lockfile", "screen", "fping", "fping6", "mtr-packet", "arping", "keybase-redirect",
    "ksu", "Xorg", "netkit-rsh", "rcp", "rlogin", "rsh", "uuidd", "lppasswd", "usernetctl",
    "gnome-keyring-daemon", "mount.nfs", "mount.cifs", "mount.ecryptfs_private", "doas",
    "dumpcap", "vmware-authd", "sendmail", "torbrowser", "tcpdump",
}

BACKUP_TOOLS = ["restic", "borg", "borgmatic", "duplicity", "duply", "rsnapshot", "rclone", "timeshift",
                "kopia", "autorestic", "bacula-fd", "urbackupclientbackend", "proxmox-backup-client",
                "duplicati-cli", "veeamconfig", "backup-manager", "bupstash", "zrepl", "sanoid", "restic-rest"]

MONITORING = [("prometheus-node-exporter", "node_exporter"), ("node_exporter", "node_exporter"),
              ("netdata", "Netdata"), ("zabbix-agent", "Zabbix"), ("zabbix-agent2", "Zabbix"),
              ("datadog-agent", "Datadog"), ("telegraf", "Telegraf"), ("monit", "Monit"),
              ("newrelic-infra", "New Relic"), ("beszel-agent", "Beszel"), ("alloy", "Grafana Alloy"),
              ("grafana-agent", "Grafana Agent"), ("collectd", "collectd"),
              ("nagios-nrpe-server", "Nagios NRPE"), ("check-mk-agent", "Checkmk"),
              ("glances", "Glances"), ("elastic-agent", "Elastic Agent"), ("wazuh-agent", "Wazuh")]

MINER_NAMES = {"xmrig", "kinsing", "kdevtmpfsi", "minerd", "cpuminer", "xmr-stak", "nanominer",
               "t-rex", "lolminer", "ccminer", "kthreaddi", "dbused", "watchbog", "sysupdate", "networkservice"}


# --------------------------------------------------------------------------- utilitaires

def log(msg, color=None):
    codes = {"blue": "34", "green": "32", "yellow": "33", "red": "31", "gray": "90", "bold": "1"}
    if color and sys.stderr.isatty():
        msg = "\033[%sm%s\033[0m" % (codes[color], msg)
    print(msg, file=sys.stderr, flush=True)


def run(cmd, timeout=60, inp=None):
    """Exécute une commande, renvoie (code retour, stdout, stderr) sans jamais lever d'exception."""
    try:
        p = subprocess.run(cmd, shell=isinstance(cmd, str), input=inp, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout, env=ENV)
        return (p.returncode, p.stdout.decode("utf-8", "replace").strip(),
                p.stderr.decode("utf-8", "replace").strip())
    except FileNotFoundError:
        return 127, "", "commande introuvable"
    except subprocess.TimeoutExpired:
        return 124, "", "délai dépassé"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def out(cmd, timeout=60):
    return run(cmd, timeout)[1]


def has(cmd):
    return shutil.which(cmd) is not None


def read(path, default=None):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:  # noqa: BLE001
        return default


def pkg(name):
    rc, o, _ = run(["dpkg-query", "-W", "-f=${Status}", name], 15)
    return rc == 0 and "install ok installed" in o


def svc_active(name):
    return out(["systemctl", "is-active", name], 15) == "active"


def unit_exists(name):
    rc, o, _ = run(["systemctl", "list-unit-files", "--no-legend", name], 15)
    return rc == 0 and name.split(".")[0] in o


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def human(n):
    n = float(n)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if abs(n) < 1024 or unit == "To":
            return ("%.0f %s" if unit == "o" else "%.1f %s") % (n, unit)
        n /= 1024.0
    return str(n)


def parse_size(s):
    m = re.search(r"([\d.]+)\s*([BKMGT])", s or "")
    if not m:
        return 0
    return float(m.group(1)) * {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]


def vkey(s):
    return [(0, int(x)) if x.isdigit() else (1, x) for x in re.split(r"(\d+)", s) if x]


def plural(n, word, word_pl=None):
    return "%d %s" % (n, word if n <= 1 else (word_pl or word + "s"))


def shorten(items, n=15, sep=", "):
    items = list(items)
    s = sep.join(str(i) for i in items[:n])
    if len(items) > n:
        s += "%s... (+%d)" % (sep, len(items) - n)
    return s


def addr_scope(addr):
    if addr in ("*", "0.0.0.0", "::", ""):
        return "public"
    try:
        ip = ipaddress.ip_address(addr)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if ip.is_loopback:
            return "loopback"
        if ip.is_private or ip.is_link_local:
            return "privé"
        return "public"
    except ValueError:
        return "loopback" if addr == "localhost" else "public"


def parse_ss():
    socks = []
    o = out(["ss", "-tulpnH"]) or out(["ss", "-tulpn"])
    for line in o.splitlines():
        if line.startswith("Netid"):
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        addr, _, port = parts[4].rpartition(":")
        if not port.isdigit():
            continue
        addr = addr.strip("[]").split("%")[0]
        m = re.search(r'users:\(\("([^"]+)"', line)
        socks.append(dict(proto=parts[0], addr=addr, port=int(port), proc=m.group(1) if m else "?",
                          scope=addr_scope(addr)))
    return socks


def parse_os_release():
    d = {}
    for line in (read("/etc/os-release") or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            d[k] = v.strip().strip('"')
    return d


def strip_comments(text):
    return "\n".join(l.split("#", 1)[0] for l in (text or "").splitlines())


def cert_info(pem=None, path=None):
    """Renvoie (date d'expiration, émetteur, sujet) d'un certificat via openssl."""
    cmd = ["openssl", "x509", "-noout", "-enddate", "-issuer", "-subject"]
    if path:
        cmd += ["-in", path]
    rc, o, _ = run(cmd, 15, inp=pem.encode() if pem else None)
    if rc != 0:
        return None, "", ""
    end, issuer, subject = None, "", ""
    for line in o.splitlines():
        if line.startswith("notAfter="):
            try:
                end = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(line.split("=", 1)[1]), datetime.timezone.utc).replace(tzinfo=None)
            except Exception:  # noqa: BLE001
                pass
        elif line.startswith("issuer="):
            m = re.search(r"CN\s*=\s*([^,/]+)", line) or re.search(r"O\s*=\s*([^,/]+)", line)
            issuer = m.group(1).strip() if m else line[7:].strip()
        elif line.startswith("subject="):
            m = re.search(r"CN\s*=\s*([^,/]+)", line)
            subject = m.group(1).strip() if m else ""
    return end, issuer, subject


def http_head(sock, domain):
    sock.sendall(("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: audit-vps/%s\r\nAccept: */*\r\n"
                  "Connection: close\r\n\r\n" % (domain, VERSION)).encode())
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    lines = data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1").split("\r\n")
    first = lines[0].split()
    status = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
    headers = {}
    for l in lines[1:]:
        if ":" in l:
            k, v = l.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status, headers


# --------------------------------------------------------------------------- audit

class Audit:
    def __init__(self, args):
        self.args = args
        self.findings = []
        self.inventory = []
        self.facts = OrderedDict()
        self.cat = "Général"
        self.is_root = os.geteuid() == 0
        self.started = time.time()
        self.now = datetime.datetime.now()
        self.hostname = socket.gethostname()
        self.domains = set(d.strip().lower() for d in (args.domain or []) if d.strip())
        self.ssh_password_auth = None

    # ---- enregistrement des résultats
    def check(self, title, ok, sev, detail="", reco="", fix=""):
        self.findings.append(dict(cat=self.cat, title=title, status=OK if ok else sev, sev=sev,
                                  detail=detail, reco="" if ok else reco, fix="" if ok else fix))

    def info(self, title, detail):
        self.findings.append(dict(cat=self.cat, title=title, status=INFO, sev=INFO, detail=detail, reco="", fix=""))

    def table(self, title, headers, rows, note=""):
        if rows:
            self.inventory.append(dict(cat=self.cat, title=title, headers=headers,
                                       rows=[[str(c) for c in r] for r in rows], note=note))

    def text(self, title, content):
        if content and content.strip():
            self.inventory.append(dict(cat=self.cat, title=title, text=content.strip()))

    # ---- orchestration
    def run_all(self):
        self.collect_common()
        steps = [
            ("Système & mises à jour", self.audit_system),
            ("Ressources", self.audit_resources),
            ("Comptes & authentification", self.audit_accounts),
            ("SSH", self.audit_ssh),
            ("Pare-feu & exposition réseau", self.audit_firewall),
            ("Anti-intrusion & détection", self.audit_intrusion),
            ("Noyau (sysctl)", self.audit_kernel),
            ("Système de fichiers", self.audit_filesystem),
            ("Services & journalisation", self.audit_services),
            ("Web & TLS", self.audit_web),
            ("Bases de données", self.audit_databases),
            ("Docker", self.audit_docker),
            ("Sauvegardes", self.audit_backups),
            ("Supervision", self.audit_monitoring),
            ("Messagerie", self.audit_mail),
            ("Réseau", self.audit_network),
        ]
        for name, fn in steps:
            self.cat = name
            t0 = time.time()
            log("[*] %s..." % name, "blue")
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                self.info("Erreur pendant l'analyse", "%s: %s" % (type(e).__name__, e))
                log("    erreur : %s" % e, "red")
            log("    terminé en %.1fs" % (time.time() - t0), "gray")
        self.duration = time.time() - self.started

    def collect_common(self):
        self.socks = parse_ss()
        self.local_ips = set(re.findall(r"inet6?\s+([0-9a-fA-F.:]+)/", out(["ip", "-o", "addr"])))
        self.containers, self.docker_ok, self.docker_ports = [], False, {}
        if has("docker"):
            rc, o, _ = run(["docker", "ps", "-q", "--no-trunc"], 30)
            if rc == 0:
                self.docker_ok = True
                if o.split():
                    rc, o2, _ = run(["docker", "inspect"] + o.split(), 90)
                    if rc == 0:
                        try:
                            self.containers = json.loads(o2)
                        except ValueError:
                            pass
        for c in self.containers:
            name = c.get("Name", "").lstrip("/")
            for cport, binds in ((c.get("NetworkSettings") or {}).get("Ports") or {}).items():
                for b in binds or []:
                    if b.get("HostPort", "").isdigit():
                        self.docker_ports.setdefault(int(b["HostPort"]), []).append(
                            dict(container=name, ip=b.get("HostIp", ""), cport=cport))
            for k, v in ((c.get("Config") or {}).get("Labels") or {}).items():
                if k.startswith("traefik.http.routers.") and k.endswith(".rule"):
                    for d in re.findall(r"Host\(([^)]*)\)", v):
                        self.domains.update(x.strip("`'\" ").lower() for x in d.split(","))
                if k in ("VIRTUAL_HOST", "LETSENCRYPT_HOST"):
                    self.domains.update(x.strip().lower() for x in v.split(","))
            for e in (c.get("Config") or {}).get("Env") or []:
                if e.startswith(("VIRTUAL_HOST=", "LETSENCRYPT_HOST=")):
                    self.domains.update(x.strip().lower() for x in e.split("=", 1)[1].split(","))
        self.tools_present = {t: has(t) for t in ("docker", "lxd", "wg", "kubectl", "k3s", "virsh", "podman")}

    # ------------------------------------------------------------------ système
    def audit_system(self):
        osr = parse_os_release()
        ver, name = osr.get("VERSION_ID", ""), osr.get("PRETTY_NAME", "inconnu")
        uptime_s = float((read("/proc/uptime") or "0").split()[0])
        cpu = re.search(r"model name\s*:\s*(.+)", read("/proc/cpuinfo") or "")
        mem = re.search(r"MemTotal:\s+(\d+)", read("/proc/meminfo") or "")
        self.facts.update([
            ("Nom d'hôte", self.hostname),
            ("Système", name),
            ("Noyau", os.uname().release),
            ("Architecture", os.uname().machine),
            ("Virtualisation", out(["systemd-detect-virt"]) or "inconnue"),
            ("Processeur", "%s (%d cœurs)" % (cpu.group(1).strip() if cpu else "?", os.cpu_count() or 0)),
            ("Mémoire", human(int(mem.group(1)) * 1024) if mem else "?"),
            ("Uptime", "%d j %d h" % (uptime_s // 86400, (uptime_s % 86400) // 3600)),
            ("Adresses IP", shorten(sorted(ip for ip in self.local_ips if addr_scope(ip) != "loopback"), 6)),
            ("Audit exécuté en root", "oui" if self.is_root else "non (résultats partiels)"),
        ])
        if not self.is_root:
            self.check("Audit exécuté avec les droits root", False, MED,
                       "Sans root, de nombreux contrôles (shadow, sshd -T, pare-feu, Docker...) sont incomplets.",
                       "Relancez l'audit avec sudo pour obtenir un rapport complet.", "sudo python3 audit_vps.py")

        if osr.get("ID") != "ubuntu":
            self.info("Distribution", "%s : ce script est conçu pour Ubuntu, certains contrôles peuvent être inexacts." % name)

        pro_attached = False
        if has("pro"):
            rc, o, _ = run(["pro", "status", "--format", "json"], 30)
            try:
                pro_attached = bool(json.loads(o).get("attached")) if rc == 0 else False
            except ValueError:
                pass
        eol = UBUNTU_EOL.get(ver)
        if eol:
            days = (eol - self.now.date()).days
            if days < 0 and pro_attached:
                self.check("Support de la version d'Ubuntu", False, MED,
                           "%s : support standard terminé le %s, mais Ubuntu Pro (ESM) est actif." % (name, eol.strftime("%d/%m/%Y")),
                           "ESM prolonge les correctifs de sécurité, mais planifiez la migration vers une LTS récente.",
                           "sudo do-release-upgrade")
            elif days < 0:
                self.check("Support de la version d'Ubuntu", False, CRIT,
                           "%s n'est plus supportée depuis le %s : plus aucun correctif de sécurité." % (name, eol.strftime("%d/%m/%Y")),
                           "Migrez vers une version LTS supportée, ou activez Ubuntu Pro (gratuit jusqu'à 5 machines) en attendant.",
                           "sudo pro attach <TOKEN>   # ou\nsudo do-release-upgrade")
            elif days < 180:
                self.check("Support de la version d'Ubuntu", False, MED,
                           "%s : fin du support standard dans %d jours (%s)." % (name, days, eol.strftime("%d/%m/%Y")),
                           "Planifiez dès maintenant la migration vers la LTS suivante.", "sudo do-release-upgrade")
            else:
                self.check("Support de la version d'Ubuntu", True, CRIT,
                           "%s supportée jusqu'au %s (environ)." % (name, eol.strftime("%m/%Y")))
        else:
            self.info("Support de la version d'Ubuntu", "Version %s inconnue du script : vérifiez sa date de fin de support." % (ver or "?"))
        self.info("Ubuntu Pro", "Attaché (ESM / Livepatch disponibles)." if pro_attached else "Non attaché.")

        # Mises à jour
        if self.is_root and not self.args.no_apt_update:
            log("    rafraîchissement de la liste des paquets (apt-get update)...", "gray")
            run(["apt-get", "update", "-qq"], 240)
        rc, o, _ = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], 240)
        if rc == 0:
            inst = [l for l in o.splitlines() if l.startswith("Inst ")]
            sec = [l.split()[1] for l in inst if "-security" in l]
            other = [l.split()[1] for l in inst if "-security" not in l]
            self.check("Mises à jour de sécurité en attente", not sec, HIGH,
                       ("%s de sécurité en attente : %s" % (plural(len(sec), "paquet"), shorten(sec, 25))) if sec
                       else "Aucune mise à jour de sécurité en attente.",
                       "Appliquez immédiatement les correctifs de sécurité.", "sudo apt update && sudo apt upgrade -y")
            self.check("Autres mises à jour en attente", not other, LOW,
                       ("%s : %s" % (plural(len(other), "paquet"), shorten(other, 25))) if other else "Système à jour.",
                       "Appliquez les mises à jour lors d'une fenêtre de maintenance.", "sudo apt update && sudo apt full-upgrade")
        else:
            self.info("Mises à jour", "Simulation apt impossible (verrou apt ou droits insuffisants).")

        conf = "".join(read(f, "") for f in sorted(glob.glob("/etc/apt/apt.conf.d/*")))
        vals = re.findall(r'APT::Periodic::Unattended-Upgrade\s+"(\d+)"', conf)
        ua_on = pkg("unattended-upgrades") and bool(vals) and vals[-1] != "0"
        self.check("Mises à jour de sécurité automatiques", ua_on, MED,
                   "unattended-upgrades installé et activé." if ua_on else
                   "unattended-upgrades absent ou désactivé : les correctifs ne s'appliquent pas automatiquement.",
                   "Activez l'installation automatique des correctifs de sécurité.",
                   "sudo apt install -y unattended-upgrades\nsudo dpkg-reconfigure -plow unattended-upgrades")

        running = os.uname().release
        kernels = sorted((os.path.basename(k)[len("vmlinuz-"):] for k in glob.glob("/boot/vmlinuz-*")), key=vkey)
        reboot_flag = os.path.exists("/var/run/reboot-required")
        newer = kernels and kernels[-1] != running and running in kernels
        if reboot_flag or newer:
            pk = (read("/var/run/reboot-required.pkgs") or "").split()
            detail = "Un redémarrage est requis"
            if newer:
                detail += " : noyau en cours %s, noyau installé le plus récent %s" % (running, kernels[-1])
            if pk:
                detail += ". Paquets concernés : %s" % shorten(sorted(set(pk)), 10)
            self.check("Redémarrage en attente", False, MED, detail + ".",
                       "Les correctifs du noyau et des bibliothèques ne sont actifs qu'après redémarrage.", "sudo reboot")
        else:
            self.check("Redémarrage en attente", True, MED, "Le noyau en cours (%s) est le plus récent installé." % running)

        if has("needrestart") and self.is_root:
            o = out(["needrestart", "-b", "-r", "l"], 120)
            svcs = re.findall(r"NEEDRESTART-SVC:\s*(\S+)", o)
            self.check("Services à redémarrer après mise à jour", not svcs, LOW,
                       ("Services utilisant d'anciennes bibliothèques : %s" % shorten(svcs, 15)) if svcs
                       else "Aucun service n'utilise de bibliothèque obsolète.",
                       "Redémarrez ces services pour charger les bibliothèques corrigées.",
                       "sudo needrestart -r a")

        o = out(["timedatectl", "show"]) or ""
        synced = "NTPSynchronized=yes" in o or "synchronized: yes" in out(["timedatectl", "status"])
        tz = re.search(r"Timezone=(\S+)", o)
        self.facts["Fuseau horaire"] = tz.group(1) if tz else "?"
        self.check("Synchronisation de l'horloge (NTP)", synced, LOW,
                   "Horloge synchronisée." if synced else "Horloge non synchronisée : journaux et certificats peuvent être faussés.",
                   "Activez la synchronisation NTP (systemd-timesyncd ou chrony).", "sudo timedatectl set-ntp true")

        held = out(["apt-mark", "showhold"]).split()
        if held:
            self.info("Paquets bloqués (hold)", "Ces paquets ne reçoivent plus de mises à jour : %s" % shorten(held))
        rc, o, _ = run(["apt-get", "-s", "-o", "Debug::NoLocking=1", "autoremove"], 120)
        rem = [l.split()[1] for l in o.splitlines() if l.startswith("Remv ")]
        self.check("Paquets orphelins / anciens noyaux", not rem, LOW,
                   ("%s supprimable(s) : %s" % (plural(len(rem), "paquet"), shorten(rem, 12))) if rem else "Aucun paquet inutile.",
                   "Supprimez les paquets devenus inutiles (anciens noyaux notamment).", "sudo apt autoremove --purge")
        if has("canonical-livepatch") and self.is_root:
            st = out(["canonical-livepatch", "status"], 30)
            if st:
                self.info("Livepatch", "Livepatch est configuré : correctifs noyau appliqués sans redémarrage.")
        snaps = out(["snap", "list"]) if has("snap") else ""
        if snaps:
            self.info("Snaps installés", shorten([l.split()[0] for l in snaps.splitlines()[1:]], 20))

    # ------------------------------------------------------------------ ressources
    def audit_resources(self):
        n = os.cpu_count() or 1
        l1, l5, l15 = os.getloadavg()
        d = "Charge moyenne 1/5/15 min : %.2f / %.2f / %.2f pour %d cœurs." % (l1, l5, l15, n)
        if l15 > n * 1.5:
            self.check("Charge CPU", False, MED, d, "Le serveur est saturé : identifiez les processus gourmands ou augmentez les ressources.", "top -o %CPU")
        elif l15 > n:
            self.check("Charge CPU", False, LOW, d, "Charge élevée : surveillez l'évolution.", "top -o %CPU")
        else:
            self.check("Charge CPU", True, MED, d)

        mi = {}
        for line in (read("/proc/meminfo") or "").splitlines():
            k, _, v = line.partition(":")
            m = re.match(r"\s*(\d+)", v)
            if m:
                mi[k] = int(m.group(1)) * 1024
        total, avail = mi.get("MemTotal", 0), mi.get("MemAvailable", 0)
        if total:
            pct = 100.0 * avail / total
            d = "Mémoire disponible : %s sur %s (%.0f %%)." % (human(avail), human(total), pct)
            if pct < 10:
                self.check("Mémoire disponible", False, MED, d, "La mémoire est presque saturée : risque d'arrêt brutal de processus (OOM).", "ps aux --sort=-%mem | head")
            elif pct < 20:
                self.check("Mémoire disponible", False, LOW, d, "Marge mémoire faible : surveillez la consommation.", "ps aux --sort=-%mem | head")
            else:
                self.check("Mémoire disponible", True, MED, d)
            st, sf = mi.get("SwapTotal", 0), mi.get("SwapFree", 0)
            if st == 0:
                if total < 4 * 1024 ** 3:
                    self.check("Espace d'échange (swap)", False, LOW,
                               "Aucun swap avec seulement %s de RAM." % human(total),
                               "Un petit swap évite que le noyau tue des processus lors des pics de mémoire.",
                               "sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile\n"
                               "sudo mkswap /swapfile && sudo swapon /swapfile\n"
                               "echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab")
                else:
                    self.info("Espace d'échange (swap)", "Aucun swap configuré (acceptable avec %s de RAM)." % human(total))
            else:
                used = 100.0 * (st - sf) / st
                self.check("Utilisation du swap", used < 50, LOW, "Swap utilisé à %.0f %% (%s)." % (used, human(st)),
                           "Le serveur manque de RAM : le swap intensif ralentit fortement le système.")

        rc, o, _ = run(["df", "-P", "-T", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
                        "-x", "efivarfs", "-x", "fuse.lxcfs", "-x", "nsfs"])
        rows, issues, seen = [], [], set()
        for line in o.splitlines()[1:]:
            p = line.split()
            if len(p) < 7 or p[0] in seen:
                continue
            seen.add(p[0])
            pct = int(p[5].rstrip("%")) if p[5].rstrip("%").isdigit() else 0
            rows.append([p[6], p[0], p[1], human(int(p[2]) * 1024), human(int(p[3]) * 1024), p[5]])
            if pct >= 80:
                issues.append((HIGH if pct >= 90 else MED, "%s rempli à %d %%" % (p[6], pct)))
        self.table("Systèmes de fichiers", ["Montage", "Périphérique", "Type", "Taille", "Utilisé", "Usage"], rows)
        if issues:
            self.check("Espace disque", False, min((s for s, _ in issues), key=lambda s: SEV_RANK[s]),
                       "; ".join(t for _, t in issues) + ".",
                       "Libérez de l'espace (journaux, images Docker, anciens noyaux, sauvegardes locales) ou agrandissez le disque.",
                       "sudo du -xh / --max-depth=2 2>/dev/null | sort -h | tail -20\nsudo journalctl --vacuum-size=200M\nsudo apt autoremove --purge && sudo apt clean")
        else:
            self.check("Espace disque", True, HIGH, "Tous les systèmes de fichiers sont remplis à moins de 80 %.")

        o = out(["df", "-P", "-i", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay"])
        ino = []
        for line in o.splitlines()[1:]:
            p = line.split()
            if len(p) >= 6 and p[4].rstrip("%").isdigit() and int(p[4].rstrip("%")) >= 80:
                ino.append("%s : %s des inodes" % (p[5], p[4]))
        self.check("Inodes disponibles", not ino, MED, "; ".join(ino) if ino else "Inodes suffisants sur tous les volumes.",
                   "Un manque d'inodes empêche la création de fichiers même avec de l'espace libre : cherchez les dossiers contenant des millions de petits fichiers.",
                   "sudo find / -xdev -printf '%h\\n' | sort | uniq -c | sort -n | tail")

        rc, o, _ = run(["journalctl", "-k", "--since", "7 days ago", "--no-pager", "-q"], 60)
        if rc != 0 or not o:
            o = read("/var/log/kern.log", "")
        oom = len(re.findall(r"Out of memory|oom-kill|Killed process", o or ""))
        self.check("Processus tués par manque de mémoire (OOM)", oom == 0, MED,
                   ("%d événement(s) OOM ces 7 derniers jours." % oom) if oom else "Aucun événement OOM sur 7 jours.",
                   "Des processus ont été tués faute de mémoire : ajoutez de la RAM/du swap ou limitez les services gourmands.",
                   "journalctl -k | grep -i -E 'out of memory|killed process'")

        failed = [l.split()[0] for l in out(["systemctl", "--failed", "--no-legend", "--plain"]).splitlines() if l.strip()]
        self.check("Services systemd en échec", not failed, MED,
                   ("Unités en échec : %s" % shorten(failed)) if failed else "Aucune unité systemd en échec.",
                   "Analysez et corrigez les services en échec, ou désactivez-les s'ils sont inutiles.",
                   "systemctl --failed\njournalctl -u <service> -n 50")

        o = out(["journalctl", "--disk-usage"])
        size = parse_size(o)
        if size:
            self.check("Taille des journaux systemd", size < 2 * 1024 ** 3, LOW, "Journaux systemd : %s." % human(size),
                       "Limitez la taille du journal (SystemMaxUse dans /etc/systemd/journald.conf).",
                       "sudo journalctl --vacuum-size=500M\n# puis SystemMaxUse=500M dans /etc/systemd/journald.conf")
        big = out("find /var/log -xdev -type f -size +500M 2>/dev/null", 60).split()
        self.check("Fichiers journaux volumineux", not big, LOW,
                   ("Fichiers de plus de 500 Mo : %s" % shorten(big, 8)) if big else "Aucun fichier journal de plus de 500 Mo.",
                   "Vérifiez la rotation des journaux (logrotate) pour ces fichiers.", "sudo logrotate -d /etc/logrotate.conf")

        o = out(["ps", "-eo", "pid,user,pcpu,pmem,rss,comm", "--sort=-pmem", "--no-headers"])
        rows = [l.split(None, 5) for l in o.splitlines()[:12]]
        rows = [[r[0], r[1], r[2], r[3], human(int(r[4]) * 1024), r[5]] for r in rows if len(r) == 6 and r[4].isdigit()]
        self.table("Processus les plus gourmands en mémoire", ["PID", "Utilisateur", "%CPU", "%MEM", "RSS", "Commande"], rows)

    # ------------------------------------------------------------------ comptes
    def audit_accounts(self):
        users = pwd.getpwall()
        nologin = ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "")
        uid0 = [u.pw_name for u in users if u.pw_uid == 0 and u.pw_name != "root"]
        self.check("Comptes avec UID 0 hors root", not uid0, CRIT,
                   ("Comptes ayant les privilèges root : %s" % ", ".join(uid0)) if uid0 else "Seul root possède l'UID 0.",
                   "Un compte UID 0 caché est un signe classique de compromission : vérifiez et supprimez-le.",
                   "sudo userdel <compte>")
        login_users = [u for u in users if u.pw_shell not in nologin and (u.pw_uid == 0 or 1000 <= u.pw_uid < 65534)]
        sysshell = [u.pw_name for u in users if 0 < u.pw_uid < 1000 and u.pw_shell not in nologin
                    and not u.pw_shell.endswith(("/sync", "/shutdown", "/halt"))]
        if sysshell:
            self.info("Comptes système avec shell", "Comptes système disposant d'un shell interactif : %s (souvent normal pour postgres, git...)." % ", ".join(sysshell))

        shadow = read("/etc/shadow")
        sh = {}
        if shadow:
            for line in shadow.splitlines():
                f = line.split(":")
                if len(f) > 1:
                    sh[f[0]] = f[1]
            empty = [n for n, p in sh.items() if p == ""]
            self.check("Comptes sans mot de passe", not empty, CRIT,
                       ("Comptes avec mot de passe vide : %s" % ", ".join(empty)) if empty else "Aucun compte avec mot de passe vide.",
                       "Verrouillez immédiatement ces comptes ou définissez un mot de passe.", "sudo passwd -l <compte>")
            weak = [n for n, p in sh.items() if p and p[0] not in "!*" and (p.startswith("$1$") or (len(p) == 13 and not p.startswith("$")))]
            self.check("Algorithme de hachage des mots de passe", not weak, MED,
                       ("Hachages obsolètes (MD5/DES) : %s" % ", ".join(weak)) if weak else "Hachages modernes (yescrypt/SHA-512).",
                       "Changez le mot de passe de ces comptes pour le ré-hacher avec l'algorithme actuel.", "sudo passwd <compte>")
            rp = sh.get("root", "")
            locked = rp.startswith(("!", "*")) or rp == ""
            self.check("Mot de passe du compte root", locked, LOW,
                       "Mot de passe root verrouillé : l'administration passe par sudo." if locked
                       else "Le compte root possède un mot de passe utilisable.",
                       "Verrouillez le mot de passe root et utilisez sudo (vérifiez d'abord qu'un utilisateur sudo fonctionne).",
                       "sudo passwd -l root")
        else:
            self.info("Fichier /etc/shadow", "Lecture impossible sans root : contrôles des mots de passe ignorés.")

        sudoers = []
        for g in ("sudo", "admin", "wheel"):
            try:
                sudoers += grp.getgrnam(g).gr_mem
            except KeyError:
                pass
        nopass = []
        for f in ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*")):
            for line in (read(f) or "").splitlines():
                l = line.strip()
                if l and not l.startswith("#") and "NOPASSWD" in l:
                    nopass.append("%s : %s" % (f, l))
        if self.is_root:
            self.check("Sudo sans mot de passe (NOPASSWD)", not nopass, MED,
                       ("Règles NOPASSWD : " + " | ".join(nopass[:6])) if nopass else "Toutes les règles sudo exigent un mot de passe.",
                       "Avec NOPASSWD, la compromission de la clé SSH d'un utilisateur donne directement root. "
                       "Définissez d'abord un mot de passe à l'utilisateur, puis retirez NOPASSWD.",
                       "sudo passwd <utilisateur>\nsudo visudo -f /etc/sudoers.d/90-cloud-init-users   # retirer NOPASSWD:")

        self.check("Politique de complexité des mots de passe", pkg("libpam-pwquality"), LOW,
                   "libpam-pwquality installé." if pkg("libpam-pwquality") else "Aucune règle de complexité (libpam-pwquality absent).",
                   "Imposez des mots de passe robustes pour les comptes locaux.",
                   "sudo apt install -y libpam-pwquality   # réglages dans /etc/security/pwquality.conf")

        bad_home = []
        for u in login_users:
            try:
                st = os.stat(u.pw_dir)
                if st.st_mode & 0o007:
                    bad_home.append("%s (%s)" % (u.pw_dir, oct(st.st_mode & 0o777)[2:]))
            except OSError:
                pass
        self.check("Permissions des dossiers personnels", not bad_home, LOW,
                   ("Dossiers lisibles par tous : %s" % ", ".join(bad_home)) if bad_home else "Dossiers personnels non accessibles aux autres utilisateurs.",
                   "Restreignez l'accès aux dossiers personnels.", "sudo chmod 750 /home/<utilisateur>")

        rows, perm_issues, weak_keys = [], [], []
        for u in login_users:
            for akf in ("authorized_keys", "authorized_keys2"):
                path = os.path.join(u.pw_dir, ".ssh", akf)
                if not os.path.isfile(path):
                    continue
                try:
                    st, dst = os.stat(path), os.stat(os.path.dirname(path))
                except OSError:
                    continue
                if st.st_uid not in (u.pw_uid, 0) or st.st_mode & 0o022 or dst.st_mode & 0o022:
                    perm_issues.append("%s (%s)" % (path, oct(st.st_mode & 0o777)[2:]))
                keys = [l for l in (read(path) or "").splitlines() if l.strip() and not l.strip().startswith("#")]
                types = Counter()
                for line in out(["ssh-keygen", "-l", "-f", path]).splitlines():
                    m = re.match(r"(\d+)\s+\S+\s+(.*)\((\w+)\)\s*$", line)
                    if m:
                        bits, comment, kt = int(m.group(1)), m.group(2).strip(), m.group(3)
                        types[kt] += 1
                        if kt == "DSA" or (kt == "RSA" and bits < 2048):
                            weak_keys.append("%s : %s %d bits (%s)" % (u.pw_name, kt, bits, comment or "sans commentaire"))
                rows.append([u.pw_name, path, len(keys), ", ".join("%s x%d" % kv for kv in types.items())])
        self.table("Clés SSH autorisées", ["Utilisateur", "Fichier", "Clés", "Types"], rows)
        self.check("Permissions des fichiers authorized_keys", not perm_issues, MED,
                   ("Fichiers modifiables par d'autres : %s" % ", ".join(perm_issues)) if perm_issues else "Permissions correctes.",
                   "Un authorized_keys modifiable par un tiers permet de s'ajouter une clé d'accès.",
                   "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys")
        self.check("Robustesse des clés SSH autorisées", not weak_keys, MED,
                   ("Clés faibles : %s" % "; ".join(weak_keys)) if weak_keys else "Aucune clé DSA ou RSA de moins de 2048 bits.",
                   "Remplacez ces clés par des clés Ed25519.", "ssh-keygen -t ed25519   # sur votre poste, puis remplacez la clé")

        rows = []
        for u in login_users:
            rows.append([u.pw_name, u.pw_uid, u.pw_dir, u.pw_shell, "oui" if u.pw_name in sudoers or u.pw_uid == 0 else "non",
                         ("verrouillé" if sh.get(u.pw_name, "x").startswith(("!", "*")) else "défini") if sh else "?"])
        self.table("Comptes pouvant se connecter", ["Compte", "UID", "Dossier", "Shell", "Admin", "Mot de passe"], rows)
        o = out(["last", "-n", "15", "-w"])
        self.text("Dernières connexions", "\n".join(l for l in o.splitlines() if l.strip() and not l.startswith("wtmp")))

    # ------------------------------------------------------------------ SSH
    def audit_ssh(self):
        sshd = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
        if not sshd:
            self.info("Serveur SSH", "OpenSSH Server n'est pas installé.")
            return
        rc, o, e = run([sshd, "-T"], 30)
        if rc != 0:
            rc, o, e = run([sshd, "-T", "-C", "user=root,host=localhost,addr=127.0.0.1"], 30)
        if rc != 0:
            self.info("Configuration SSH", "sshd -T a échoué (%s). Lancez l'audit en root." % (e[:200] or "erreur"))
            return
        cfg, multi = {}, {}
        for line in o.splitlines():
            k, _, v = line.partition(" ")
            k = k.lower()
            cfg.setdefault(k, v.strip())
            multi.setdefault(k, []).append(v.strip())
        g = lambda k, d="": cfg.get(k, d).lower()  # noqa: E731

        self.info("Version OpenSSH", (run(["ssh", "-V"])[2] or "?"))
        pa = g("passwordauthentication") == "yes"
        kbd = g("kbdinteractiveauthentication", g("challengeresponseauthentication")) == "yes" and g("usepam") == "yes"
        self.ssh_password_auth = pa or kbd

        prl = g("permitrootlogin")
        if prl == "no":
            self.check("Connexion SSH directe en root", True, HIGH, "PermitRootLogin no.")
        elif prl in ("prohibit-password", "without-password", "forced-commands-only"):
            self.check("Connexion SSH directe en root", False, LOW, "PermitRootLogin %s : root peut se connecter par clé." % prl,
                       "Connectez-vous avec un utilisateur nominatif puis sudo : meilleure traçabilité et une barrière de plus.",
                       "# /etc/ssh/sshd_config.d/99-hardening.conf\nPermitRootLogin no\n\nsudo sshd -t && sudo systemctl reload ssh")
        else:
            self.check("Connexion SSH directe en root", False, CRIT if pa else HIGH,
                       "PermitRootLogin %s : root peut se connecter%s." % (prl, " avec un mot de passe" if pa else ""),
                       "Interdisez la connexion root directe.",
                       "# /etc/ssh/sshd_config.d/99-hardening.conf\nPermitRootLogin no\n\nsudo sshd -t && sudo systemctl reload ssh")

        self.check("Authentification SSH par mot de passe", not pa, HIGH,
                   "PasswordAuthentication %s." % g("passwordauthentication"),
                   "Les mots de passe sont exposés au bruteforce permanent d'Internet. Utilisez exclusivement les clés SSH "
                   "(vérifiez d'abord que votre clé fonctionne dans une seconde session).",
                   "# /etc/ssh/sshd_config.d/99-hardening.conf\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n\n"
                   "sudo sshd -t && sudo systemctl reload ssh\n# Attention : cloud-init peut créer /etc/ssh/sshd_config.d/50-cloud-init.conf qui réactive les mots de passe")
        self.check("Authentification SSH clavier-interactive", not kbd, MED,
                   "KbdInteractiveAuthentication %s (UsePAM %s)." % (g("kbdinteractiveauthentication", g("challengeresponseauthentication")), g("usepam")),
                   "Cette méthode permet aussi la saisie d'un mot de passe via PAM.", "KbdInteractiveAuthentication no")
        self.check("Mots de passe vides autorisés en SSH", g("permitemptypasswords") != "yes", CRIT,
                   "PermitEmptyPasswords %s." % g("permitemptypasswords"), "Désactivez immédiatement.", "PermitEmptyPasswords no")
        self.check("Authentification par clé publique", g("pubkeyauthentication") == "yes", MED,
                   "PubkeyAuthentication %s." % g("pubkeyauthentication"), "Activez l'authentification par clé.", "PubkeyAuthentication yes")

        mat = int(g("maxauthtries", "6") or 6)
        self.check("Tentatives d'authentification par connexion", mat <= 4, LOW, "MaxAuthTries %d." % mat,
                   "Réduisez le nombre d'essais par connexion.", "MaxAuthTries 3")
        lgt = int(re.sub(r"\D", "", g("logingracetime", "120")) or 120)
        self.check("Délai de connexion (LoginGraceTime)", lgt <= 60, LOW, "LoginGraceTime %ds." % lgt,
                   "Réduisez le délai laissé pour s'authentifier.", "LoginGraceTime 30")
        self.check("Redirection X11", g("x11forwarding") != "yes", LOW, "X11Forwarding %s." % g("x11forwarding"),
                   "Inutile sur un serveur, élargit la surface d'attaque.", "X11Forwarding no")
        self.check("Redirection de l'agent SSH", g("allowagentforwarding") != "yes", LOW,
                   "AllowAgentForwarding %s." % g("allowagentforwarding"),
                   "Un administrateur du serveur peut détourner votre agent SSH transféré. Désactivez si inutile.", "AllowAgentForwarding no")
        cai = int(g("clientaliveinterval", "0") or 0)
        self.check("Déconnexion des sessions inactives", cai > 0, LOW,
                   "ClientAliveInterval %d, ClientAliveCountMax %s." % (cai, g("clientalivecountmax")),
                   "Fermez automatiquement les sessions SSH abandonnées.", "ClientAliveInterval 300\nClientAliveCountMax 2")
        restricted = any(cfg.get(k) for k in ("allowusers", "allowgroups"))
        self.check("Restriction des utilisateurs SSH (AllowUsers/AllowGroups)", restricted, LOW,
                   ("AllowUsers=%s AllowGroups=%s" % (cfg.get("allowusers", "-"), cfg.get("allowgroups", "-"))) if restricted
                   else "Tous les comptes du système peuvent tenter de se connecter.",
                   "Listez explicitement les comptes autorisés à se connecter.", "AllowUsers <votre_utilisateur>")
        self.check("Niveau de journalisation SSH", g("loglevel") not in ("quiet", "fatal", "error"), LOW,
                   "LogLevel %s." % g("loglevel"), "Conservez au moins le niveau INFO (VERBOSE pour tracer les empreintes de clés).", "LogLevel VERBOSE")

        weak_c = [c for c in g("ciphers").split(",") if re.search(r"cbc|arcfour|3des|blowfish|cast128", c)]
        weak_m = [m for m in g("macs").split(",") if re.search(r"md5|sha1|umac-64|ripemd|-96", m)]
        weak_k = [k for k in g("kexalgorithms").split(",") if re.search(r"group1-|group14-sha1|group-exchange-sha1|sha1", k)]
        weak = weak_c + weak_m + weak_k
        self.check("Algorithmes cryptographiques SSH", not weak, MED,
                   ("Algorithmes faibles acceptés : %s" % shorten(weak, 12)) if weak else "Aucun chiffrement, MAC ou échange de clés obsolète.",
                   "Retirez les algorithmes CBC, SHA-1 et MD5.",
                   "# /etc/ssh/sshd_config.d/99-hardening.conf\n"
                   "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n"
                   "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n"
                   "KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512")
        dsa = os.path.exists("/etc/ssh/ssh_host_dsa_key")
        self.check("Clé d'hôte DSA", not dsa, LOW, "Clé d'hôte DSA présente." if dsa else "Aucune clé d'hôte DSA.",
                   "Supprimez la clé d'hôte DSA obsolète.", "sudo rm /etc/ssh/ssh_host_dsa_key*\nsudo systemctl reload ssh")
        try:
            st = os.stat("/etc/ssh/sshd_config")
            okp = st.st_uid == 0 and not st.st_mode & 0o022
            self.check("Permissions de sshd_config", okp, MED, "Mode %s, propriétaire UID %d." % (oct(st.st_mode & 0o777)[2:], st.st_uid),
                       "Seul root doit pouvoir modifier la configuration SSH.", "sudo chown root:root /etc/ssh/sshd_config && sudo chmod 600 /etc/ssh/sshd_config")
        except OSError:
            pass
        ports = multi.get("port", ["22"])
        self.info("Port(s) SSH", "%s. Changer de port réduit le bruit des scans automatiques mais ne remplace ni les clés ni Fail2ban." % ", ".join(ports))
        if pkg("libpam-google-authenticator") or pkg("libpam-oath") or "publickey," in g("authenticationmethods"):
            self.info("Authentification multifacteur SSH", "Un mécanisme MFA semble configuré (%s)." % (g("authenticationmethods") or "module PAM"))

        rc, o, _ = run(["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", "24 hours ago", "--no-pager", "-q"], 90)
        source = "24 dernières heures"
        if not o:
            o = "\n".join(l for l in (read("/var/log/auth.log") or "").splitlines() if "sshd" in l)
            source = "depuis la dernière rotation de auth.log"
        fails = [l for l in o.splitlines() if re.search(r"Failed password|Invalid user|authentication failure|Failed publickey", l)]
        ips = Counter(re.findall(r"from (\S+?)(?: port|$)", "\n".join(fails)))
        acc = re.findall(r"Accepted (\S+) for (\S+) from (\S+)", o)
        self.info("Tentatives SSH échouées (%s)" % source, "%d tentatives depuis %d adresses IP distinctes. %d connexion(s) réussie(s)."
                  % (len(fails), len(ips), len(acc)))
        self.table("Adresses IP les plus actives contre SSH (%s)" % source, ["Adresse IP", "Échecs"], ips.most_common(10))
        accc = Counter(acc)
        self.table("Connexions SSH réussies (%s)" % source, ["Méthode", "Utilisateur", "Depuis", "Nombre"],
                   [list(k) + [v] for k, v in accc.most_common(20)])
        pw_ok = [a for a in acc if a[0] in ("password", "keyboard-interactive/pam")]
        if pw_ok:
            self.info("Connexions SSH par mot de passe", "%d connexion(s) réussie(s) par mot de passe récemment." % len(pw_ok))

    # ------------------------------------------------------------------ pare-feu
    def ufw_allowed(self, status):
        allowed, allow_all = set(), False
        for line in status.splitlines():
            m = re.match(r"^(.+?)\s{2,}(ALLOW|LIMIT)(?: IN)?\s{2,}(.+)$", line.strip())
            if not m or not m.group(3).strip().startswith("Anywhere"):
                continue
            to = re.sub(r"\s*\(v6\)$", "", m.group(1).strip())
            to = re.sub(r"\s+on\s+\S+$", "", to)
            if to.startswith("Anywhere"):
                allow_all = True
                continue
            spec = to
            if not re.match(r"^[\d,:]+(/\w+)?$", to):
                ai = out(["ufw", "app", "info", to])
                spec = ai.split("Ports:", 1)[1] if "Ports:" in ai else ""
            for a, b in re.findall(r"(\d+)(?::(\d+))?", spec):
                allowed.update(range(int(a), int(b or a) + 1))
        return allowed, allow_all

    def audit_firewall(self):
        ufw_status = out(["ufw", "status", "verbose"]) if has("ufw") and self.is_root else ""
        ufw_active = "Status: active" in ufw_status
        default_in = re.search(r"Default:\s*(\w+)\s*\(incoming\)", ufw_status)
        default_in = default_in.group(1) if default_in else ""
        nft = out(["nft", "list", "ruleset"], 30) if has("nft") and self.is_root else ""
        nft_drop = bool(re.search(r"hook input[^;]*;\s*policy drop", nft))
        ipt = out(["iptables", "-S", "INPUT"], 30) if has("iptables") and self.is_root else ""
        ipt_drop = "-P INPUT DROP" in ipt
        ipt_rules = len(re.findall(r"-j (DROP|REJECT)", ipt))
        self.fw_ufw_deny = ufw_active and default_in in ("deny", "reject")

        if not self.is_root:
            self.info("Pare-feu", "Contrôle impossible sans root.")
        elif ufw_active:
            self.check("Pare-feu actif", self.fw_ufw_deny, CRIT if self.fw_ufw_deny else HIGH,
                       "UFW actif, politique entrante par défaut : %s." % default_in,
                       "Bloquez par défaut le trafic entrant et n'autorisez que les ports nécessaires.",
                       "sudo ufw default deny incoming\nsudo ufw default allow outgoing")
            if "Logging: off" in ufw_status:
                self.check("Journalisation du pare-feu", False, LOW, "La journalisation UFW est désactivée.",
                           "Activez-la pour garder une trace des connexions bloquées.", "sudo ufw logging low")
            else:
                self.check("Journalisation du pare-feu", True, LOW, "Journalisation UFW active.")
            v6 = re.search(r"^IPV6=(\w+)", read("/etc/default/ufw", "") or "", re.M)
            has_v6 = bool(out(["ip", "-6", "addr", "show", "scope", "global"]))
            if has_v6:
                self.check("Filtrage IPv6", not v6 or v6.group(1) == "yes", MED,
                           "IPv6 actif sur le serveur, IPV6=%s dans /etc/default/ufw." % (v6.group(1) if v6 else "?"),
                           "Sans filtrage IPv6, tous vos services sont joignables en IPv6 malgré UFW.",
                           "sudo sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw && sudo ufw reload")
            rules = out(["ufw", "status", "numbered"])
            self.text("Règles UFW", rules)
        elif nft_drop or ipt_drop:
            self.check("Pare-feu actif", True, CRIT, "Politique INPUT à DROP (%s)." % ("nftables" if nft_drop else "iptables"))
            self.text("Règles nftables" if nft_drop else "Règles iptables (INPUT)", nft if nft_drop else ipt)
        elif ipt_rules:
            self.check("Pare-feu actif", False, MED,
                       "%d règle(s) DROP/REJECT dans INPUT mais politique par défaut ACCEPT." % ipt_rules,
                       "Passez à une politique « tout bloquer sauf » : UFW est le plus simple à maintenir.",
                       "sudo ufw allow OpenSSH\nsudo ufw default deny incoming\nsudo ufw enable")
        else:
            self.check("Pare-feu actif", False, CRIT, "Aucun pare-feu actif détecté (UFW inactif, aucune règle de filtrage).",
                       "Activez un pare-feu. Autorisez SSH AVANT d'activer UFW pour ne pas perdre l'accès. "
                       "Le pare-feu de l'hébergeur (s'il existe) n'est pas visible depuis le serveur.",
                       "sudo ufw allow OpenSSH        # ou : sudo ufw allow <port_ssh>/tcp\n"
                       "sudo ufw allow 80,443/tcp     # si serveur web\nsudo ufw default deny incoming\nsudo ufw enable")

        allowed, allow_all = self.ufw_allowed(ufw_status) if ufw_active else (set(), False)

        rows, exposures = [], OrderedDict()
        for s in sorted(self.socks, key=lambda s: (s["port"], s["proto"])):
            rows.append([s["proto"], s["addr"] or "*", s["port"], s["proc"], s["scope"]])
            if s["scope"] == "public":
                e = exposures.setdefault(s["port"], dict(procs=set(), addrs=set(), protos=set(), docker=False))
                e["procs"].add(s["proc"])
                e["addrs"].add(s["addr"] or "*")
                e["protos"].add(s["proto"])
                if s["proc"] == "docker-proxy":
                    e["docker"] = True
        for port, binds in self.docker_ports.items():
            for b in binds:
                if addr_scope(b["ip"]) == "public":
                    e = exposures.setdefault(port, dict(procs=set(), addrs=set(), protos=set(), docker=True))
                    e["docker"] = True
                    e["procs"].add("conteneur %s" % b["container"])
                    e["addrs"].add(b["ip"] or "0.0.0.0")
        self.table("Ports en écoute", ["Proto", "Adresse", "Port", "Processus", "Portée"], rows)

        risky = 0
        for port, e in exposures.items():
            procs = sorted(p for p in e["procs"] if p != "docker-proxy") or sorted(e["procs"])
            if port == 53 and all(p.startswith("systemd-resolve") for p in procs):
                continue
            if port not in RISKY_PORTS:
                continue
            name, sev, why = RISKY_PORTS[port]
            filtered = self.fw_ufw_deny and not allow_all and port not in allowed and not e["docker"]
            detail = "Port %d (%s) en écoute sur %s, processus : %s." % (port, name, ", ".join(sorted(e["addrs"])), ", ".join(procs))
            if filtered:
                sev = LOW
                detail += " Le port n'est pas autorisé dans UFW : il est filtré, mais le service reste exposé si le pare-feu est désactivé."
            elif e["docker"]:
                detail += " Port publié par Docker : il contourne les règles UFW."
            fix = ('# docker-compose.yml : publier uniquement en local\nports:\n  - "127.0.0.1:%d:%d"' % (port, port)) if e["docker"] \
                else "# Faire écouter le service sur 127.0.0.1 dans sa configuration, ou :\nsudo ufw deny %d" % port
            self.check("Port %d (%s) exposé" % (port, name), False, sev, detail,
                       why + " Limitez l'écoute à 127.0.0.1 (ou au réseau privé) et filtrez le port au pare-feu.", fix)
            risky += 1
        if not risky:
            self.check("Services sensibles exposés publiquement", True, HIGH,
                       "Aucune base de données, cache, API d'administration ou service non chiffré exposé publiquement.")
        pub = sorted(exposures)
        self.info("Ports exposés publiquement", ("%d port(s) : %s" % (len(pub), ", ".join(map(str, pub)))) if pub else "Aucun port public.")
        self.check("Surface d'exposition réseau", len(pub) <= 10, LOW, "%d port(s) en écoute publique." % len(pub),
                   "Chaque port ouvert est une cible : fermez ou faites écouter en local les services qui n'ont pas besoin d'être publics.",
                   "sudo ss -tulpn")

    # ------------------------------------------------------------------ anti-intrusion
    def audit_intrusion(self):
        f2b = has("fail2ban-client") and svc_active("fail2ban")
        cs = svc_active("crowdsec")
        sev_missing = HIGH if self.ssh_password_auth else MED
        if f2b and self.is_root:
            st = out(["fail2ban-client", "status"])
            m = re.search(r"Jail list:\s*(.*)", st)
            jails = [j.strip() for j in m.group(1).split(",") if j.strip()] if m else []
            self.check("Protection anti-bruteforce", True, sev_missing, "Fail2ban actif avec %s : %s." % (plural(len(jails), "jail"), ", ".join(jails) or "aucune"))
            self.check("Jail SSH Fail2ban", any("ssh" in j for j in jails), MED,
                       "Jail SSH active." if any("ssh" in j for j in jails) else "Fail2ban tourne mais aucune jail ne protège SSH.",
                       "Activez la jail sshd.",
                       "printf '[sshd]\\nenabled = true\\nbantime = 1h\\nmaxretry = 5\\n' | sudo tee /etc/fail2ban/jail.d/sshd.local\nsudo systemctl restart fail2ban")
            rows = []
            for j in jails:
                js = out(["fail2ban-client", "status", j])
                cb = re.search(r"Currently banned:\s*(\d+)", js)
                tb = re.search(r"Total banned:\s*(\d+)", js)
                tf = re.search(r"Total failed:\s*(\d+)", js)
                bt = out(["fail2ban-client", "get", j, "bantime"])
                rows.append([j, cb.group(1) if cb else "?", tb.group(1) if tb else "?", tf.group(1) if tf else "?", bt])
            self.table("Jails Fail2ban", ["Jail", "Bannis actuels", "Total bannis", "Échecs", "Durée de ban (s)"], rows)
        elif cs:
            bouncers = []
            if has("cscli") and self.is_root:
                try:
                    bouncers = json.loads(out(["cscli", "bouncers", "list", "-o", "json"]) or "[]") or []
                except ValueError:
                    bouncers = []
            self.check("Protection anti-bruteforce", True, sev_missing, "CrowdSec actif.")
            if self.is_root:
                self.check("Bouncer CrowdSec", bool(bouncers), MED,
                           ("%d bouncer(s) enregistré(s)." % len(bouncers)) if bouncers else "Aucun bouncer : CrowdSec détecte mais ne bloque rien.",
                           "Installez un bouncer pare-feu.", "sudo apt install crowdsec-firewall-bouncer-iptables")
        else:
            self.check("Protection anti-bruteforce", False, sev_missing,
                       "Ni Fail2ban ni CrowdSec ne sont actifs.",
                       "Bannissez automatiquement les IP qui multiplient les échecs d'authentification.",
                       "sudo apt install -y fail2ban\n"
                       "printf '[sshd]\\nenabled = true\\nbantime = 1h\\nmaxretry = 5\\n' | sudo tee /etc/fail2ban/jail.d/sshd.local\n"
                       "sudo systemctl enable --now fail2ban")

        tools = [t for t in ("rkhunter", "chkrootkit", "aide", "clamscan", "lynis") if has(t)]
        self.check("Outils de détection (rootkits, intégrité)", any(t in tools for t in ("rkhunter", "chkrootkit", "aide")), LOW,
                   ("Outils présents : %s." % ", ".join(tools)) if tools else "Aucun outil de détection de rootkit ou d'intégrité.",
                   "Installez un détecteur de rootkits et lancez-le périodiquement. Lynis complète utilement cet audit.",
                   "sudo apt install -y rkhunter && sudo rkhunter --update && sudo rkhunter --check --sk")

        preload = (read("/etc/ld.so.preload") or "").strip()
        self.check("Fichier /etc/ld.so.preload", not preload, HIGH,
                   ("Contenu : %s" % preload[:200]) if preload else "Absent ou vide.",
                   "Ce fichier force le chargement d'une bibliothèque dans tous les processus : technique classique de rootkit. Vérifiez son origine.",
                   "cat /etc/ld.so.preload && dpkg -S $(cat /etc/ld.so.preload)")

        sus, miners = [], []
        for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
            try:
                exe = os.readlink("/proc/%s/exe" % pid)
            except OSError:
                continue
            comm = (read("/proc/%s/comm" % pid) or "").strip()
            if exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                sus.append("PID %s : %s" % (pid, exe))
            if comm.lower() in MINER_NAMES or os.path.basename(exe.replace(" (deleted)", "")).lower() in MINER_NAMES:
                miners.append("PID %s : %s (%s)" % (pid, comm, exe))
        self.check("Processus de minage connus", not miners, CRIT,
                   ("Processus suspects : %s" % "; ".join(miners)) if miners else "Aucun nom de mineur connu parmi les processus.",
                   "Signe probable de compromission : isolez le serveur, identifiez le vecteur d'entrée et réinstallez.",
                   "ls -l /proc/<PID>/exe && sudo ss -tpn | grep <PID>")
        self.check("Processus exécutés depuis /tmp ou /dev/shm", not sus, HIGH,
                   ("Processus : %s" % "; ".join(sus[:8])) if sus else "Aucun processus lancé depuis un répertoire temporaire.",
                   "Les malwares s'exécutent souvent depuis les répertoires temporaires : vérifiez ces processus.",
                   "ls -l /proc/<PID>/exe; cat /proc/<PID>/cmdline | tr '\\0' ' '")
        ex = out("find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null | head -30", 60).split()
        self.check("Exécutables dans les répertoires temporaires", not ex, MED,
                   ("Fichiers : %s" % shorten(ex, 10)) if ex else "Aucun fichier exécutable dans /tmp, /var/tmp, /dev/shm.",
                   "Vérifiez la provenance de ces fichiers.", "file <fichier>; ls -la <fichier>")

    # ------------------------------------------------------------------ noyau
    def audit_kernel(self):
        def sysctl(name):
            v = read("/proc/sys/" + name.replace(".", "/"))
            return v.strip() if v is not None else None

        groups = [
            ("Durcissement réseau du noyau", [
                ("net.ipv4.tcp_syncookies", ("1",), MED), ("net.ipv4.conf.all.rp_filter", ("1", "2"), LOW),
                ("net.ipv4.conf.all.accept_redirects", ("0",), LOW), ("net.ipv4.conf.default.accept_redirects", ("0",), LOW),
                ("net.ipv6.conf.all.accept_redirects", ("0",), LOW), ("net.ipv4.conf.all.send_redirects", ("0",), LOW),
                ("net.ipv4.conf.all.accept_source_route", ("0",), LOW), ("net.ipv6.conf.all.accept_source_route", ("0",), LOW),
                ("net.ipv4.icmp_echo_ignore_broadcasts", ("1",), LOW), ("net.ipv4.icmp_ignore_bogus_error_responses", ("1",), LOW),
                ("net.ipv4.conf.all.log_martians", ("1",), LOW)]),
            ("Protection mémoire et processus", [
                ("kernel.randomize_va_space", ("2",), HIGH), ("kernel.kptr_restrict", ("1", "2"), LOW),
                ("kernel.dmesg_restrict", ("1",), LOW), ("kernel.yama.ptrace_scope", ("1", "2", "3"), LOW),
                ("kernel.unprivileged_bpf_disabled", ("1", "2"), LOW), ("fs.suid_dumpable", ("0",), LOW)]),
            ("Protection des liens et fichiers partagés", [
                ("fs.protected_hardlinks", ("1",), MED), ("fs.protected_symlinks", ("1",), MED),
                ("fs.protected_fifos", ("1", "2"), LOW), ("fs.protected_regular", ("1", "2"), LOW)]),
        ]
        rows = []
        for title, params in groups:
            bad, maxsev = [], LOW
            for name, expected, sev in params:
                v = sysctl(name)
                if v is None:
                    continue
                ok = v in expected
                rows.append([name, v, " ou ".join(expected), "OK" if ok else "à corriger"])
                if SEV_RANK[sev] < SEV_RANK[maxsev]:
                    maxsev = sev
                if not ok:
                    bad.append((name, v, expected[0], sev))
            if bad:
                worst = min((b[3] for b in bad), key=lambda s: SEV_RANK[s])
                self.check(title, False, worst,
                           "Paramètres non conformes : " + "; ".join("%s = %s (attendu %s)" % (n, v, e) for n, v, e, _ in bad),
                           "Appliquez les valeurs recommandées de façon persistante.",
                           "cat <<'EOF' | sudo tee -a /etc/sysctl.d/99-hardening.conf\n" +
                           "\n".join("%s = %s" % (n, e) for n, _, e, _ in bad) + "\nEOF\nsudo sysctl --system")
            else:
                self.check(title, True, maxsev, "Tous les paramètres contrôlés sont conformes.")
        self.table("Paramètres noyau contrôlés", ["Paramètre", "Valeur", "Attendu", "État"], rows)

        fwd = sysctl("net.ipv4.ip_forward")
        need = [t for t, p in self.tools_present.items() if p]
        if fwd == "1" and need:
            self.info("Routage IP (ip_forward)", "Activé, nécessaire pour : %s." % ", ".join(need))
        elif fwd is not None:
            self.check("Routage IP (ip_forward)", fwd == "0", LOW, "net.ipv4.ip_forward = %s." % fwd,
                       "Le serveur route des paquets alors qu'aucun outil de conteneur/VPN n'a été détecté.",
                       "echo 'net.ipv4.ip_forward = 0' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system")
        mods = set(l.split()[0] for l in out(["lsmod"]).splitlines()[1:] if l.split())
        rare = sorted(mods & {"dccp", "sctp", "rds", "tipc", "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf"})
        self.check("Modules noyau rarement utilisés", not rare, LOW,
                   ("Modules chargés : %s" % ", ".join(rare)) if rare else "Aucun module réseau/système de fichiers exotique chargé.",
                   "Ces modules ont un historique de failles : bloquez-les s'ils sont inutiles.",
                   "\n".join("echo 'install %s /bin/true' | sudo tee -a /etc/modprobe.d/hardening.conf" % m for m in rare))

    # ------------------------------------------------------------------ fichiers
    def audit_filesystem(self):
        files = [("/etc/passwd", 0o644, HIGH), ("/etc/group", 0o644, MED), ("/etc/shadow", 0o640, HIGH),
                 ("/etc/gshadow", 0o640, HIGH), ("/etc/sudoers", 0o440, HIGH), ("/etc/crontab", 0o644, MED),
                 ("/etc/ssh/sshd_config", 0o644, MED)]
        bad, worst = [], LOW
        for path, maxmode, sev in files:
            try:
                st = os.stat(path)
            except OSError:
                continue
            mode = st.st_mode & 0o777
            if st.st_uid != 0 or mode & ~maxmode:
                bad.append("%s (mode %s, UID %d, attendu <= %s root)" % (path, oct(mode)[2:], st.st_uid, oct(maxmode)[2:]))
                worst = min(worst, sev, key=lambda s: SEV_RANK[s])
        self.check("Permissions des fichiers système sensibles", not bad, worst if bad else HIGH,
                   "; ".join(bad) if bad else "passwd, shadow, group, gshadow, sudoers, crontab : permissions correctes.",
                   "Rétablissez les permissions standard.",
                   "sudo chmod 644 /etc/passwd /etc/group && sudo chmod 640 /etc/shadow /etc/gshadow\n"
                   "sudo chown root:shadow /etc/shadow /etc/gshadow && sudo chmod 440 /etc/sudoers")

        mounts = {}
        for line in (read("/proc/mounts") or "").splitlines():
            p = line.split()
            if len(p) >= 4:
                mounts[p[1]] = p[3].split(",")
        issues = []
        if "/tmp" not in mounts:
            issues.append("/tmp n'est pas une partition séparée")
        else:
            miss = [o for o in ("nodev", "nosuid", "noexec") if o not in mounts["/tmp"]]
            if miss:
                issues.append("/tmp sans %s" % ", ".join(miss))
        if "/dev/shm" in mounts:
            miss = [o for o in ("nodev", "nosuid", "noexec") if o not in mounts["/dev/shm"]]
            if miss:
                issues.append("/dev/shm sans %s" % ", ".join(miss))
        self.check("Options de montage durcies (/tmp, /dev/shm)", not issues, LOW,
                   "; ".join(issues) if issues else "/tmp et /dev/shm montés avec nodev, nosuid, noexec.",
                   "Empêchez l'exécution de binaires depuis les zones temporaires (testez vos applications ensuite).",
                   "echo 'tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0' | sudo tee -a /etc/fstab\n"
                   "sudo cp /usr/share/systemd/tmp.mount /etc/systemd/system/ && sudo systemctl enable --now tmp.mount")

        if self.args.quick:
            self.info("Scan complet du disque", "Ignoré (--quick) : fichiers modifiables par tous, SUID, fichiers orphelins non contrôlés.")
            return
        roots = []
        for line in out(["df", "-P", "-T", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
                         "-x", "efivarfs", "-x", "nfs", "-x", "nfs4", "-x", "cifs", "-x", "fuse.sshfs", "-x", "vfat",
                         "-x", "9p", "-x", "drvfs", "-x", "fuse", "-x", "fuse.rclone", "-x", "ceph", "-x", "glusterfs"]).splitlines()[1:]:
            p = line.split()
            if len(p) >= 7:
                roots.append(p[6])
        roots = sorted(set(roots)) or ["/"]
        prune = " -o ".join("-path %s" % p for p in ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker",
                                                       "/var/lib/containerd", "/var/lib/lxd", "/var/snap", "/var/lib/snapd"))
        cmd = ("find %s -xdev \\( %s \\) -prune -o "
               "\\( -type f \\( -perm -0002 -o -perm -4000 -o -perm -2000 -o -nouser -o -nogroup \\) -printf 'F %%m %%u %%g %%p\\n' \\) -o "
               "\\( -type d -perm -0002 ! -perm -1000 -printf 'D %%m %%u %%g %%p\\n' \\) 2>/dev/null"
               % (" ".join("'%s'" % r for r in roots), prune))
        log("    scan du disque (fichiers modifiables, SUID, orphelins)...", "gray")
        rc, o, _ = run(cmd, 900)
        if rc == 124:
            self.info("Scan complet du disque", "Interrompu après 15 minutes : résultats partiels.")
        ww, wwd, suid, orphan = [], [], [], []
        for line in o.splitlines():
            p = line.split(" ", 4)
            if len(p) < 5:
                continue
            kind, mode, user, group, path = p[0], int(p[1], 8), p[2], p[3], p[4]
            if kind == "D":
                if path not in mounts:
                    wwd.append(path)
                continue
            if mode & 0o002 and not path.startswith(("/tmp/", "/var/tmp/")):
                ww.append(path)
            if mode & 0o6000 and os.path.basename(path) not in KNOWN_SUID:
                suid.append("%s (%s%s)" % (path, "SUID" if mode & 0o4000 else "", " SGID" if mode & 0o2000 else ""))
            if user.isdigit() or group.isdigit():
                orphan.append(path)
        self.check("Fichiers modifiables par tous", not ww, MED,
                   ("%d fichier(s) : %s" % (len(ww), shorten(ww, 10))) if ww else "Aucun fichier modifiable par tous les utilisateurs.",
                   "N'importe quel utilisateur ou service compromis peut modifier ces fichiers.", "sudo chmod o-w <fichier>")
        self.check("Répertoires modifiables par tous sans sticky bit", not wwd, MED,
                   ("%d répertoire(s) : %s" % (len(wwd), shorten(wwd, 10))) if wwd else "Tous les répertoires partagés ont le sticky bit.",
                   "Sans sticky bit, chacun peut supprimer les fichiers des autres.", "sudo chmod +t <répertoire>   # ou chmod o-w")
        self.check("Binaires SUID/SGID non standards", not suid, MED,
                   ("%d binaire(s) à vérifier : %s" % (len(suid), shorten(suid, 12))) if suid else "Seuls les binaires SUID/SGID standards d'Ubuntu sont présents.",
                   "Un binaire SUID inattendu peut permettre une élévation de privilèges. Vérifiez qu'il provient d'un paquet (dpkg -S).",
                   "dpkg -S <chemin>   # non trouvé => suspect\nsudo chmod u-s <chemin>")
        self.check("Fichiers sans propriétaire valide", not orphan, LOW,
                   ("%d fichier(s) : %s" % (len(orphan), shorten(orphan, 10))) if orphan else "Tous les fichiers ont un propriétaire existant.",
                   "Fichiers d'un compte supprimé : un futur compte réutilisant l'UID en hériterait.", "sudo chown root:root <fichier>")

    # ------------------------------------------------------------------ services
    def audit_services(self):
        o = out(["systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--plain"])
        rows = []
        for line in o.splitlines():
            p = line.split(None, 4)
            if p:
                rows.append([p[0], p[4] if len(p) > 4 else ""])
        self.table("Services actifs", ["Service", "Description"], rows)
        self.facts["Services actifs"] = str(len(rows))

        bad_services = [("telnet.socket", "Telnet", HIGH), ("inetd", "inetd", MED), ("openbsd-inetd", "inetd", MED),
                        ("xinetd", "xinetd", MED), ("vsftpd", "FTP vsftpd", MED), ("proftpd", "FTP ProFTPD", MED),
                        ("pure-ftpd", "FTP Pure-FTPd", MED), ("tftpd-hpa", "TFTP", HIGH), ("ypbind", "NIS", MED),
                        ("snmpd", "SNMP", MED), ("rpcbind", "rpcbind", MED), ("avahi-daemon", "Avahi (mDNS)", LOW),
                        ("cups", "CUPS (impression)", LOW), ("smbd", "Samba", MED), ("nfs-server", "Serveur NFS", MED),
                        ("isc-dhcp-server", "Serveur DHCP", LOW), ("bluetooth", "Bluetooth", LOW), ("ModemManager", "ModemManager", LOW)]
        found, worst = [], LOW
        for unit, label, sev in bad_services:
            if svc_active(unit) or svc_active(unit + ".socket"):
                found.append((unit, label))
                worst = min(worst, sev, key=lambda s: SEV_RANK[s])
        self.check("Services superflus ou non sécurisés", not found, worst if found else MED,
                   ("Services actifs : %s" % ", ".join("%s (%s)" % (l, u) for u, l in found)) if found
                   else "Aucun service obsolète ou superflu (telnet, FTP, rpcbind, avahi, cups...) actif.",
                   "Désactivez les services inutiles sur un serveur : chacun élargit la surface d'attaque.",
                   "\n".join("sudo systemctl disable --now %s" % u for u, _ in found))

        aa = out(["aa-enabled"]) == "Yes" or (read("/sys/module/apparmor/parameters/enabled") or "").strip() == "Y"
        st = out(["aa-status"]) if self.is_root and has("aa-status") else ""
        enf = re.search(r"(\d+) profiles are in enforce mode", st)
        self.check("AppArmor", aa, MED,
                   ("AppArmor actif%s." % (", %s profils en mode enforce" % enf.group(1) if enf else "")) if aa else "AppArmor désactivé.",
                   "AppArmor confine les services et limite l'impact d'une compromission.",
                   "sudo apt install -y apparmor apparmor-utils && sudo systemctl enable --now apparmor")

        audit_on = svc_active("auditd")
        self.check("Audit système (auditd)", audit_on, LOW, "auditd actif." if audit_on else "auditd n'est pas installé ou inactif.",
                   "auditd trace les actions sensibles (modifications de fichiers critiques, usage de sudo) pour les enquêtes après incident.",
                   "sudo apt install -y auditd && sudo systemctl enable --now auditd")
        persistent = os.path.isdir("/var/log/journal") or svc_active("rsyslog")
        self.check("Conservation des journaux", persistent, LOW,
                   "Journaux persistants (%s)." % ("journald + rsyslog" if svc_active("rsyslog") else "journald") if persistent
                   else "Les journaux sont perdus à chaque redémarrage.",
                   "Rendez les journaux persistants pour pouvoir enquêter après un incident.",
                   "sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal\nsudo systemctl restart systemd-journald")
        self.check("Rotation des journaux (logrotate)", has("logrotate"), LOW,
                   "logrotate installé." if has("logrotate") else "logrotate absent : les journaux peuvent remplir le disque.",
                   "Installez logrotate.", "sudo apt install -y logrotate")

        cron_bad = []
        for p in ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
                  "/var/spool/cron/crontabs"]:
            paths = [p] + (glob.glob(p + "/*") if os.path.isdir(p) else [])
            for f in paths:
                try:
                    st = os.stat(f)
                    if st.st_mode & 0o002 or (st.st_uid != 0 and not f.startswith("/var/spool/cron/crontabs/")):
                        cron_bad.append("%s (%s, UID %d)" % (f, oct(st.st_mode & 0o777)[2:], st.st_uid))
                except OSError:
                    pass
        self.check("Permissions des tâches planifiées", not cron_bad, HIGH,
                   ("Éléments modifiables par un non-root : %s" % shorten(cron_bad, 8)) if cron_bad
                   else "Fichiers et scripts cron appartenant à root et non modifiables par les autres.",
                   "Une tâche cron modifiable par un tiers permet d'exécuter du code en root.",
                   "sudo chown root:root <fichier> && sudo chmod go-w <fichier>")

        rows = []
        for f in ["/etc/crontab"] + sorted(glob.glob("/etc/cron.d/*")):
            for line in (read(f) or "").splitlines():
                l = line.strip()
                if l and not l.startswith("#") and not re.match(r"^[A-Z_]+=", l):
                    rows.append([f, l])
        for f in sorted(glob.glob("/var/spool/cron/crontabs/*")):
            for line in (read(f) or "").splitlines():
                l = line.strip()
                if l and not l.startswith("#") and not re.match(r"^[A-Z_]+=", l):
                    rows.append(["crontab de %s" % os.path.basename(f), l])
        for d in ("daily", "weekly", "monthly", "hourly"):
            for f in sorted(glob.glob("/etc/cron.%s/*" % d)):
                if not f.endswith(".placeholder"):
                    rows.append(["/etc/cron.%s" % d, os.path.basename(f)])
        self.cron_rows = rows
        self.table("Tâches cron", ["Source", "Entrée"], rows)
        timers = re.findall(r"(\S+\.timer)\s+(\S+\.service)", out(["systemctl", "list-timers", "--all", "--no-legend", "--plain"]))
        self.timers = timers
        self.table("Timers systemd", ["Timer", "Service déclenché"], timers)

    # ------------------------------------------------------------------ web
    def audit_web(self):
        found = []
        if has("nginx"):
            found.append("Nginx")
            ver = run(["nginx", "-v"])[2]
            rc, _, err = run(["nginx", "-t"], 30)
            self.check("Configuration Nginx valide", rc == 0, HIGH, "nginx -t : %s" % ("OK" if rc == 0 else err[-300:]),
                       "Corrigez la configuration : le prochain rechargement échouera.", "sudo nginx -t")
            rc, conf, _ = run(["nginx", "-T"], 30)
            c = strip_comments(conf)
            if c:
                self.info("Version Nginx", ver.replace("nginx version: ", ""))
                self.check("Nginx : version masquée (server_tokens)", bool(re.search(r"\bserver_tokens\s+off\s*;", c)), LOW,
                           "server_tokens off présent." if re.search(r"\bserver_tokens\s+off\s*;", c) else "Nginx affiche sa version dans les en-têtes et pages d'erreur.",
                           "Masquez la version pour compliquer le ciblage de failles connues.",
                           "# bloc http de /etc/nginx/nginx.conf\nserver_tokens off;\n\nsudo nginx -t && sudo systemctl reload nginx")
                weak = sorted(set(t for p in re.findall(r"\bssl_protocols\s+([^;]+);", c) for t in p.split()
                                  if t in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")))
                self.check("Nginx : protocoles TLS obsolètes", not weak, MED,
                           ("Protocoles obsolètes activés : %s" % ", ".join(weak)) if weak else "Aucun protocole antérieur à TLS 1.2 dans ssl_protocols.",
                           "Désactivez TLS 1.0/1.1, vulnérables et refusés par les navigateurs.",
                           "ssl_protocols TLSv1.2 TLSv1.3;")
                ai = re.search(r"\bautoindex\s+on\s*;", c)
                self.check("Nginx : listage des répertoires", not ai, LOW,
                           "autoindex on présent." if ai else "Aucun listage de répertoire activé.",
                           "Le listage expose l'arborescence et des fichiers potentiellement sensibles.", "autoindex off;")
                for names in re.findall(r"\bserver_name\s+([^;]+);", c):
                    for n in names.split():
                        n = n.lower().lstrip(".")
                        if n not in ("_", "localhost", '""') and "*" not in n and not n.startswith("~") and "." in n:
                            self.domains.add(n)
        ctl = shutil.which("apache2ctl") or shutil.which("apachectl")
        if ctl and (pkg("apache2") or svc_active("apache2")):
            found.append("Apache")
            rc, o, e = run([ctl, "configtest"], 30)
            self.check("Configuration Apache valide", "Syntax OK" in (o + e), HIGH, (o + e)[-300:],
                       "Corrigez la configuration Apache.", "sudo apache2ctl configtest")
            conf = ""
            for f in (["/etc/apache2/apache2.conf"] + glob.glob("/etc/apache2/conf-enabled/*.conf")
                      + glob.glob("/etc/apache2/sites-enabled/*") + glob.glob("/etc/apache2/mods-enabled/*.conf")):
                conf += (read(f) or "") + "\n"
            c = strip_comments(conf)
            tokens = re.findall(r"^\s*ServerTokens\s+(\S+)", c, re.M | re.I)
            sig = re.findall(r"^\s*ServerSignature\s+(\S+)", c, re.M | re.I)
            ok = tokens and tokens[-1].lower() in ("prod", "productonly") and sig and sig[-1].lower() == "off"
            self.check("Apache : version masquée", bool(ok), LOW,
                       "ServerTokens %s, ServerSignature %s." % (tokens[-1] if tokens else "défaut", sig[-1] if sig else "défaut"),
                       "Masquez la version d'Apache et du système.",
                       "sudo sed -i 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf\nsudo systemctl reload apache2")
            trace = re.findall(r"^\s*TraceEnable\s+(\S+)", c, re.M | re.I)
            self.check("Apache : méthode TRACE", bool(trace) and trace[-1].lower() == "off", LOW,
                       "TraceEnable %s." % (trace[-1] if trace else "défaut (On)"), "Désactivez TRACE.", "TraceEnable Off")
            idx = re.search(r"^\s*Options\s+[^\n]*(?<![-\w])\+?Indexes", c, re.M | re.I)
            self.check("Apache : listage des répertoires", not idx, LOW,
                       "« Options Indexes » présent dans la configuration active." if idx else "Listage des répertoires désactivé.",
                       "Retirez Indexes des directives Options (présent par défaut sur <Directory /var/www/>).",
                       "Options -Indexes +FollowSymLinks")
            weak = []
            for p in re.findall(r"^\s*SSLProtocol\s+(.+)$", c, re.M | re.I):
                t = p.split()
                if any(x.lstrip("+") in ("SSLv3", "TLSv1", "TLSv1.1") for x in t if not x.startswith("-")):
                    weak.append(p.strip())
            self.check("Apache : protocoles TLS obsolètes", not weak, MED,
                       ("SSLProtocol : %s" % "; ".join(weak)) if weak else "Aucun protocole obsolète explicitement activé.",
                       "N'autorisez que TLS 1.2 et 1.3.", "SSLProtocol -all +TLSv1.2 +TLSv1.3")
            mods = out([ctl, "-M"])
            if "status_module" in mods:
                self.info("Apache mod_status", "mod_status est chargé : vérifiez que /server-status n'est accessible qu'en local.")
            S = " ".join(run([ctl, "-S"], 30)[1:])
            for n in re.findall(r"(?:namevhost|alias)\s+(\S+)", S):
                if "." in n and "*" not in n:
                    self.domains.add(n.lower())
        for name, unit in (("Caddy", "caddy"), ("Traefik", "traefik"), ("HAProxy", "haproxy"), ("Lighttpd", "lighttpd")):
            if svc_active(unit):
                found.append(name)
        caddy = read("/etc/caddy/Caddyfile")
        if caddy:
            for m in re.findall(r"^([^\s#{][^{\n]*)\{", caddy, re.M):
                for n in re.split(r"[,\s]+", m.strip()):
                    n = re.sub(r"^https?://", "", n).split(":")[0].lower()
                    if "." in n and "*" not in n:
                        self.domains.add(n)
        images = " ".join((c.get("Config") or {}).get("Image", "") for c in self.containers).lower()
        for n in ("traefik", "nginx", "caddy", "haproxy", "httpd", "nginx-proxy-manager", "swag"):
            if n in images:
                found.append("%s (Docker)" % n)
        self.info("Serveurs web / reverse proxy", ", ".join(sorted(set(found))) if found else "Aucun serveur web détecté.")

        # PHP
        php_issues, worst = [], LOW
        for ini in sorted(glob.glob("/etc/php/*/fpm/php.ini") + glob.glob("/etc/php/*/apache2/php.ini")):
            t = strip_comments(read(ini) or "").replace(";", "#")
            t = "\n".join(l.split("#", 1)[0] for l in t.splitlines())
            d = {k.lower(): v.strip().strip('"').lower() for k, v in re.findall(r"^\s*([\w.]+)\s*=\s*(.*)$", t, re.M)}
            for key, bad_vals, sev, label in (("expose_php", ("on", "1"), LOW, "expose_php=On"),
                                              ("display_errors", ("on", "1", "stdout"), MED, "display_errors=On"),
                                              ("allow_url_include", ("on", "1"), HIGH, "allow_url_include=On")):
                if d.get(key) in bad_vals:
                    php_issues.append("%s : %s" % (ini, label))
                    worst = min(worst, sev, key=lambda s: SEV_RANK[s])
        if glob.glob("/etc/php/*/*/php.ini"):
            self.check("Configuration PHP de production", not php_issues, worst if php_issues else MED,
                       "; ".join(php_issues) if php_issues else "expose_php, display_errors et allow_url_include désactivés.",
                       "Les erreurs affichées divulguent chemins et requêtes ; allow_url_include permet l'inclusion de code distant.",
                       "# dans php.ini (fpm/apache2)\nexpose_php = Off\ndisplay_errors = Off\nallow_url_include = Off\n\nsudo systemctl restart php*-fpm")

        # Certificats Let's Encrypt locaux
        cert_rows, exp_issues = [], []
        for cf in sorted(glob.glob("/etc/letsencrypt/live/*/cert.pem")):
            end, issuer, subj = cert_info(path=cf)
            if end:
                days = (end - utcnow()).days
                cert_rows.append([os.path.basename(os.path.dirname(cf)), end.strftime("%d/%m/%Y"), days, issuer])
                if days < 30:
                    exp_issues.append((days, "%s (fichier, %d j)" % (os.path.basename(os.path.dirname(cf)), days)))
        if cert_rows:
            timers = out(["systemctl", "list-timers", "--all", "--no-legend"])
            renew = "certbot" in timers or os.path.exists("/etc/cron.d/certbot")
            self.check("Renouvellement automatique des certificats", renew, MED,
                       "Timer/cron certbot présent." if renew else "Certificats Let's Encrypt présents mais aucun renouvellement automatique détecté.",
                       "Sans renouvellement, les certificats expirent au bout de 90 jours.",
                       "sudo systemctl enable --now certbot.timer\nsudo certbot renew --dry-run")
            self.table("Certificats Let's Encrypt (fichiers)", ["Certificat", "Expiration", "Jours restants", "Émetteur"], cert_rows)

        # Tests HTTP/TLS des domaines
        domains = sorted(self.domains)[:25]
        if not domains:
            self.info("Tests TLS / en-têtes HTTP", "Aucun domaine détecté. Utilisez --domain exemple.fr pour tester vos sites.")
            if exp_issues:
                self._cert_expiry_check(exp_issues)
            return
        log("    test de %d domaine(s)..." % len(domains), "gray")
        rows, invalid, nohttps, noredirect, hdr_missing, leak = [], [], [], [], {}, []
        for d in domains:
            r = self.probe_domain(d)
            if not r["https"]:
                nohttps.append(d)
                rows.append([d, "non", "-", "-", "-", r.get("error", "")[:60]])
                continue
            days = (r["end"] - utcnow()).days if r.get("end") else None
            if days is not None and days < 30:
                exp_issues.append((days, "%s (%d j)" % (d, days)))
            if r.get("valid") is False:
                invalid.append("%s : %s" % (d, r.get("verify_error", "")))
            h = r.get("headers", {})
            miss = []
            if "strict-transport-security" not in h:
                miss.append("HSTS")
            if "x-content-type-options" not in h:
                miss.append("X-Content-Type-Options")
            if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
                miss.append("X-Frame-Options/CSP")
            if "referrer-policy" not in h:
                miss.append("Referrer-Policy")
            if miss:
                hdr_missing[d] = miss
            srv = h.get("server", "") + " " + h.get("x-powered-by", "")
            if re.search(r"/\d", srv):
                leak.append("%s : %s" % (d, srv.strip()))
            st = r.get("http_status")
            if st is not None and not (st in (301, 302, 307, 308) and r.get("http_location", "").startswith("https://")):
                noredirect.append("%s (HTTP %s)" % (d, st))
            rows.append([d, r.get("tls_version", "?"), "valide" if r.get("valid") else ("invalide" if r.get("valid") is False else "?"),
                         ("%d j" % days) if days is not None else "?", r.get("issuer", ""), ", ".join(miss) or "complets"])
        self.table("Domaines testés", ["Domaine", "TLS", "Certificat", "Expire dans", "Émetteur", "En-têtes manquants"], rows,
                   "Tests effectués en local (127.0.0.1) avec SNI, puis via l'IP DNS si nécessaire.")
        self._cert_expiry_check(exp_issues)
        self.check("Validité des certificats TLS", not invalid, HIGH,
                   "; ".join(invalid) if invalid else "Certificats valides et correspondant aux domaines.",
                   "Les visiteurs voient une alerte de sécurité. (Un certificat d'origine Cloudflare apparaît invalide en test direct : c'est attendu.)",
                   "sudo certbot --nginx -d <domaine>   # ou --apache")
        if nohttps:
            self.check("HTTPS disponible", False, MED, "Pas de HTTPS joignable pour : %s" % ", ".join(nohttps),
                       "Servez tous les sites en HTTPS (certificat Let's Encrypt gratuit).", "sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx")
        else:
            self.check("HTTPS disponible", True, MED, "Tous les domaines détectés répondent en HTTPS.")
        self.check("Redirection HTTP vers HTTPS", not noredirect, MED,
                   ("Sans redirection : %s" % ", ".join(noredirect)) if noredirect else "Le trafic HTTP est redirigé vers HTTPS.",
                   "Redirigez systématiquement le HTTP vers le HTTPS.", "return 301 https://$host$request_uri;   # Nginx, bloc server port 80")
        self.check("En-têtes de sécurité HTTP", not hdr_missing, LOW,
                   "; ".join("%s : %s" % (d, ", ".join(m)) for d, m in hdr_missing.items()) if hdr_missing
                   else "HSTS, X-Content-Type-Options, X-Frame-Options/CSP et Referrer-Policy présents.",
                   "Ces en-têtes protègent les visiteurs (clickjacking, détournement MIME, rétrogradation HTTPS).",
                   'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
                   'add_header X-Content-Type-Options "nosniff" always;\nadd_header X-Frame-Options "SAMEORIGIN" always;\n'
                   'add_header Referrer-Policy "strict-origin-when-cross-origin" always;')
        self.check("Divulgation des versions logicielles (HTTP)", not leak, LOW,
                   "; ".join(leak) if leak else "Aucune version divulguée dans Server / X-Powered-By.",
                   "Masquez les numéros de version (server_tokens off, expose_php = Off).", "server_tokens off;")

    def _cert_expiry_check(self, issues):
        if not issues:
            self.check("Expiration des certificats TLS", True, HIGH, "Aucun certificat n'expire dans les 30 jours.")
            return
        mind = min(d for d, _ in issues)
        sev = CRIT if mind < 0 else HIGH if mind < 14 else MED
        self.check("Expiration des certificats TLS", False, sev, "Certificats expirés ou proches de l'expiration : %s"
                   % ", ".join(t for _, t in sorted(issues)), "Renouvelez-les et vérifiez le renouvellement automatique.",
                   "sudo certbot renew && sudo systemctl reload nginx")

    def probe_domain(self, domain):
        r = dict(domain=domain, https=False)
        targets = ["127.0.0.1"]
        try:
            for ai in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP):
                if ai[4][0] not in targets:
                    targets.append(ai[4][0])
        except Exception:  # noqa: BLE001
            pass
        der = None
        for host in targets[:3]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                with socket.create_connection((host, 443), timeout=6) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        ss.settimeout(6)
                        der = ss.getpeercert(True)
                        r["tls_version"] = ss.version()
                        r["status"], r["headers"] = http_head(ss, domain)
                r["https"], r["host"] = True, host
                break
            except Exception as e:  # noqa: BLE001
                r["error"] = str(e)
        if r["https"] and der:
            r["end"], r["issuer"], _ = cert_info(pem=ssl.DER_cert_to_PEM_cert(der))
            try:
                vctx = ssl.create_default_context()
                with socket.create_connection((r["host"], 443), timeout=6) as s:
                    with vctx.wrap_socket(s, server_hostname=domain):
                        r["valid"] = True
            except ssl.SSLCertVerificationError as e:
                r["valid"], r["verify_error"] = False, getattr(e, "verify_message", "") or str(e)
            except Exception:  # noqa: BLE001
                r["valid"] = None
        for host in targets[:3]:
            try:
                with socket.create_connection((host, 80), timeout=6) as s:
                    s.settimeout(6)
                    r["http_status"], h = http_head(s, domain)
                    r["http_location"] = h.get("location", "")
                break
            except Exception:  # noqa: BLE001
                continue
        return r

    # ------------------------------------------------------------------ bases de données
    def exposed(self, *ports):
        return [s for s in self.socks if s["port"] in ports and s["scope"] == "public"]

    def audit_databases(self):
        found = []
        if any(has(b) for b in ("mysqld", "mariadbd")) or pkg("mysql-server") or pkg("mariadb-server"):
            found.append("MySQL/MariaDB")
            exp = self.exposed(3306, 33060)
            self.check("MySQL/MariaDB : écoute réseau", not exp, HIGH,
                       ("Écoute publique sur %s." % ", ".join("%s:%d" % (s["addr"], s["port"]) for s in exp)) if exp else "N'écoute pas sur une interface publique.",
                       "Limitez l'écoute à 127.0.0.1 ; pour un accès distant, passez par un tunnel SSH.",
                       "# /etc/mysql/mysql.conf.d/mysqld.cnf (ou mariadb.conf.d/50-server.cnf)\nbind-address = 127.0.0.1\n\nsudo systemctl restart mysql")
            if has("mysql") and self.is_root:
                rc, o, _ = run(["mysql", "-N", "-B", "-e", "SELECT user, host FROM mysql.user"], 20)
                if rc == 0:
                    users = [l.split("\t") for l in o.splitlines() if "\t" in l]
                    anon = [h for u, h in users if u == ""]
                    rroot = [h for u, h in users if u == "root" and h not in ("localhost", "127.0.0.1", "::1")]
                    wild = ["%s@%s" % (u, h) for u, h in users if h == "%"]
                    self.check("MySQL/MariaDB : comptes anonymes", not anon, HIGH,
                               ("%d compte(s) anonyme(s)." % len(anon)) if anon else "Aucun compte anonyme.",
                               "Supprimez les comptes anonymes.", "sudo mysql_secure_installation")
                    self.check("MySQL/MariaDB : root distant", not rroot, HIGH,
                               ("root autorisé depuis : %s" % ", ".join(rroot)) if rroot else "root limité à localhost.",
                               "root ne doit se connecter qu'en local.", "sudo mysql -e \"DROP USER 'root'@'%';\"")
                    self.check("MySQL/MariaDB : comptes ouverts à toute adresse (%)", not wild, MED,
                               ("Comptes : %s" % ", ".join(wild)) if wild else "Aucun compte avec hôte '%'.",
                               "Restreignez chaque compte à l'hôte qui en a besoin.", "RENAME USER 'app'@'%' TO 'app'@'localhost';")
                    rc, o, _ = run(["mysql", "-N", "-B", "-e", "SHOW DATABASES LIKE 'test'"], 20)
                    self.check("MySQL/MariaDB : base de test", "test" not in o.split(), LOW, "Base 'test' présente." if "test" in o.split() else "Pas de base 'test'.",
                               "Supprimez la base de test, accessible à tous par défaut.", "sudo mysql -e 'DROP DATABASE test;'")
                else:
                    self.info("MySQL/MariaDB : comptes", "Connexion locale impossible sans identifiants : contrôle des comptes ignoré.")

        pg_confs = glob.glob("/etc/postgresql/*/main/postgresql.conf")
        if pg_confs:
            found.append("PostgreSQL")
            for conf in pg_confs:
                ver = conf.split("/")[3]
                la = re.findall(r"^\s*listen_addresses\s*=\s*'([^']*)'", read(conf) or "", re.M)
                la = la[-1] if la else "localhost"
                exp = self.exposed(5432)
                self.check("PostgreSQL %s : écoute réseau" % ver, not exp, HIGH,
                           "listen_addresses = '%s'%s." % (la, ", port 5432 exposé publiquement" if exp else ""),
                           "Limitez l'écoute à localhost ou au réseau privé.",
                           "listen_addresses = 'localhost'   # %s\nsudo systemctl restart postgresql" % conf)
                hba = strip_comments(read(conf.replace("postgresql.conf", "pg_hba.conf")) or "")
                trust_host, trust_local, md5, open_net = [], [], [], []
                for line in hba.splitlines():
                    f = line.split()
                    if len(f) < 4:
                        continue
                    method = f[3] if f[0] == "local" else (f[4] if len(f) > 4 else "")
                    if method == "trust":
                        (trust_local if f[0] == "local" else trust_host).append(" ".join(f))
                    if method == "md5":
                        md5.append(" ".join(f))
                    if f[0].startswith("host") and len(f) > 3 and f[3] in ("0.0.0.0/0", "::/0", "all"):
                        open_net.append(" ".join(f))
                self.check("PostgreSQL %s : méthode trust" % ver, not (trust_host or trust_local), CRIT if trust_host else MED,
                           ("Règles trust : %s" % "; ".join(trust_host + trust_local)) if trust_host or trust_local else "Aucune règle trust.",
                           "trust permet de se connecter sans mot de passe sous n'importe quel rôle.",
                           "# pg_hba.conf : remplacer trust par scram-sha-256 (ou peer en local)\nsudo systemctl reload postgresql")
                if open_net:
                    self.check("PostgreSQL %s : accès depuis toute adresse" % ver, False, MED, "; ".join(open_net),
                               "Restreignez les adresses autorisées dans pg_hba.conf.", "host all all 10.0.0.0/24 scram-sha-256")
                if md5:
                    self.check("PostgreSQL %s : hachage md5" % ver, False, LOW, "%d règle(s) md5." % len(md5),
                               "Préférez scram-sha-256 (plus résistant).", "password_encryption = scram-sha-256   # puis redéfinir les mots de passe")

        for conf in glob.glob("/etc/redis/*.conf"):
            found.append("Redis")
            c = strip_comments(read(conf) or "")
            pm = re.findall(r"^\s*protected-mode\s+(\w+)", c, re.M)
            rp = re.search(r"^\s*requirepass\s+\S+", c, re.M) or re.search(r"^\s*user\s+\S+\s+on\s+.*>", c, re.M)
            exp = self.exposed(6379)
            if exp:
                self.check("Redis : exposition", False, CRIT if not rp or (pm and pm[-1] == "no") else HIGH,
                           "Redis écoute publiquement%s." % ("" if rp else " sans mot de passe"),
                           "Redis exposé est compromis en quelques minutes : bind 127.0.0.1 et mot de passe obligatoire.",
                           "# %s\nbind 127.0.0.1 ::1\nprotected-mode yes\nrequirepass <mot_de_passe_long>\n\nsudo systemctl restart redis-server" % conf)
            else:
                self.check("Redis : exposition", True, CRIT, "Redis n'écoute pas publiquement.")
                self.check("Redis : mot de passe", bool(rp), LOW, "Mot de passe/ACL configuré." if rp else "Aucun mot de passe (accès local uniquement).",
                           "Un mot de passe protège contre l'exploitation via SSRF depuis une application web.", "requirepass <mot_de_passe_long>")
        mc = read("/etc/mongod.conf")
        if mc:
            found.append("MongoDB")
            bind = re.search(r"bindIp:\s*(\S+)", mc)
            auth = re.search(r"authorization:\s*[\"']?enabled", mc)
            exp = self.exposed(27017)
            self.check("MongoDB : authentification", bool(auth), CRIT if exp else MED,
                       "authorization %s, bindIp %s." % ("enabled" if auth else "désactivée", bind.group(1) if bind else "défaut"),
                       "Activez l'authentification et limitez bindIp à 127.0.0.1.",
                       "# /etc/mongod.conf\nnet:\n  bindIp: 127.0.0.1\nsecurity:\n  authorization: enabled")
        db_images = [c.get("Config", {}).get("Image", "") for c in self.containers
                     if re.search(r"mysql|mariadb|postgres|redis|mongo|elasticsearch|valkey|memcached|clickhouse|influx",
                                  (c.get("Config") or {}).get("Image", ""), re.I)]
        if db_images:
            found.append("conteneurs : %s" % shorten(db_images, 6))
        self.info("Bases de données détectées", ", ".join(found) if found else "Aucune base de données détectée.")

    # ------------------------------------------------------------------ Docker
    def audit_docker(self):
        if not has("docker"):
            self.info("Docker", "Docker n'est pas installé.")
            return
        rc, o, _ = run(["docker", "info", "--format", "{{json .}}"], 30)
        if rc != 0:
            self.info("Docker", "Docker est installé mais le démon est inaccessible (droits ou service arrêté).")
            return
        try:
            di = json.loads(o)
        except ValueError:
            di = {}
        self.facts["Docker"] = "%s, %s conteneur(s) actif(s)" % (di.get("ServerVersion", "?"), di.get("ContainersRunning", "?"))
        secopts = " ".join(di.get("SecurityOptions") or [])
        daemon = {}
        try:
            daemon = json.loads(read("/etc/docker/daemon.json") or "{}")
        except ValueError:
            self.check("Fichier daemon.json", False, MED, "/etc/docker/daemon.json n'est pas un JSON valide.",
                       "Corrigez la syntaxe : Docker ne redémarrera pas.", "python3 -m json.tool /etc/docker/daemon.json")
        logdrv = di.get("LoggingDriver", "")
        lim = (daemon.get("log-opts") or {}).get("max-size")
        self.check("Docker : rotation des journaux des conteneurs", logdrv != "json-file" or bool(lim), MED,
                   "Pilote %s%s." % (logdrv, (", max-size %s" % lim) if lim else ", sans limite de taille"),
                   "Les journaux json-file grossissent sans limite et finissent par remplir le disque.",
                   'cat <<\'EOF\' | sudo tee /etc/docker/daemon.json\n{\n  "log-driver": "json-file",\n  "log-opts": {"max-size": "10m", "max-file": "3"},\n'
                   '  "live-restore": true,\n  "no-new-privileges": true\n}\nEOF\nsudo systemctl restart docker   # s\'applique aux nouveaux conteneurs')
        self.check("Docker : live-restore", bool(di.get("LiveRestoreEnabled")), LOW,
                   "live-restore %s." % ("activé" if di.get("LiveRestoreEnabled") else "désactivé"),
                   "Permet de mettre à jour/redémarrer le démon sans arrêter les conteneurs.", '"live-restore": true   # dans daemon.json')
        self.check("Docker : no-new-privileges par défaut", bool(daemon.get("no-new-privileges")), LOW,
                   "Activé." if daemon.get("no-new-privileges") else "Non activé.",
                   "Empêche les processus des conteneurs d'acquérir de nouveaux privilèges (SUID).", '"no-new-privileges": true   # dans daemon.json')
        self.info("Docker : isolation", "Options de sécurité : %s." % (secopts or "aucune")
                  + (" Mode rootless ou userns-remap actif." if ("rootless" in secopts or "userns" in secopts) else
                     " Ni rootless ni userns-remap : root dans un conteneur = root sur l'hôte en cas d'évasion."))

        hosts = daemon.get("hosts") or []
        unit = out(["systemctl", "cat", "docker.service"])
        tcp = [h for h in hosts if h.startswith("tcp://")] + re.findall(r"-H\s*(tcp://\S+)", unit)
        tls = daemon.get("tlsverify") or "--tlsverify" in unit
        api_exp = self.exposed(2375, 2376, 4243)
        self.check("Docker : API exposée sur le réseau", not (tcp or api_exp), CRIT if (tcp and not tls) or self.exposed(2375) else MED,
                   ("API Docker en TCP : %s%s." % (", ".join(tcp) or "port ouvert", "" if tls else ", sans TLS")) if tcp or api_exp
                   else "L'API Docker n'écoute que sur le socket Unix local.",
                   "L'API Docker donne un contrôle root total de l'hôte : ne l'exposez jamais sans TLS mutuel. Préférez un accès via SSH (DOCKER_HOST=ssh://...).",
                   "# retirer \"hosts\" tcp:// de /etc/docker/daemon.json et -H tcp:// de l'unité systemd\nsudo systemctl daemon-reload && sudo systemctl restart docker")
        try:
            members = grp.getgrnam("docker").gr_mem
        except KeyError:
            members = []
        if members:
            self.info("Groupe docker", "Membres : %s. Appartenir au groupe docker équivaut à être root." % ", ".join(members))

        priv, sock, sens, hostns, caps, rootu, nomem, norestart, unhealthy, pubports, rows, img_ids = ([] for _ in range(12))
        for c in self.containers:
            name = c.get("Name", "").lstrip("/")
            hc, cfg = c.get("HostConfig") or {}, c.get("Config") or {}
            if hc.get("Privileged"):
                priv.append(name)
            mounts = c.get("Mounts") or []
            for m in mounts:
                src = m.get("Source", "")
                if src in ("/var/run/docker.sock", "/run/docker.sock"):
                    sock.append("%s%s" % (name, " (lecture seule)" if not m.get("RW", True) else ""))
                elif src in ("/", "/etc", "/root", "/boot", "/proc", "/sys", "/var/run", "/run", "/home", "/usr", "/var") and m.get("RW", True):
                    sens.append("%s : %s" % (name, src))
            if hc.get("NetworkMode") == "host" or hc.get("PidMode") == "host":
                hostns.append("%s (%s)" % (name, ", ".join(x for x, v in (("network host", hc.get("NetworkMode") == "host"), ("pid host", hc.get("PidMode") == "host")) if v)))
            dcaps = sorted(set(hc.get("CapAdd") or []) & {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_RAWIO",
                                                         "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"})
            if dcaps:
                caps.append("%s : %s" % (name, ", ".join(dcaps)))
            user = cfg.get("User") or "root"
            if user in ("root", "0", "0:0"):
                rootu.append(name)
            if not hc.get("Memory"):
                nomem.append(name)
            if (hc.get("RestartPolicy") or {}).get("Name", "no") in ("no", ""):
                norestart.append(name)
            health = ((c.get("State") or {}).get("Health") or {}).get("Status", "")
            if health == "unhealthy" or c.get("RestartCount", 0) > 5:
                unhealthy.append("%s (%s, %d redémarrages)" % (name, health or "sans healthcheck", c.get("RestartCount", 0)))
            ports = []
            for cport, binds in ((c.get("NetworkSettings") or {}).get("Ports") or {}).items():
                for b in binds or []:
                    pub = addr_scope(b.get("HostIp", "")) == "public"
                    ports.append("%s%s->%s" % ("" if pub else b.get("HostIp", "") + ":", b.get("HostPort"), cport))
                    if pub:
                        pubports.append("%s:%s" % (name, b.get("HostPort")))
            img_ids.append(c.get("Image", ""))
            rows.append([name, cfg.get("Image", ""), user, ", ".join(sorted(set(ports))) or "-",
                         (c.get("State") or {}).get("Status", "") + (" / " + health if health else "")])
        self.table("Conteneurs en cours d'exécution", ["Nom", "Image", "Utilisateur", "Ports publiés", "État"], rows)
        if not self.containers:
            self.info("Conteneurs", "Aucun conteneur en cours d'exécution.")
            return
        self.check("Docker : conteneurs privilégiés", not priv, HIGH,
                   ("Conteneurs : %s" % ", ".join(priv)) if priv else "Aucun conteneur en mode privilégié.",
                   "Un conteneur privilégié a un accès quasi complet à l'hôte. Donnez seulement les capacités nécessaires (cap_add).",
                   "# docker-compose.yml : retirer privileged: true")
        self.check("Docker : socket Docker monté", not sock, HIGH,
                   ("Conteneurs : %s" % ", ".join(sock)) if sock else "Aucun conteneur n'accède au socket Docker.",
                   "Accès au socket = root sur l'hôte. Si indispensable (Traefik, Portainer...), passez par un proxy de socket en lecture seule (tecnativa/docker-socket-proxy).",
                   "# exposer uniquement les API nécessaires via docker-socket-proxy")
        self.check("Docker : montages sensibles de l'hôte", not sens, HIGH,
                   ("Montages en écriture : %s" % "; ".join(sens)) if sens else "Aucun répertoire système de l'hôte monté en écriture.",
                   "Monter /, /etc ou /root en écriture permet de prendre le contrôle de l'hôte.", "- /etc/xxx:/etc/xxx:ro   # monter en lecture seule et au plus juste")
        self.check("Docker : espaces de noms de l'hôte", not hostns, MED,
                   ("Conteneurs : %s" % ", ".join(hostns)) if hostns else "Aucun conteneur en network/pid host.",
                   "Le mode host supprime l'isolation réseau/processus.", "# préférer un réseau bridge et publier les ports nécessaires")
        self.check("Docker : capacités Linux dangereuses", not caps, MED,
                   "; ".join(caps) if caps else "Aucune capacité dangereuse ajoutée.",
                   "Ces capacités facilitent l'évasion du conteneur.", "cap_drop: [ALL]\ncap_add: [<strict nécessaire>]")
        self.check("Docker : conteneurs exécutés en root", not rootu, LOW,
                   ("%d/%d conteneur(s) en root : %s" % (len(rootu), len(self.containers), shorten(rootu, 10))) if rootu else "Tous les conteneurs utilisent un utilisateur non-root.",
                   "Utilisez un utilisateur non privilégié quand l'image le permet.", "user: \"1000:1000\"   # docker-compose")
        self.check("Docker : limites de mémoire", not nomem, LOW,
                   ("%d conteneur(s) sans limite : %s" % (len(nomem), shorten(nomem, 10))) if nomem else "Tous les conteneurs ont une limite mémoire.",
                   "Un conteneur qui fuit peut saturer toute la RAM du serveur.", "deploy:\n  resources:\n    limits:\n      memory: 512M")
        self.check("Docker : politique de redémarrage", not norestart, LOW,
                   ("Sans politique : %s" % shorten(norestart, 10)) if norestart else "Tous les conteneurs redémarrent automatiquement.",
                   "Sans politique, le service reste arrêté après un crash ou un redémarrage du serveur.", "restart: unless-stopped")
        self.check("Docker : santé des conteneurs", not unhealthy, MED,
                   "; ".join(unhealthy) if unhealthy else "Aucun conteneur en mauvaise santé ni en boucle de redémarrage.",
                   "Analysez les journaux de ces conteneurs.", "docker logs --tail 100 <conteneur>")
        self.check("Docker : ports publiés sur toutes les interfaces", not pubports, MED,
                   ("Ports : %s. Docker insère ses propres règles iptables : ces ports sont joignables même si UFW les bloque." % shorten(pubports, 15)) if pubports
                   else "Aucun port publié publiquement (ou uniquement via 127.0.0.1).",
                   "Publiez sur 127.0.0.1 les services placés derrière un reverse proxy ; pour les autres, filtrez via la chaîne DOCKER-USER (ou ufw-docker).",
                   'ports:\n  - "127.0.0.1:8080:80"')
        old = []
        for iid in sorted(set(img_ids)):
            rc, o, _ = run(["docker", "image", "inspect", "--format", "{{.Created}}|{{join .RepoTags \",\"}}", iid], 20)
            if rc == 0 and "|" in o:
                created, tags = o.split("|", 1)
                try:
                    dt = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")
                    age = (utcnow() - dt).days
                    if age > 180:
                        old.append("%s (%d j)" % (tags or iid[7:19], age))
                except ValueError:
                    pass
        self.check("Docker : ancienneté des images", not old, LOW,
                   ("Images de plus de 6 mois : %s" % shorten(old, 10)) if old else "Toutes les images utilisées ont moins de 6 mois.",
                   "Les vieilles images contiennent des vulnérabilités corrigées depuis : reconstruisez/mettez à jour régulièrement.",
                   "docker compose pull && docker compose up -d\ndocker image prune")
        df = out(["docker", "system", "df"])
        self.text("Espace disque Docker", df)
        rec = sum(parse_size(m) for m in re.findall(r"([\d.]+\s*[KMGT]?B)\s+\(\d+%\)", df))
        if rec > 5 * 1024 ** 3:
            self.check("Docker : espace récupérable", False, LOW, "%s récupérables (images, volumes, cache inutilisés)." % human(rec),
                       "Nettoyez les ressources Docker inutilisées.", "docker system prune   # ajouter -a pour les images non utilisées")

    # ------------------------------------------------------------------ sauvegardes
    def audit_backups(self):
        tools = [t for t in BACKUP_TOOLS if has(t)]
        text = "\n".join(" ".join(r) for r in getattr(self, "cron_rows", [])) + "\n" + \
               "\n".join(" ".join(t) for t in getattr(self, "timers", []))
        text = re.sub(r"\S*dpkg-db-backup\S*", "", text)
        hits = sorted(set(m.lower() for m in re.findall(
            r"\b(restic|borg\w*|duplicity|rsnapshot|rclone|mysqldump|mariadb-dump|pg_dump\w*|mongodump|kopia|autorestic|backup\w*|sauvegarde\w*)\b", text, re.I)))
        imgs = [(c.get("Config") or {}).get("Image", "") for c in self.containers
                if re.search(r"backup|restic|borg|duplicati|kopia|rclone", (c.get("Config") or {}).get("Image", ""), re.I)]
        if tools or hits or imgs:
            parts = []
            if tools:
                parts.append("outils : %s" % ", ".join(tools))
            if hits:
                parts.append("tâches planifiées mentionnant : %s" % ", ".join(hits))
            if imgs:
                parts.append("conteneurs : %s" % ", ".join(imgs))
            self.check("Sauvegardes", True, HIGH, "Mécanisme de sauvegarde détecté (%s)." % "; ".join(parts))
            self.info("Sauvegardes : à vérifier manuellement",
                      "Le script ne peut pas valider la restauration. Vérifiez : copie hors du serveur, chiffrement, rétention, et test de restauration régulier.")
        else:
            self.check("Sauvegardes", False, HIGH,
                       "Aucun outil ni tâche planifiée de sauvegarde détecté sur le serveur.",
                       "Mettez en place des sauvegardes automatiques, chiffrées et externalisées (règle 3-2-1) : fichiers, volumes Docker et dumps de bases. "
                       "Les snapshots de l'hébergeur ne sont pas visibles d'ici : s'ils existent, vérifiez leur fréquence.",
                       "sudo apt install -y restic\nrestic -r sftp:user@backup-host:/srv/restic init\nrestic -r ... backup /etc /home /srv /var/lib/docker/volumes")

    # ------------------------------------------------------------------ supervision
    def audit_monitoring(self):
        found = sorted(set(label for unit, label in MONITORING if svc_active(unit)))
        imgs = " ".join((c.get("Config") or {}).get("Image", "") for c in self.containers).lower()
        for k, label in (("netdata", "Netdata"), ("node-exporter", "node_exporter"), ("uptime-kuma", "Uptime Kuma"),
                         ("prometheus", "Prometheus"), ("grafana", "Grafana"), ("zabbix", "Zabbix"), ("beszel", "Beszel"),
                         ("cadvisor", "cAdvisor"), ("glances", "Glances"), ("gatus", "Gatus")):
            if k in imgs:
                found.append("%s (Docker)" % label)
        self.check("Supervision / alertes", bool(found), LOW,
                   ("Outils détectés : %s." % ", ".join(sorted(set(found)))) if found else "Aucun agent de supervision détecté.",
                   "Sans supervision, une panne, un disque plein ou une compromission passent inaperçus. "
                   "Ajoutez au moins une surveillance externe de disponibilité (Uptime Kuma, UptimeRobot...) et des alertes disque/CPU.",
                   "# exemple léger : Netdata\nwget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh && sh /tmp/netdata-kickstart.sh")

    # ------------------------------------------------------------------ messagerie
    def audit_mail(self):
        if has("postconf"):
            inet = out(["postconf", "-h", "inet_interfaces"])
            mynet = out(["postconf", "-h", "mynetworks"])
            exp = self.exposed(25, 465, 587)
            self.check("Postfix : relais ouvert", not re.search(r"0\.0\.0\.0/0|::/0|\[::\]/0", mynet), CRIT,
                       "mynetworks = %s." % mynet,
                       "Un relais ouvert sera utilisé pour envoyer du spam : votre IP sera blacklistée.",
                       "sudo postconf -e 'mynetworks = 127.0.0.0/8 [::1]/128' && sudo systemctl reload postfix")
            if exp and inet == "all":
                self.check("Postfix : exposition", False, MED, "Postfix écoute publiquement (inet_interfaces = all).",
                           "Si le serveur n'est pas un serveur de messagerie et n'envoie que des notifications, écoutez seulement en local.",
                           "sudo postconf -e 'inet_interfaces = loopback-only' && sudo systemctl restart postfix")
            else:
                self.check("Postfix : exposition", True, MED, "inet_interfaces = %s." % inet)
        elif os.path.exists("/etc/exim4/update-exim4.conf.conf"):
            c = read("/etc/exim4/update-exim4.conf.conf") or ""
            li = re.search(r"dc_local_interfaces='([^']*)'", c)
            local = li and all(x.strip() in ("127.0.0.1", "::1") for x in li.group(1).split(";") if x.strip())
            self.check("Exim : exposition", bool(local), MED, "dc_local_interfaces = %s." % (li.group(1) if li else "toutes"),
                       "Limitez Exim à l'interface locale s'il ne reçoit pas de courrier.", "sudo dpkg-reconfigure exim4-config")
        else:
            self.info("Messagerie", "Aucun serveur de messagerie (Postfix/Exim) détecté.")

    # ------------------------------------------------------------------ réseau
    def audit_network(self):
        self.text("Interfaces réseau", out(["ip", "-br", "addr"]))
        self.text("Table de routage", out(["ip", "route"]) + "\n" + out(["ip", "-6", "route"]))
        dns = out(["resolvectl", "dns"]) or "\n".join(l for l in (read("/etc/resolv.conf") or "").splitlines() if l.startswith("nameserver"))
        self.text("Résolveurs DNS", dns)
        promisc = [l.split(":")[1].strip() for l in out(["ip", "-o", "link"]).splitlines()
                   if "PROMISC" in l and not re.search(r": (veth|docker|br-|cni|flannel|virbr)", l)]
        self.check("Interfaces en mode promiscuous", not promisc, MED,
                   ("Interfaces : %s" % ", ".join(promisc)) if promisc else "Aucune interface physique en écoute de tout le trafic.",
                   "Le mode promiscuous permet de capturer le trafic : vérifiez qu'un outil légitime (tcpdump, IDS) en est la cause.",
                   "ip link set <interface> promisc off")
        hosts = [l for l in (read("/etc/hosts") or "").splitlines() if l.strip() and not l.startswith("#")]
        self.text("/etc/hosts", "\n".join(hosts))

    # ------------------------------------------------------------------ synthèse
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
        return ("Le serveur présente %s. Ces points exposent directement l'infrastructure à une compromission "
                "et doivent être traités en priorité absolue, avant toute autre amélioration." % plural(counts[CRIT], "problème critique", "problèmes critiques"))
    if counts[HIGH]:
        return ("Aucun problème critique, mais %s à corriger rapidement. La base est %s ; traitez les points élevés "
                "puis les points moyens pour durcir le serveur." % (plural(counts[HIGH], "point de sévérité élevée", "points de sévérité élevée"),
                                                                     "saine" if score >= 70 else "à consolider"))
    if counts[MED]:
        return "Bon niveau général. Il reste %s pour atteindre un niveau de durcissement solide." % plural(counts[MED], "point moyen", "points moyens")
    return "Excellent niveau : seules des améliorations mineures sont suggérées. Maintenez les mises à jour et vérifiez régulièrement vos sauvegardes."


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
    from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame, KeepTogether, NextPageTemplate, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table, TableStyle)

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
        if not unicode_ok:
            s = s.encode("cp1252", "replace").decode("cp1252")
        return s

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

    score = a.global_score()
    grade = grade_of(score)
    counts = a.counts()
    date_str = a.now.strftime("%d/%m/%Y %H:%M")

    def on_page(c, doc):
        c.saveState()
        w, h = A4
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
        c.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
        c.setFont(F, 7.5)
        c.setFillColor(GRAY)
        c.drawString(18 * mm, h - 11.5 * mm, clean("Audit VPS - %s" % a.hostname))
        c.drawRightString(w - 18 * mm, h - 11.5 * mm, date_str)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : contient des informations sensibles sur l'infrastructure"))
        c.drawRightString(w - 18 * mm, 9.5 * mm, "Page %d" % doc.page)
        c.restoreState()

    def on_cover(c, doc):
        c.saveState()
        w, h = A4
        c.setFillColor(DARK)
        c.rect(0, h - 72 * mm, w, 72 * mm, fill=1, stroke=0)
        c.setFillColor(C("#3B82F6"))
        c.rect(0, h - 73.5 * mm, w, 1.5 * mm, fill=1, stroke=0)
        c.setFillColor(colors.white)
        c.setFont(FB, 27)
        c.drawString(18 * mm, h - 32 * mm, clean("Rapport d'audit VPS"))
        c.setFont(F, 14)
        c.drawString(18 * mm, h - 43 * mm, clean(a.hostname))
        c.setFont(F, 9.5)
        c.setFillColor(C("#CBD5E1"))
        c.drawString(18 * mm, h - 52 * mm, clean("%s  |  Généré le %s  |  Durée de l'analyse : %ds" % (a.facts.get("Système", ""), date_str, a.duration)))
        c.drawString(18 * mm, h - 59 * mm, clean("Sécurité, configuration et santé de l'infrastructure  |  audit_vps.py v%s" % VERSION))
        c.setFont(F, 7.5)
        c.setFillColor(GRAY)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : contient des informations sensibles sur l'infrastructure"))
        c.restoreState()

    def gauge(value, color):
        d = Drawing(46 * mm, 46 * mm)
        cx = cy = 23 * mm
        r = 22 * mm
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
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
              ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE)]
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

    # ---- couverture
    gcolor = score_color(score)
    grade_block = [P("<font size=9 color='#6B7280'>NOTE GLOBALE</font>", "body"),
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
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LINEAFTER", (0, 0), (-2, -1), 2, colors.white)]))
    story.append(Spacer(1, 7 * mm))
    story.append(P("Fiche d'identité du serveur", "h2"))
    facts = [[P(t(k), "cellb"), P(t(v))] for k, v in a.facts.items()]
    story.append(grid(facts, [45 * mm, W - 45 * mm], header=False))
    if not unicode_ok:
        story.append(Spacer(1, 3 * mm))
        story.append(P("Police DejaVu absente : certains caractères spéciaux peuvent être remplacés (sudo apt install fonts-dejavu-core).", "small"))
    story.append(PageBreak())

    # ---- synthèse
    story.append(P("Synthèse par domaine", "h1"))
    story.append(P(t("Score de chaque domaine : part des contrôles réussis, pondérée par leur sévérité "
                     "(critique 10, élevé 6, moyen 3, faible 1)."), "small"))
    story.append(Spacer(1, 3 * mm))
    data = [[P(h, "cellh") for h in ("Domaine", "Score", "", "Crit.", "Élevé", "Moyen", "Faible", "OK")]]
    extra = []
    for i, (cat, fs) in enumerate(a.categories().items(), 1):
        s = a.score(fs)
        c = a.counts(fs)
        row = [P(t(cat), "cellb"), P("<b>%s</b>" % ("-" if s is None else "%d %%" % s)), bar(s or 0)]
        for j, sev in enumerate((CRIT, HIGH, MED, LOW, OK)):
            row.append(P("<font color='%s'><b>%d</b></font>" % (SEV_COLOR[sev], c[sev]) if c[sev] else "<font color='#D1D5DB'>0</font>"))
        data.append(row)
    story.append(grid(data, [50 * mm, 14 * mm, 42 * mm] + [(W - 106 * mm) / 5.0] * 5, extra=extra + [("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))

    acts = a.actions()
    story.append(Spacer(1, 6 * mm))
    story.append(P("Les 15 actions prioritaires", "h2"))
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

    # ---- plan d'action détaillé
    story.append(P("Ce qu'il faut changer : plan d'action détaillé", "h1"))
    story.append(P(t("Classé par sévérité. Testez chaque correctif sur une session SSH ouverte en parallèle avant de fermer la vôtre, "
                     "en particulier pour SSH et le pare-feu."), "small"))
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

    # ---- points conformes
    story.append(P("Ce qui est déjà bien : points conformes", "h1"))
    oks = [f for f in a.findings if f["status"] == OK]
    story.append(P(t("%s réussi(s) sur %d évalué(s)." % (plural(len(oks), "contrôle"), len([f for f in a.findings if f["status"] != INFO]))), "small"))
    story.append(Spacer(1, 3 * mm))
    if oks:
        data = [[P(h, "cellh") for h in ("Domaine", "Contrôle", "Constat")]]
        for f in oks:
            data.append([P(t(f["cat"])), P("<font color='#15803D'><b>OK</b></font>  " + t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [36 * mm, 58 * mm, W - 94 * mm]))

    infos = [f for f in a.findings if f["status"] == INFO]
    if infos:
        story.append(CondPageBreak(40 * mm))
        story.append(Spacer(1, 6 * mm))
        story.append(P("Informations complémentaires", "h1"))
        story.append(P("Éléments relevés à titre informatif, sans impact sur le score.", "small"))
        story.append(Spacer(1, 3 * mm))
        data = [[P(h, "cellh") for h in ("Domaine", "Élément", "Détail")]]
        for f in infos:
            data.append([P(t(f["cat"])), P(t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [36 * mm, 50 * mm, W - 86 * mm]))
    story.append(PageBreak())

    # ---- annexes
    story.append(P("Annexes : inventaire de l'infrastructure", "h1"))
    current = None
    for inv in a.inventory:
        if inv["cat"] != current:
            current = inv["cat"]
            story.append(CondPageBreak(30 * mm))
            story.append(Paragraph(t(current), ParagraphStyle("cat", parent=S["h2"], fontSize=11, textColor=GRAY, spaceBefore=12)))
        story.append(CondPageBreak(25 * mm))
        story.append(P("<b>%s</b>" % t(inv["title"]), "body"))
        story.append(Spacer(1, 1.5 * mm))
        if "text" in inv:
            lines = inv["text"].splitlines()
            txt = "\n".join(lines[:150]) + ("\n... (%d lignes supplémentaires)" % (len(lines) - 150) if len(lines) > 150 else "")
            story.append(Table([[P(tm(txt), "mono")]], colWidths=[W],
                               style=[("BACKGROUND", (0, 0), (-1, -1), C("#F3F4F6")), ("LEFTPADDING", (0, 0), (-1, -1), 5),
                                      ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
        else:
            hdr, rows = inv["headers"], inv["rows"][:250]
            lens = []
            for i, h in enumerate(hdr):
                m = max([len(h)] + [min(len(r[i]) if i < len(r) else 0, 70) for r in rows])
                lens.append(max(m, 4))
            widths = [W * l / float(sum(lens)) for l in lens]
            data = [[P(t(h), "cellh") for h in hdr]] + [[P(t(r[i]) if i < len(r) else "") for i in range(len(hdr))] for r in rows]
            story.append(grid(data, widths))
            if len(inv["rows"]) > 250:
                story.append(P("... %d lignes supplémentaires non affichées." % (len(inv["rows"]) - 250), "small"))
        if inv.get("note"):
            story.append(P(t(inv["note"]), "small"))
        story.append(Spacer(1, 4 * mm))

    # ---- méthodologie
    story.append(PageBreak())
    story.append(P("Méthodologie et limites", "h1"))
    for para in (
        "Cet audit est réalisé depuis le serveur lui-même par le script audit_vps.py, en lecture seule. Chaque contrôle reçoit une "
        "sévérité : CRITIQUE (exploitable immédiatement ou compromission probable), ÉLEVÉ (risque important à corriger rapidement), "
        "MOYEN (durcissement recommandé), FAIBLE (bonne pratique). Les éléments INFO ne comptent pas dans le score.",
        "Le score global est la part des contrôles réussis pondérée par leur sévérité (10, 6, 3, 1). Il est plafonné à 50 en présence "
        "d'un point critique et à 80 en présence d'un point élevé : un seul problème grave suffit à compromettre un serveur.",
        "Limites : le pare-feu et les snapshots de l'hébergeur ne sont pas visibles depuis le serveur ; la restauration des sauvegardes "
        "n'est pas testée ; les applications web elles-mêmes (code, CMS, dépendances) ne sont pas auditées ; les conteneurs sont analysés "
        "par leur configuration, pas par un scan de vulnérabilités des images. Pour aller plus loin : Lynis (audit système), Trivy "
        "(vulnérabilités des images Docker), testssl.sh ou SSL Labs (TLS vu de l'extérieur), et un scan nmap depuis une autre machine "
        "pour confirmer les ports réellement joignables.",
        "Bonne pratique : relancez cet audit après chaque correction et au moins une fois par mois (tâche cron), et conservez les rapports "
        "pour suivre l'évolution du score.",
    ):
        story.append(P(t(para), "lead"))
        story.append(Spacer(1, 3 * mm))

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
                          title="Rapport d'audit VPS - %s" % a.hostname, author="audit_vps.py", subject="Audit de sécurité")
    cover_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 72 * mm - 30 * mm, id="cover", leftPadding=0, rightPadding=0)
    page_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 40 * mm, id="page", leftPadding=0, rightPadding=0)
    doc.addPageTemplates([PageTemplate(id="cover", frames=[cover_frame], onPage=on_cover),
                          PageTemplate(id="page", frames=[page_frame], onPage=on_page)])
    doc.build(story)


# --------------------------------------------------------------------------- HTML (repli sans reportlab)

def build_html(a, path):
    e = lambda s: escape(str(s)).replace("\n", "<br>")  # noqa: E731
    score, counts = a.global_score(), a.counts()
    h = ["<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>Audit VPS - %s</title><style>"
         "body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#111827}"
         "h1{margin-bottom:0}h2{border-bottom:2px solid #e5e7eb;padding-bottom:4px;margin-top:32px}"
         "table{border-collapse:collapse;width:100%%;font-size:13px;margin:8px 0}td,th{border-bottom:1px solid #e5e7eb;padding:5px;text-align:left;vertical-align:top}"
         "th{background:#111827;color:#fff}.b{color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold;white-space:nowrap}"
         "pre{background:#f3f4f6;padding:8px;white-space:pre-wrap;font-size:12px}.card{border:1px solid #e5e7eb;border-left:5px solid;padding:8px 12px;margin:10px 0}"
         "@media print{h2{page-break-before:always}.card{page-break-inside:avoid}}</style></head><body>" % e(a.hostname)]
    h.append("<h1>Rapport d'audit VPS : %s</h1><p>%s, %s</p>" % (e(a.hostname), e(a.facts.get("Système", "")), a.now.strftime("%d/%m/%Y %H:%M")))
    h.append("<p style='font-size:28px'><b style='color:%s'>%d/100 (note %s)</b></p><p>%s</p>" % (score_color(score), score, grade_of(score), e(verdict(score, counts))))
    h.append("<p>" + " ".join("<span class='b' style='background:%s'>%s : %d</span>" % (SEV_COLOR[s], SEV_LABEL[s], counts[s]) for s in (CRIT, HIGH, MED, LOW, OK)) + "</p>")
    h.append("<table>" + "".join("<tr><th style='width:30%%'>%s</th><td>%s</td></tr>" % (e(k), e(v)) for k, v in a.facts.items()) + "</table>")
    h.append("<h2>Ce qu'il faut changer</h2>")
    for i, f in enumerate(a.actions(), 1):
        h.append("<div class='card' style='border-left-color:%s'><span class='b' style='background:%s'>%s</span> <b>%d. %s</b> <small>(%s)</small>"
                 % (SEV_COLOR[f["status"]], SEV_COLOR[f["status"]], SEV_LABEL[f["status"]], i, e(f["title"]), e(f["cat"])))
        h.append("<p><b>Constat :</b> %s</p><p><b>Recommandation :</b> %s</p>" % (e(f["detail"]), e(f["reco"])))
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
        if "text" in inv:
            h.append("<pre>%s</pre>" % escape(inv["text"]))
        else:
            h.append("<table><tr>%s</tr>%s</table>" % ("".join("<th>%s</th>" % e(x) for x in inv["headers"]),
                                                        "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % e(c) for c in r) for r in inv["rows"])))
    h.append("</body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(h))


# --------------------------------------------------------------------------- main

def ensure_reportlab(args):
    try:
        import reportlab  # noqa: F401
        return True
    except ImportError:
        pass
    if os.geteuid() != 0:
        log("[!] python3-reportlab absent et pas de droits root pour l'installer : un rapport HTML sera produit.", "yellow")
        return False
    want = args.install_deps
    if not want and sys.stdin.isatty():
        try:
            ans = input("Le paquet python3-reportlab (génération du PDF) est absent. L'installer via apt ? [O/n] ")
        except EOFError:
            ans = "n"
        want = ans.strip().lower() in ("", "o", "oui", "y", "yes")
    if not want:
        log("[!] Sans reportlab, le rapport sera produit en HTML (imprimable en PDF depuis un navigateur).", "yellow")
        return False
    log("[*] Installation de python3-reportlab et fonts-dejavu-core...", "blue")
    run(["apt-get", "update", "-qq"], 300)
    rc, _, err = run(["apt-get", "install", "-y", "-qq", "python3-reportlab", "fonts-dejavu-core"], 600)
    if rc != 0:
        log("[!] Échec de l'installation : %s" % err[-300:], "red")
        return False
    import importlib
    importlib.invalidate_caches()
    try:
        import reportlab  # noqa: F401,F811
        return True
    except ImportError:
        log("[!] reportlab installé mais introuvable par cet interpréteur Python (%s). Utilisez /usr/bin/python3." % sys.executable, "red")
        return False


def main():
    p = argparse.ArgumentParser(description="Audit complet de sécurité et de santé d'un VPS Ubuntu, avec rapport PDF.")
    p.add_argument("-o", "--output", help="chemin du rapport (défaut : ./audit-<hôte>-<date>.pdf)")
    p.add_argument("--quick", action="store_true", help="ne pas scanner tout le disque (plus rapide)")
    p.add_argument("--no-apt-update", action="store_true", help="ne pas lancer apt-get update avant de vérifier les mises à jour")
    p.add_argument("--install-deps", action="store_true", help="installer python3-reportlab sans demander s'il est absent")
    p.add_argument("--domain", action="append", metavar="DOMAINE", help="domaine supplémentaire à tester en HTTPS (répétable)")
    p.add_argument("--json", action="store_true", help="exporter aussi les résultats bruts en JSON")
    p.add_argument("--version", action="version", version="audit_vps.py " + VERSION)
    args = p.parse_args()

    if not sys.platform.startswith("linux"):
        sys.exit("Ce script doit être exécuté sur le serveur Linux (Ubuntu) à auditer.")
    if os.geteuid() != 0:
        log("[!] Exécution sans root : l'audit sera incomplet. Relancez avec : sudo python3 %s" % sys.argv[0], "yellow")

    pdf_ok = ensure_reportlab(args)
    a = Audit(args)
    log("[*] Audit de %s (%s)" % (a.hostname, a.now.strftime("%d/%m/%Y %H:%M")), "bold")
    a.run_all()

    base = args.output or os.path.join(os.getcwd(), "audit-%s-%s.pdf" % (a.hostname, a.now.strftime("%Y%m%d-%H%M")))
    if not pdf_ok:
        base = os.path.splitext(base)[0] + ".html"
    outputs = []
    try:
        if pdf_ok:
            build_pdf(a, base)
        else:
            build_html(a, base)
        outputs.append(base)
    except Exception as e:  # noqa: BLE001
        log("[!] Échec de la génération du PDF (%s) : rapport HTML de secours." % e, "red")
        base = os.path.splitext(base)[0] + ".html"
        build_html(a, base)
        outputs.append(base)
    if args.json:
        jp = os.path.splitext(base)[0] + ".json"
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(dict(host=a.hostname, date=a.now.isoformat(), version=VERSION, score=a.global_score(),
                           grade=grade_of(a.global_score()), facts=a.facts, findings=a.findings, inventory=a.inventory),
                      f, ensure_ascii=False, indent=2)
        outputs.append(jp)
    for o in outputs:
        try:
            os.chmod(o, 0o600)
            if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
                os.chown(o, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
        except OSError:
            pass

    score, counts = a.global_score(), a.counts()
    col = "green" if score >= 80 else "yellow" if score >= 55 else "red"
    log("")
    log("Score global : %d/100 (note %s)" % (score, grade_of(score)), col)
    log("Critiques : %d | Élevés : %d | Moyens : %d | Faibles : %d | Conformes : %d"
        % (counts[CRIT], counts[HIGH], counts[MED], counts[LOW], counts[OK]))
    for f in a.actions()[:5]:
        log("  - [%s] %s" % (SEV_LABEL[f["status"]], f["title"]), "red" if f["status"] in (CRIT, HIGH) else "yellow")
    for o in outputs:
        log("Rapport : %s" % o, "bold")


if __name__ == "__main__":
    main()
