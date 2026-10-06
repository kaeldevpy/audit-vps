#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit_docker.py - Audit des vulnérabilités des images Docker, via Trivy.

Complément des audits interne et externe : ceux-ci regardent la configuration des conteneurs
et ce qui est exposé, mais pas les failles connues (CVE) contenues dans les images elles-mêmes.
Ce script scanne chaque image avec Trivy et produit un rapport PDF : combien de vulnérabilités
par image, lesquelles sont corrigeables, quelles images mettre à jour en priorité.

  Par défaut, il scanne les images des conteneurs EN COURS D'EXÉCUTION.
  Vous pouvez aussi passer des images précises en argument.

Usage :
    python3 audit_docker.py                      # images des conteneurs qui tournent
    python3 audit_docker.py --all                # + conteneurs arrêtés
    python3 audit_docker.py nginx:1.25 redis:7   # images précises
    python3 audit_docker.py --secrets            # chercher aussi des secrets dans les images
    python3 audit_docker.py -o rapport.pdf --json

Le script est en lecture seule : il analyse les images, il ne modifie ni les conteneurs ni le système.

Dépendances :
  - Trivy (https://trivy.dev). S'il est absent mais que Docker est présent, le script l'utilise
    automatiquement via l'image officielle « aquasec/trivy » (aucune installation).
  - python3-reportlab (optionnel) pour le PDF ; sinon un rapport HTML est produit.
Trivy télécharge sa base de vulnérabilités au premier lancement (connexion Internet requise).
"""

import argparse
import datetime
import json
import os
import re
import shutil
import socket
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
TRIVY_SEV = {"CRITICAL": CRIT, "HIGH": HIGH, "MEDIUM": MED, "LOW": LOW}


def log(msg, color=None):
    codes = {"blue": "34", "green": "32", "yellow": "33", "red": "31", "gray": "90", "bold": "1"}
    if color and sys.stderr.isatty():
        msg = "\033[%sm%s\033[0m" % (codes[color], msg)
    print(msg, file=sys.stderr, flush=True)


def run(cmd, timeout=900):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return (p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
    except FileNotFoundError:
        return 127, "", "commande introuvable"
    except subprocess.TimeoutExpired:
        return 124, "", "délai dépassé"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def has(cmd):
    return shutil.which(cmd) is not None


def plural(n, word, word_pl=None):
    return "%d %s" % (n, word if n <= 1 else (word_pl or word + "s"))


def shorten(items, n=12, sep=", "):
    items = list(items)
    s = sep.join(str(i) for i in items[:n])
    if len(items) > n:
        s += "%s... (+%d)" % (sep, len(items) - n)
    return s


def short_image(ref):
    """Raccourcit une référence d'image pour l'affichage (retire le digest, garde nom:tag)."""
    ref = ref.split("@", 1)[0]
    return ref if len(ref) <= 48 else "..." + ref[-45:]


# --------------------------------------------------------------------------- Trivy

class Trivy:
    """Pilote Trivy, soit en binaire local, soit via le conteneur officiel aquasec/trivy."""

    def __init__(self, args):
        self.args = args
        self.mode = None       # "binaire" | "docker" | None
        self.version = "?"
        self.cache_vol = "trivy-cache-audit"

    def detect(self):
        if has("trivy"):
            rc, o, _ = run(["trivy", "--version"], 30)
            if rc == 0:
                self.mode = "binaire"
                m = re.search(r"Version:\s*(\S+)", o)
                self.version = m.group(1) if m else o.splitlines()[0].strip() if o else "?"
                return True
        if has("docker"):
            rc, _, _ = run(["docker", "info"], 30)
            if rc == 0:
                self.mode = "docker"
                self.version = "via conteneur aquasec/trivy"
                return True
        return False

    def _base_cmd(self):
        if self.mode == "binaire":
            return ["trivy"]
        # Via Docker : accès au démon pour voir les images locales + cache persistant.
        return ["docker", "run", "--rm",
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", "%s:/root/.cache/" % self.cache_vol,
                "aquasec/trivy"]

    def update_db(self):
        log("    mise à jour de la base de vulnérabilités Trivy...", "gray")
        run(self._base_cmd() + ["image", "--download-db-only"], 600)

    def scan(self, image):
        """Scanne une image, renvoie le JSON Trivy (dict) ou None."""
        scanners = "vuln,secret" if self.args.secrets else "vuln"
        common = ["image", "--quiet", "--format", "json", "--timeout", "%dm" % self.args.timeout,
                  "--severity", "CRITICAL,HIGH,MEDIUM,LOW"]
        for flag in (["--scanners", scanners], ["--security-checks", scanners]):
            rc, o, e = run(self._base_cmd() + common + flag + [image], self.args.timeout * 60 + 60)
            if rc == 0 and o.strip():
                try:
                    return json.loads(o)
                except ValueError:
                    pass
            if "unknown flag" not in e and "flag provided" not in e:
                if rc != 0:
                    log("    Trivy a échoué sur %s : %s" % (image, (e.strip().splitlines() or [""])[-1][:160]), "yellow")
                break
        return None


# --------------------------------------------------------------------------- audit

class DockerAudit:
    def __init__(self, args, trivy):
        self.args = args
        self.trivy = trivy
        self.findings = []
        self.inventory = []
        self.facts = OrderedDict()
        self.cat = "Général"
        self.now = datetime.datetime.now()
        self.started = time.time()
        self.hostname = socket.gethostname()
        self.target = "Images Docker de %s" % self.hostname
        self.images = []        # [(ref, [noms de conteneurs])]
        self.duration = 0

    def check(self, title, ok, sev, detail="", reco="", fix=""):
        self.findings.append(dict(cat=self.cat, title=title, status=OK if ok else sev, sev=sev,
                                  detail=detail, reco="" if ok else reco, fix="" if ok else fix))

    def info(self, title, detail):
        self.findings.append(dict(cat=self.cat, title=title, status=INFO, sev=INFO, detail=detail, reco="", fix=""))

    def table(self, title, headers, rows, note=""):
        if rows:
            self.inventory.append(dict(cat=self.cat, title=title, headers=headers,
                                       rows=[[str(c) for c in r] for r in rows], note=note))

    # ---- collecte des images à scanner
    def collect_images(self):
        if self.args.images:
            self.images = [(ref, []) for ref in self.args.images]
            self.facts["Source des images"] = "images fournies en argument"
            return True
        if not has("docker"):
            log("[!] Docker n'est pas installé et aucune image n'a été fournie en argument.", "red")
            return False
        rc, o, _ = run(["docker", "ps"] + (["-a"] if self.args.all else []) +
                       ["--format", "{{.Image}}\t{{.Names}}"], 60)
        if rc != 0:
            log("[!] Impossible de lister les conteneurs (démon Docker inaccessible ?).", "red")
            return False
        per_image = OrderedDict()
        for line in o.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                image, names = parts[0], parts[1]
                per_image.setdefault(image, []).append(names)
        self.images = list(per_image.items())
        self.facts["Source des images"] = "conteneurs %s" % ("(tous)" if self.args.all else "en cours d'exécution")
        if not self.images:
            self.info("Conteneurs", "Aucun conteneur %s trouvé." % ("" if self.args.all else "en cours d'exécution"))
        return True

    def run_all(self):
        self.facts["Hôte"] = self.hostname
        self.facts["Trivy"] = "%s (%s)" % (self.trivy.version, self.trivy.mode)
        self.facts["Date de l'audit"] = self.now.strftime("%d/%m/%Y %H:%M")
        if not self.collect_images():
            return
        self.facts["Images analysées"] = str(len(self.images))
        if not self.images:
            self.duration = time.time() - self.started
            return
        if not self.args.no_db_update:
            self.trivy.update_db()
        total = Counter()
        rows_overview = []
        for i, (ref, containers) in enumerate(self.images, 1):
            log("[*] (%d/%d) scan de %s..." % (i, len(self.images), ref), "blue")
            data = self.trivy.scan(ref)
            counts, fixable, cves, secrets, osinfo = self._parse(data) if data else (Counter(), Counter(), [], [], "")
            total.update(counts)
            self._emit_image(ref, containers, counts, fixable, cves, secrets, osinfo, data is not None)
            rows_overview.append([short_image(ref), ", ".join(containers) or "(image seule)", osinfo,
                                  counts[CRIT], counts[HIGH], counts[MED], counts[LOW]])
        self.cat = "Synthèse"
        self.table("Vue d'ensemble des images", ["Image", "Conteneur(s)", "Base", "Crit.", "Élevé", "Moyen", "Faible"], rows_overview)
        self.facts["Vulnérabilités (total)"] = "%d critiques, %d élevées, %d moyennes, %d faibles" % (
            total[CRIT], total[HIGH], total[MED], total[LOW])
        self.duration = time.time() - self.started

    def _parse(self, data):
        counts, fixable = Counter(), Counter()
        cves, secrets = [], []
        seen = set()
        for r in data.get("Results", []) or []:
            for v in r.get("Vulnerabilities", []) or []:
                sev = TRIVY_SEV.get((v.get("Severity") or "").upper())
                if not sev:
                    continue
                key = (v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"))
                if key in seen:
                    continue
                seen.add(key)
                counts[sev] += 1
                fix = v.get("FixedVersion") or ""
                if fix:
                    fixable[sev] += 1
                cves.append(dict(id=v.get("VulnerabilityID", "?"), pkg=v.get("PkgName", "?"),
                                 installed=v.get("InstalledVersion", ""), fixed=fix, sev=sev,
                                 title=(v.get("Title") or v.get("Description") or "")[:80]))
            for s in r.get("Secrets", []) or []:
                secrets.append(dict(rule=s.get("RuleID", "?"), title=s.get("Title", ""),
                                    target=r.get("Target", ""), line=s.get("StartLine", "")))
        osfam = (data.get("Metadata", {}) or {}).get("OS", {}) or {}
        osinfo = "%s %s" % (osfam.get("Family", ""), osfam.get("Name", "")) if osfam else ""
        cves.sort(key=lambda c: (SEV_RANK[c["sev"]], not c["fixed"]))
        return counts, fixable, cves, secrets, osinfo.strip()

    def _emit_image(self, ref, containers, counts, fixable, cves, secrets, osinfo, scanned):
        self.cat = short_image(ref)
        ctx = (" (conteneur(s) : %s)" % ", ".join(containers)) if containers else ""
        if not scanned:
            self.check("Analyse de l'image", False, MED,
                       "Le scan Trivy de %s%s a échoué (image introuvable, réseau, ou délai dépassé)." % (ref, ctx),
                       "Vérifiez que l'image existe localement (docker images) et relancez.",
                       "docker pull %s   # puis relancer l'audit" % ref)
            return
        update_fix = ("# Mettre à jour l'image puis redémarrer le conteneur\n"
                      "docker pull %s\ndocker compose up -d   # ou : docker compose pull && docker compose up -d" % ref)
        for sev, plural_adj, sing_adj in ((CRIT, "critiques", "critique"), (HIGH, "élevées", "élevée"), (MED, "moyennes", "moyenne")):
            n, nf = counts[sev], fixable[sev]
            if n == 0:
                self.check("Vulnérabilités %s" % plural_adj, True, sev, "Aucune vulnérabilité %s dans %s%s." % (sing_adj, ref, ctx))
                continue
            ex = [c for c in cves if c["sev"] == sev][:4]
            ex_txt = " ; ".join("%s (%s)" % (c["id"], c["pkg"]) for c in ex)
            detail = "%d vulnérabilité%s %s dans %s%s, dont %d corrigeable%s par mise à jour. Ex. : %s." % (
                n, "s" if n > 1 else "", plural_adj if n > 1 else sing_adj, ref, ctx,
                nf, "s" if nf > 1 else "", ex_txt)
            reco = ("Mettez à jour cette image : %d de ces failles sont corrigées dans une version plus récente." % nf) if nf \
                else ("Aucune correction n'est encore disponible pour ces failles %s ; surveillez les mises à jour, "
                      "envisagez une autre image de base ou des mesures de limitation." % plural_adj)
            self.check("Vulnérabilités %s" % plural_adj, False, sev, detail, reco, update_fix if nf else "")
        if secrets:
            self.check("Secrets détectés dans l'image", False, CRIT,
                       "%d secret(s) potentiel(s) détecté(s) : %s." % (len(secrets), shorten(["%s (%s)" % (s["rule"], s["target"]) for s in secrets], 6)),
                       "Un secret (mot de passe, clé, jeton) intégré à l'image est exposé à quiconque y accède. "
                       "Retirez-le, invalidez-le, et passez les secrets par des variables d'environnement ou des volumes.",
                       "# ne jamais copier de secret dans une image ; utiliser des secrets d'exécution")
        elif self.args.secrets:
            self.check("Secrets dans l'image", True, HIGH, "Aucun secret détecté dans %s." % ref)
        if osinfo:
            self.info("Base de %s" % short_image(ref), "Système de base détecté : %s." % osinfo)
        if cves:
            rows = [[c["sev"].upper() if False else SEV_LABEL[c["sev"]], c["id"], c["pkg"], c["installed"],
                     c["fixed"] or "(aucune)", c["title"]] for c in cves[:40]]
            self.table("Vulnérabilités de %s" % short_image(ref),
                       ["Sévérité", "CVE", "Paquet", "Version", "Corrigé en", "Description"], rows,
                       ("%d vulnérabilités au total, 40 premières affichées." % len(cves)) if len(cves) > 40 else "")

    # ---- synthèse
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


def verdict(score, counts, n_images):
    if counts[CRIT]:
        return ("Les images présentent %s : des failles connues et exploitables sont embarquées. "
                "Mettez à jour en priorité les images concernées." % plural(counts[CRIT], "vulnérabilité critique", "vulnérabilités critiques"))
    if counts[HIGH]:
        return ("Aucune vulnérabilité critique, mais %s à corriger. La plupart se règlent en reconstruisant "
                "ou en mettant à jour les images concernées." % plural(counts[HIGH], "point de sévérité élevée", "points de sévérité élevée"))
    if counts[MED]:
        return "Bon état général des %d image(s). Il reste des vulnérabilités moyennes à traiter lors des prochaines mises à jour." % n_images
    return "Excellent : aucune vulnérabilité critique, élevée ou moyenne connue dans les images analysées. Maintenez les images à jour."


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

    def on_page(c, doc):
        c.saveState()
        w, h = A4
        c.setStrokeColor(LINE); c.setLineWidth(0.5)
        c.line(18 * mm, h - 14 * mm, w - 18 * mm, h - 14 * mm)
        c.line(18 * mm, 14 * mm, w - 18 * mm, 14 * mm)
        c.setFont(F, 7.5); c.setFillColor(GRAY)
        c.drawString(18 * mm, h - 11.5 * mm, clean("Audit Docker - %s" % a.hostname))
        c.drawRightString(w - 18 * mm, h - 11.5 * mm, date_str)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : vulnérabilités des images du serveur"))
        c.drawRightString(w - 18 * mm, 9.5 * mm, "Page %d" % doc.page)
        c.restoreState()

    def on_cover(c, doc):
        c.saveState()
        w, h = A4
        c.setFillColor(DARK); c.rect(0, h - 72 * mm, w, 72 * mm, fill=1, stroke=0)
        c.setFillColor(C("#3B82F6")); c.rect(0, h - 73.5 * mm, w, 1.5 * mm, fill=1, stroke=0)
        c.setFillColor(colors.white); c.setFont(FB, 26)
        c.drawString(18 * mm, h - 32 * mm, clean("Audit des images Docker"))
        c.setFont(F, 14); c.drawString(18 * mm, h - 43 * mm, clean(a.hostname))
        c.setFont(F, 9.5); c.setFillColor(C("#CBD5E1"))
        c.drawString(18 * mm, h - 52 * mm, clean("Vulnérabilités connues (CVE) des images  |  %s" % date_str))
        c.drawString(18 * mm, h - 59 * mm, clean("Analyse Trivy (lecture seule)  |  audit_docker.py v%s" % VERSION))
        c.setFont(F, 7.5); c.setFillColor(GRAY)
        c.drawString(18 * mm, 9.5 * mm, clean("Document confidentiel : vulnérabilités des images du serveur"))
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
    grade_block = [P("<font size=9 color='#6B7280'>SANTÉ DES IMAGES</font>", "body"),
                   Paragraph("<font size=40 color='%s'><b>%s</b></font>" % (gcolor, grade),
                             ParagraphStyle("g", fontName=FB, fontSize=40, leading=46)),
                   Spacer(1, 2 * mm), P(t(verdict(score, counts, len(a.images))), "body")]
    story.append(Table([[gauge(score, gcolor), grade_block]], colWidths=[52 * mm, W - 52 * mm],
                       style=[("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(Spacer(1, 6 * mm))
    cells, st = [], []
    for i, sev in enumerate((CRIT, HIGH, MED, LOW, OK)):
        cells.append([P(str(counts[sev]), "countn"), P(SEV_LABEL[sev], "count")])
        st.append(("BACKGROUND", (i, 0), (i, 0), C(SEV_COLOR[sev])))
    story.append(Table([cells], colWidths=[W / 5.0] * 5, style=st + [
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LINEAFTER", (0, 0), (-2, -1), 2, colors.white)]))
    story.append(Spacer(1, 2 * mm))
    story.append(P("Chaque case compte les <b>contrôles</b> (par image et par sévérité), pas le nombre total de CVE.", "small"))
    story.append(Spacer(1, 5 * mm))
    story.append(P("Contexte de l'audit", "h2"))
    story.append(grid([[P(t(k), "cellb"), P(t(v))] for k, v in a.facts.items()], [48 * mm, W - 48 * mm], header=False))
    if not unicode_ok:
        story.append(Spacer(1, 2 * mm))
        story.append(P("Police DejaVu absente : certains caractères peuvent être remplacés (sudo apt install fonts-dejavu-core).", "small"))
    story.append(PageBreak())

    story.append(P("Synthèse par image", "h1"))
    data = [[P(h, "cellh") for h in ("Image", "Score", "", "Crit.", "Élevé", "Moyen", "Faible", "OK")]]
    for cat, fs in a.categories().items():
        if cat in ("Synthèse", "Général"):
            continue
        s = a.score(fs); c = a.counts(fs)
        row = [P(t(cat), "cellb"), P("<b>%s</b>" % ("-" if s is None else "%d %%" % s)), bar(s or 0)]
        for sev in (CRIT, HIGH, MED, LOW, OK):
            row.append(P("<font color='%s'><b>%d</b></font>" % (SEV_COLOR[sev], c[sev]) if c[sev] else "<font color='#D1D5DB'>0</font>"))
        data.append(row)
    if len(data) > 1:
        story.append(grid(data, [50 * mm, 14 * mm, 42 * mm] + [(W - 106 * mm) / 5.0] * 5, extra=[("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    acts = a.actions()
    story.append(Spacer(1, 6 * mm))
    story.append(P("Actions prioritaires", "h2"))
    if acts:
        data = [[P(h, "cellh") for h in ("#", "Sévérité", "Image", "Point à corriger")]]
        extra = []
        for i, f in enumerate(acts[:15], 1):
            data.append([P(str(i)), P(SEV_LABEL[f["status"]], "badge"), P(t(f["cat"])), P(t(f["title"]), "cellb")])
            extra.append(("BACKGROUND", (1, i), (1, i), C(SEV_COLOR[f["status"]])))
        story.append(grid(data, [8 * mm, 20 * mm, 50 * mm, W - 78 * mm], zebra=False, extra=extra + [("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    else:
        story.append(P("Aucune action corrective nécessaire.", "body"))
    story.append(PageBreak())

    story.append(P("Ce qu'il faut corriger", "h1"))
    story.append(P("La plupart des vulnérabilités se corrigent en mettant à jour l'image (nouvelle version officielle "
                   "ou reconstruction à partir d'une base récente). Les « corrigeables » ont déjà un correctif disponible.", "small"))
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

    story.append(P("Ce qui est déjà bien", "h1"))
    oks = [f for f in a.findings if f["status"] == OK]
    if oks:
        data = [[P(h, "cellh") for h in ("Image", "Contrôle", "Constat")]]
        for f in oks:
            data.append([P(t(f["cat"])), P("<font color='#15803D'><b>OK</b></font>  " + t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [44 * mm, 44 * mm, W - 88 * mm]))
    else:
        story.append(P("Aucun contrôle entièrement conforme.", "body"))
    infos = [f for f in a.findings if f["status"] == INFO]
    if infos:
        story.append(Spacer(1, 6 * mm))
        story.append(P("Informations", "h1"))
        data = [[P(h, "cellh") for h in ("Image / domaine", "Élément", "Détail")]]
        for f in infos:
            data.append([P(t(f["cat"])), P(t(f["title"]), "cellb"), P(t(f["detail"]))])
        story.append(grid(data, [44 * mm, 44 * mm, W - 88 * mm]))
    story.append(PageBreak())

    story.append(P("Annexes : détail des vulnérabilités", "h1"))
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
        lens = [max([len(h)] + [min(len(r[i]) if i < len(r) else 0, 60) for r in rows]) for i, h in enumerate(hdr)]
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
        "Cet audit s'appuie sur Trivy (Aqua Security) pour détecter les vulnérabilités connues (CVE) des paquets système et "
        "des bibliothèques présents dans chaque image Docker. Il est en lecture seule : il analyse les images, sans modifier "
        "les conteneurs ni le système.",
        "Chaque case de la page de garde compte des contrôles (par image et par niveau de gravité), pas le nombre total de CVE : "
        "une image peut cumuler des centaines de CVE sous un seul contrôle « critique ». Le détail par CVE figure en annexe. Le "
        "score est la part des contrôles réussis pondérée par leur gravité, plafonné en présence de failles critiques ou élevées.",
        "Une vulnérabilité « corrigeable » dispose déjà d'une version corrigée : mettre à jour l'image (ou la reconstruire sur une "
        "base récente) la supprime. Les failles sans correctif disponible demandent une surveillance, un changement d'image de base, "
        "ou des mesures de limitation.",
        "Limites : l'analyse dépend de la fraîcheur de la base Trivy (mise à jour à chaque exécution par défaut) ; elle ne couvre pas "
        "les failles de votre propre code applicatif embarqué dans l'image, ni les erreurs de configuration à l'exécution (voir "
        "l'audit interne pour la configuration des conteneurs).",
    ):
        story.append(P(t(para), "lead")); story.append(Spacer(1, 3 * mm))

    doc = BaseDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=20 * mm,
                          title="Audit Docker - %s" % a.hostname, author="audit_docker.py", subject="Vulnérabilités des images Docker")
    cover_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 72 * mm - 30 * mm, id="cover", leftPadding=0, rightPadding=0)
    page_frame = Frame(18 * mm, 20 * mm, W, A4[1] - 40 * mm, id="page", leftPadding=0, rightPadding=0)
    doc.addPageTemplates([PageTemplate(id="cover", frames=[cover_frame], onPage=on_cover),
                          PageTemplate(id="page", frames=[page_frame], onPage=on_page)])
    doc.build(story)


def build_html(a, path):
    e = lambda s: escape(str(s)).replace("\n", "<br>")  # noqa: E731
    score, counts = a.global_score(), a.counts()
    h = ["<!doctype html><html lang='fr'><head><meta charset='utf-8'><title>Audit Docker - %s</title><style>"
         "body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#111827}"
         "h2{border-bottom:2px solid #e5e7eb;padding-bottom:4px;margin-top:32px}"
         "table{border-collapse:collapse;width:100%%;font-size:13px;margin:8px 0}td,th{border-bottom:1px solid #e5e7eb;padding:5px;text-align:left;vertical-align:top}"
         "th{background:#111827;color:#fff}.b{color:#fff;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold}"
         "pre{background:#f3f4f6;padding:8px;white-space:pre-wrap;font-size:12px}.card{border:1px solid #e5e7eb;border-left:5px solid;padding:8px 12px;margin:10px 0}"
         "@media print{h2{page-break-before:always}.card{page-break-inside:avoid}}</style></head><body>" % e(a.hostname)]
    h.append("<h1>Audit des images Docker : %s</h1><p>%s</p>" % (e(a.hostname), a.now.strftime("%d/%m/%Y %H:%M")))
    h.append("<p style='font-size:28px'><b style='color:%s'>%d/100 (note %s)</b></p><p>%s</p>" % (score_color(score), score, grade_of(score), e(verdict(score, counts, len(a.images)))))
    h.append("<p>" + " ".join("<span class='b' style='background:%s'>%s : %d</span>" % (SEV_COLOR[s], SEV_LABEL[s], counts[s]) for s in (CRIT, HIGH, MED, LOW, OK)) + "</p>")
    h.append("<table>" + "".join("<tr><th style='width:30%%'>%s</th><td>%s</td></tr>" % (e(k), e(v)) for k, v in a.facts.items()) + "</table>")
    h.append("<h2>Ce qu'il faut corriger</h2>")
    for i, f in enumerate(a.actions(), 1):
        h.append("<div class='card' style='border-left-color:%s'><span class='b' style='background:%s'>%s</span> <b>%d. %s</b> <small>(%s)</small>"
                 % (SEV_COLOR[f["status"]], SEV_COLOR[f["status"]], SEV_LABEL[f["status"]], i, e(f["title"]), e(f["cat"])))
        h.append("<p><b>Constat :</b> %s</p><p><b>À faire :</b> %s</p>" % (e(f["detail"]), e(f["reco"])))
        if f["fix"]:
            h.append("<pre>%s</pre>" % escape(f["fix"]))
        h.append("</div>")
    h.append("<h2>Ce qui est déjà bien</h2><table><tr><th>Image</th><th>Contrôle</th><th>Constat</th></tr>")
    h += ["<tr><td>%s</td><td><b>%s</b></td><td>%s</td></tr>" % (e(f["cat"]), e(f["title"]), e(f["detail"])) for f in a.findings if f["status"] == OK]
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


def main():
    p = argparse.ArgumentParser(description="Audit des vulnérabilités (CVE) des images Docker, via Trivy. Lecture seule.")
    p.add_argument("images", nargs="*", help="images précises à scanner (défaut : images des conteneurs en cours d'exécution)")
    p.add_argument("-o", "--output", help="chemin du rapport (défaut : ./audit-docker-<hôte>-<date>.pdf)")
    p.add_argument("--all", action="store_true", help="inclure les conteneurs arrêtés (docker ps -a)")
    p.add_argument("--secrets", action="store_true", help="chercher aussi des secrets intégrés dans les images")
    p.add_argument("--timeout", type=int, default=10, help="délai max par image, en minutes (défaut : 10)")
    p.add_argument("--no-db-update", action="store_true", help="ne pas mettre à jour la base de vulnérabilités Trivy")
    p.add_argument("--json", action="store_true", help="exporter aussi les résultats en JSON")
    p.add_argument("--version", action="version", version="audit_docker.py " + VERSION)
    args = p.parse_args()

    trivy = Trivy(args)
    if not trivy.detect():
        log("[!] Trivy est introuvable et Docker n'est pas disponible pour l'exécuter.", "red")
        log("    Installez Trivy : https://trivy.dev/latest/getting-started/installation/", "gray")
        log("    Sur Ubuntu/Debian :", "gray")
        log("      sudo apt-get install -y wget gnupg", "gray")
        log("      wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg >/dev/null", "gray")
        log("      echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\" | sudo tee /etc/apt/sources.list.d/trivy.list", "gray")
        log("      sudo apt-get update && sudo apt-get install -y trivy", "gray")
        sys.exit(1)

    pdf_ok = ensure_reportlab()
    log("[*] Audit Docker (Trivy %s) - %s" % (trivy.version, datetime.datetime.now().strftime("%d/%m/%Y %H:%M")), "bold")
    a = DockerAudit(args, trivy)
    a.run_all()
    if not a.images:
        log("[!] Aucune image à analyser.", "yellow")
        sys.exit(0)

    base = args.output or os.path.join(os.getcwd(), "audit-docker-%s-%s.pdf" % (a.hostname, a.now.strftime("%Y%m%d-%H%M")))
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
            json.dump(dict(host=a.hostname, date=a.now.isoformat(), version=VERSION, score=a.global_score(),
                           grade=grade_of(a.global_score()), facts=a.facts, findings=a.findings, inventory=a.inventory),
                      f, ensure_ascii=False, indent=2)
        outputs.append(jp)
    for o in outputs:
        try:
            os.chmod(o, 0o600)
            if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
                os.chown(o, int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"])))
        except (OSError, AttributeError):
            pass

    score, counts = a.global_score(), a.counts()
    col = "green" if score >= 80 else "yellow" if score >= 55 else "red"
    log("")
    log("Santé des images : %d/100 (note %s)" % (score, grade_of(score)), col)
    log("Contrôles — Critiques : %d | Élevés : %d | Moyens : %d | Faibles : %d | OK : %d"
        % (counts[CRIT], counts[HIGH], counts[MED], counts[LOW], counts[OK]))
    for f in a.actions()[:5]:
        log("  - [%s] %s (%s)" % (SEV_LABEL[f["status"]], f["title"], f["cat"]), "red" if f["status"] in (CRIT, HIGH) else "yellow")
    for o in outputs:
        log("Rapport : %s" % o, "bold")


if __name__ == "__main__":
    main()
