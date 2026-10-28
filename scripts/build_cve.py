#!/usr/bin/env python3
"""Bouwt de CVE-briefingpagina's van it-mike.be uit content/cve/*.json.

Gebruik:  python3 scripts/build_cve.py
Schrijft: cve/index.html (laatste briefing), cve/<datum>/index.html (archief)
          en werkt de CVE-items in sitemap.xml bij.

Het script valideert elke JSON strikt en stopt (exit 1) zonder iets te schrijven
als er iets mis is, zodat er nooit een kapotte pagina online komt.
Alleen standaardbibliotheek, geen dependencies.
"""
import datetime as dt
import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "content" / "cve"
OUT_DIR = ROOT / "cve"
SITEMAP = ROOT / "sitemap.xml"
SITE = "https://it-mike.be"

SEVERITIES = {"critical": "Kritiek", "high": "Hoog", "medium": "Gemiddeld"}
STATUSES = {"patch": ("Patch beschikbaar", "ok"), "nopatch": ("Geen patch", "critical"),
            "mitigation": ("Workaround", "warn")}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ID_RE = re.compile(r"^[a-z0-9-]+$")
MONTHS = ["januari", "februari", "maart", "april", "mei", "juni", "juli",
          "augustus", "september", "oktober", "november", "december"]
DAYS = ["maandag", "dinsdag", "woensdag", "donderdag", "vrijdag", "zaterdag", "zondag"]


class Invalid(Exception):
    pass


def e(s):
    return html.escape(str(s), quote=True)


def need(obj, key, typ, where):
    if key not in obj or not isinstance(obj[key], typ):
        raise Invalid(f"{where}: '{key}' ontbreekt of heeft verkeerd type")
    if typ is str and not obj[key].strip():
        raise Invalid(f"{where}: '{key}' is leeg")
    return obj[key]


def url_ok(u, where):
    if not isinstance(u, str) or not u.startswith("https://") or any(c in u for c in ' "<>'):
        raise Invalid(f"{where}: ongeldige URL {u!r} (alleen https)")
    return u


def validate(d, fname):
    w = fname
    date = need(d, "date", str, w)
    if not DATE_RE.match(date) or f"{date}.json" != fname:
        raise Invalid(f"{w}: 'date' moet JJJJ-MM-DD zijn en gelijk aan de bestandsnaam")
    dt.date.fromisoformat(date)
    for k in ("headline", "summary"):
        need(d, k, str, w)
    stats = need(d, "stats", dict, w)
    for k in ("critical", "exploited", "fixes"):
        if not isinstance(stats.get(k), int) or stats[k] < 0:
            raise Invalid(f"{w}: stats.{k} moet een positief geheel getal zijn")
    groups = need(d, "groups", list, w)
    if not groups:
        raise Invalid(f"{w}: geen groepen")
    seen = set()
    for gi, g in enumerate(groups):
        gw = f"{w} groep {gi}"
        gid = need(g, "id", str, gw)
        if not ID_RE.match(gid) or gid in seen:
            raise Invalid(f"{gw}: id ongeldig of dubbel")
        seen.add(gid)
        need(g, "label", str, gw); need(g, "title", str, gw)
        items = g.get("items", [])
        if not isinstance(items, list):
            raise Invalid(f"{gw}: items moet een lijst zijn")
        for ii, it in enumerate(items):
            iw = f"{gw} item {ii}"
            need(it, "product", str, iw); need(it, "what", str, iw)
            if it.get("severity") not in SEVERITIES:
                raise Invalid(f"{iw}: severity moet {list(SEVERITIES)} zijn")
            if it.get("status") not in STATUSES:
                raise Invalid(f"{iw}: status moet {list(STATUSES)} zijn")
            if not isinstance(it.get("exploited"), bool):
                raise Invalid(f"{iw}: exploited moet true/false zijn")
            for c in it.get("cves", []):
                if not CVE_RE.match(c):
                    raise Invalid(f"{iw}: ongeldig CVE-nummer {c!r}")
            steps = need(it, "steps", list, iw)
            if not steps or not all(isinstance(s, str) and s.strip() for s in steps):
                raise Invalid(f"{iw}: steps moet niet-lege tekst bevatten")
            srcs = need(it, "sources", list, iw)
            if not srcs:
                raise Invalid(f"{iw}: minstens één bron vereist")
            for s in srcs:
                need(s, "label", str, iw); url_ok(s.get("url"), iw)
    for fi, f in enumerate(d.get("fixed", [])):
        fw = f"{w} fixed {fi}"
        need(f, "product", str, fw); need(f, "fix", str, fw); url_ok(f.get("url"), fw)


def nl_date(iso, weekday=True):
    d = dt.date.fromisoformat(iso)
    s = f"{d.day} {MONTHS[d.month - 1]} {d.year}"
    return f"{DAYS[d.weekday()]} {s}" if weekday else s


def short_date(iso):
    d = dt.date.fromisoformat(iso)
    return f"{d.day:02d}/{d.month:02d}/{d.year}"


ARROW = '<span aria-hidden="true">↗</span>'


def card(it):
    sev = it["severity"]
    status_txt, status_cls = STATUSES[it["status"]]
    badges = [f'<span class="cve-badge cve-badge--{sev}">{e(SEVERITIES[sev])}</span>']
    if it["exploited"]:
        badges.insert(0, '<span class="cve-badge cve-badge--expl">Actief misbruikt</span>')
    badges.append(f'<span class="cve-badge cve-badge--{status_cls}">{e(status_txt)}</span>')
    ids = "".join(
        f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}" target="_blank" rel="noopener">{e(c)}</a>'
        for c in it.get("cves", []))
    steps = "".join(f"<li>{e(s)}</li>" for s in it["steps"])
    srcs = "".join(
        f'<a href="{e(s["url"])}" target="_blank" rel="noopener">{e(s["label"])} {ARROW}</a>'
        for s in it["sources"])
    score = (it.get("score") or "").strip()
    score_html = (f'<div class="cve-score"><div class="cve-score-num">{e(score)}</div>'
                  f'<div class="cve-score-label">CVSS</div></div>') if score and score not in ("-", "–") else ""
    return f"""
    <article class="cve-card cve-card--{sev}">
      <div class="cve-card-head">
        <div class="cve-badges">{''.join(badges)}</div>
        {score_html}
      </div>
      <h3 class="cve-title">{e(it["product"])}</h3>
      {f'<div class="cve-ids">{ids}</div>' if ids else ''}
      <p class="cve-what">{e(it["what"])}</p>
      <ul class="cve-steps">{steps}</ul>
      <div class="cve-sources">{srcs}</div>
    </article>"""


def render(d, all_dates, is_latest):
    date = d["date"]
    canonical = f"{SITE}/cve/" if is_latest else f"{SITE}/cve/{date}/"
    title = f"CVE-briefing {short_date(date)} – {d['stats']['critical']} kritiek, {d['stats']['exploited']} actief misbruikt | IT-Mike"
    desc = d["summary"][:300]
    groups = [g for g in d["groups"] if g.get("items") or g.get("empty_note")]

    jump = "".join(
        f'<a href="#{e(g["id"])}">{e(g["label"])} <span class="cve-count">{len(g.get("items", []))}</span></a>'
        for g in groups)

    sections = []
    for n, g in enumerate(groups, 1):
        items = "".join(card(it) for it in g.get("items", []))
        em = f' <em>{e(g["title_em"])}</em>' if g.get("title_em") else ""
        sub = f'<p class="section-sub">{e(g["sub"])}</p>' if g.get("sub") else ""
        empty = f'<p class="cve-empty">{e(g["empty_note"])}</p>' if g.get("empty_note") else ""
        sections.append(f"""
<section class="section cve-group reveal" id="{e(g['id'])}">
  <div class="section-head">
    <div class="section-tag"><span class="tag-num">§ {n:02d}</span>{e(g['label'])}</div>
    <h2 class="section-title">{e(g['title'])}{em}</h2>
    {sub}
  </div>
  {f'<div class="cve-grid">{items}</div>' if items else ''}
  {empty}
</section>""")

    fixed_rows = "".join(f"""
    <div class="cve-fixed-row">
      <span class="cve-fixed-prod">{e(f['product'])}</span>
      <span class="cve-fixed-ver">{e(f['fix'])}</span>
      <a href="{e(f['url'])}" target="_blank" rel="noopener">Bron {ARROW}</a>
    </div>""" for f in d.get("fixed", []))
    fixed = f"""
<section class="section cve-fixed reveal" id="opgelost">
  <div class="section-head">
    <div class="section-tag"><span class="tag-num">§ FIX</span>Opgelost</div>
    <h2 class="section-title">Nieuwe <em>patches.</em></h2>
    <p class="section-sub">Updates die sinds de vorige briefing verschenen.</p>
  </div>
  <div class="cve-fixed-list">{fixed_rows}</div>
</section>""" if fixed_rows else ""

    cur = ' aria-current="page"'
    archive_links = "".join(
        f'<a href="/cve/{x}/"{cur if x == date else ""}>{short_date(x)}</a>'
        for x in all_dates[:30])

    em = f' <em>{e(d["headline_em"])}</em>' if d.get("headline_em") else ""
    period = f'<span>Periode <strong>{e(d["period"])}</strong></span>' if d.get("period") else ""
    ld = json.dumps({
        "@context": "https://schema.org", "@type": "Article",
        "headline": f"CVE-briefing {short_date(date)}", "datePublished": date, "dateModified": date,
        "inLanguage": "nl-BE", "description": desc,
        "author": {"@type": "Person", "name": "Mike Jonckheere"},
        "publisher": {"@type": "LocalBusiness", "name": "IT-Mike", "url": SITE},
        "mainEntityOfPage": canonical,
    }, ensure_ascii=False).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{e(title)}</title>
<meta name="description" content="{e(desc)}"/>
<meta name="author" content="Mike Jonckheere — IT-Mike"/>
<meta name="robots" content="index, follow"/>
<link rel="canonical" href="{canonical}"/>
<link rel="icon" type="image/png" href="/media/Favicon.png"/>
<link rel="apple-touch-icon" href="/media/Favicon.png"/>
<meta property="og:type" content="article"/>
<meta property="og:url" content="{canonical}"/>
<meta property="og:title" content="{e(title)}"/>
<meta property="og:description" content="{e(desc)}"/>
<meta property="og:locale" content="nl_BE"/>
<meta property="og:image" content="{SITE}/media/Logo with slogan.png"/>
<script type="application/ld+json">{ld}</script>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin/>
<link href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@500;700;800;900&family=Cinzel:wght@500;700;900&family=Instrument+Serif:ital@0;1&family=Instrument+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="/styles.css"/>
<link rel="stylesheet" href="/cve/cve.css"/>
</head>
<body>

<div class="mobile-menu" id="mobileMenu">
  <button class="mobile-close" id="mobileClose" aria-label="Sluit menu">×</button>
  <a href="/#diensten" class="mobile-link"><span>01</span>Diensten</a>
  <a href="/#werkwijze" class="mobile-link"><span>02</span>Werkwijze</a>
  <a href="/#over" class="mobile-link"><span>03</span>Over Mike</a>
  <a href="#contact" class="mobile-link"><span>04</span>Contact</a>
  <a href="tel:+32496797671" class="mobile-call">04 96 79 76 71</a>
</div>

<nav id="navbar" class="nav scrolled">
  <a href="/" class="nav-brand" aria-label="IT-Mike home">
    <img src="/media/Dog mark.png" alt="" class="nav-dog"/>
    <span class="nav-name">MIKE JONCKHEERE</span>
  </a>
  <ul class="nav-links">
    <li><a href="/#diensten"><span class="nav-num">01</span>Diensten</a></li>
    <li><a href="/#werkwijze"><span class="nav-num">02</span>Werkwijze</a></li>
    <li><a href="/#over"><span class="nav-num">03</span>Over Mike</a></li>
    <li><a href="#contact"><span class="nav-num">04</span>Contact</a></li>
  </ul>
  <a href="tel:+32496797671" class="nav-cta"><span class="nav-cta-dot"></span>04 96 79 76 71</a>
  <button class="nav-burger" id="navBurger" aria-label="Open menu"><span></span><span></span><span></span></button>
</nav>

<main>

<section class="section cve-hero">
  <div class="section-head">
    <div class="section-tag"><span class="tag-num">§ SECURITY</span>CVE-briefing · {e(nl_date(date))}</div>
    <h1 class="section-title">{e(d['headline'])}{em}</h1>
    <p class="section-sub">{e(d['summary'])}</p>
    <div class="cve-meta">{period}<span>Bijgewerkt <strong>{e(short_date(date))}</strong></span><a href="#archief">Archief →</a></div>
  </div>
  <div class="cve-stats">
    <div class="cve-stat cve-stat--crit"><div class="cve-stat-num">{d['stats']['critical']}</div><div class="cve-stat-label">Kritiek</div></div>
    <div class="cve-stat cve-stat--expl"><div class="cve-stat-num">{d['stats']['exploited']}</div><div class="cve-stat-label">Actief misbruikt</div></div>
    <div class="cve-stat cve-stat--ok"><div class="cve-stat-num">{d['stats']['fixes']}</div><div class="cve-stat-label">Nieuwe fixes</div></div>
  </div>
  <nav class="cve-jump" aria-label="Spring naar groep">{jump}</nav>
</section>
{''.join(sections)}
{fixed}

<section class="section reveal" id="archief">
  <div class="section-head">
    <div class="section-tag"><span class="tag-num">§ ARCHIEF</span>Vorige briefings</div>
    <h2 class="section-title">Eerder <em>gemeld.</em></h2>
  </div>
  <div class="cve-archive-list">{archive_links}</div>
</section>

<section class="section wb-contact reveal" id="contact">
  <div class="section-head">
    <div class="section-tag"><span class="tag-num">§ CONTACT</span>Hulp nodig?</div>
    <h2 class="section-title">Geen tijd om <em>te patchen?</em></h2>
    <p class="section-sub">Ik volg dit dagelijks op voor kmo's en lokale besturen in West-Vlaanderen. Bel of mail, dan bekijken we samen wat er bij u moet gebeuren.</p>
  </div>
  <div class="wb-contact-actions">
    <a href="tel:+32496797671" class="btn btn-primary">04 96 79 76 71 <span class="btn-arrow">→</span></a>
    <a href="mailto:mike@it-mike.be?subject=CVE-briefing%20{e(short_date(date))}" class="btn btn-ghost">mike@it-mike.be</a>
  </div>
</section>

<p class="cve-disclaimer">Deze briefing wordt automatisch samengesteld uit publieke bronnen (CCB, CISA, NVD, advisories van leveranciers en vakpers), met een link naar elke bron. Ze is informatief en zonder garantie: controleer versienummers en stappen altijd bij de leverancier voordat u updates uitrolt.</p>

</main>

<footer class="footer">
  <div class="footer-row">
    <div class="footer-brand">
      <img src="/media/Dog mark.png" alt="IT-Mike" class="footer-dog"/>
      <span class="footer-name">MIKE JONCKHEERE</span>
    </div>
    <div class="footer-meta">
      <span>© {date[:4]} IT-Mike — Mike Jonckheere — Ardooie</span>
      <span class="footer-sep">·</span>
      <a href="https://mjon.be">→ MJON.be</a>
    </div>
  </div>
  <div class="footer-areas">
    <span>Actief in:</span>
    <a href="/ardooie/">Ardooie</a> ·
    <a href="/lichtervelde/">Lichtervelde</a> ·
    <a href="/pittem/">Pittem</a> ·
    <a href="/izegem/">Izegem</a> ·
    <a href="/roeselare/">Roeselare</a>
    <span>· en de ruime regio</span>
  </div>
  <div class="footer-bar">
    <address class="footer-address">
      <strong>IT-Mike</strong> · Mike Jonckheere · Ardooie, 8850 West-Vlaanderen · België ·
      <a href="tel:+32496797671">+32 496 79 76 71</a> ·
      <a href="mailto:mike@it-mike.be">mike@it-mike.be</a>
    </address>
    <span>🔒 Geen cookies · GDPR-conform via Cloudflare Web Analytics · BTW BE0780.671.242</span>
  </div>
</footer>

<script>
var mobileMenu = document.getElementById('mobileMenu');
document.getElementById('navBurger').addEventListener('click', function() {{ mobileMenu.classList.add('open'); }});
document.getElementById('mobileClose').addEventListener('click', function() {{ mobileMenu.classList.remove('open'); }});
document.querySelectorAll('.mobile-link').forEach(function(l) {{ l.addEventListener('click', function() {{ mobileMenu.classList.remove('open'); }}); }});
if ('IntersectionObserver' in window) {{
  var obs = new IntersectionObserver(function(entries) {{
    entries.forEach(function(en) {{ if (en.isIntersecting) {{ en.target.classList.add('visible'); obs.unobserve(en.target); }} }});
  }}, {{ threshold: 0.08, rootMargin: '0px 0px -40px 0px' }});
  document.querySelectorAll('.reveal').forEach(function(el) {{ obs.observe(el); }});
}} else {{
  document.querySelectorAll('.reveal').forEach(function(el) {{ el.classList.add('visible'); }});
}}
</script>
</body>
</html>
"""


def update_sitemap(dates):
    text = SITEMAP.read_text(encoding="utf-8")
    text = re.sub(r"\s*<url>\s*<loc>https://it-mike\.be/cve/[^<]*</loc>.*?</url>", "", text, flags=re.S)
    entries = [f"""  <url>
    <loc>{SITE}/cve/</loc>
    <lastmod>{dates[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.7</priority>
  </url>"""]
    entries += [f"""  <url>
    <loc>{SITE}/cve/{x}/</loc>
    <lastmod>{x}</lastmod>
    <changefreq>never</changefreq>
    <priority>0.3</priority>
  </url>""" for x in dates]
    text = text.replace("</urlset>", "\n".join(entries) + "\n</urlset>")
    return text


def main():
    files = sorted(DATA_DIR.glob("*.json"), reverse=True)
    if not files:
        print("Geen briefings gevonden in content/cve/", file=sys.stderr)
        return 1
    data = []
    try:
        for f in files:
            d = json.loads(f.read_text(encoding="utf-8"))
            validate(d, f.name)
            data.append(d)
    except (Invalid, ValueError) as ex:
        print(f"VALIDATIE MISLUKT: {ex}", file=sys.stderr)
        return 1

    dates = [d["date"] for d in data]
    outputs = {OUT_DIR / "index.html": render(data[0], dates, True)}
    for d in data:
        outputs[OUT_DIR / d["date"] / "index.html"] = render(d, dates, False)
    sitemap = update_sitemap(dates)

    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    SITEMAP.write_text(sitemap, encoding="utf-8")
    print(f"OK: {len(outputs)} pagina's gebouwd, laatste briefing {dates[0]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
