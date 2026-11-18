#!/usr/bin/env python3
"""
AKS component release report.

Scans GitHub release Atom feeds for AKS and its underlying components
(CSI drivers, Cilium, Azure CNI, CoreDNS, etc.) and publishes a report of
every release in the last N days (default 3).

Standard library only - no pip installs required.

Usage:
  python aks_release_report.py                    # last 3 days, writes ./<yyyymmdd>/ HTML + Markdown
  python aks_release_report.py --days 7
  python aks_release_report.py --include-prerelease   # also include rc/alpha/beta
  python aks_release_report.py --out-root C:\\Reports  # writes C:\\Reports\\<yyyymmdd>\\
  python aks_release_report.py --teams-webhook https://...   # also post summary to Teams
  python aks_release_report.py --github-token ghp_xxx        # optional, raises rate limit
  python aks_release_report.py --search CVE --search "node image"      # highlight terms in the HTML report
  python aks_release_report.py --days 14 --search cilium --search-only  # only releases that match

Search: --search is case-insensitive and can be repeated. Matches are highlighted
in the HTML report (component, title, tag, CVEs, summary) and every matching line
from the full release notes is listed under each release, even when it falls
outside the 12-line summary. Wrap a term in slashes for a regex: --search "/CVE-2026-\\d+/"

Teams: create the webhook with the Teams "Workflows" app
("Post to a channel when a webhook request is received") and pass its URL.
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

FEEDS = {
    # Category, Component, owner/repo
    ("AKS", "AKS release notes"): "Azure/AKS",
    ("AKS", "Node images (AgentBaker)"): "Azure/AgentBaker",
    ("Storage", "Azure Disk CSI"): "kubernetes-sigs/azuredisk-csi-driver",
    ("Storage", "Azure Files CSI"): "kubernetes-sigs/azurefile-csi-driver",
    ("Storage", "Azure Blob CSI"): "kubernetes-sigs/blob-csi-driver",
    ("Storage", "Secrets Store CSI"): "kubernetes-sigs/secrets-store-csi-driver",
    ("Storage", "Key Vault provider"): "Azure/secrets-store-csi-driver-provider-azure",
    ("Storage", "CSI external-snapshotter"): "kubernetes-csi/external-snapshotter",
    ("Networking", "Cilium"): "cilium/cilium",
    ("Networking", "Azure CNI / CNS / NPM"): "Azure/azure-container-networking",
    ("Networking", "Calico"): "projectcalico/calico",
    ("Networking", "CoreDNS"): "coredns/coredns",
    ("Networking", "Konnectivity"): "kubernetes-sigs/apiserver-network-proxy",
    ("Networking", "ip-masq-agent-v2"): "Azure/ip-masq-agent-v2",
    ("Networking", "Retina (ACNS)"): "microsoft/retina",
    ("Networking", "Istio"): "istio/istio",
    ("Control plane & add-ons", "cloud-provider-azure"): "kubernetes-sigs/cloud-provider-azure",
    ("Control plane & add-ons", "Kubernetes"): "kubernetes/kubernetes",
    ("Control plane & add-ons", "metrics-server"): "kubernetes-sigs/metrics-server",
    ("Control plane & add-ons", "Workload Identity"): "Azure/azure-workload-identity",
    ("Control plane & add-ons", "KEDA"): "kedacore/keda",
    ("Control plane & add-ons", "Gatekeeper (Azure Policy)"): "open-policy-agent/gatekeeper",
}

ATOM = "{http://www.w3.org/2005/Atom}"
PRERELEASE_RE = re.compile(r"(?i)\b(rc|alpha|beta|pre-?release|snapshot|nightly)\b|-rc\.?\d|-alpha|-beta")
FLAGS = {
    "Breaking": re.compile(r"(?i)breaking|deprecat|removed|action required|urgent upgrade"),
    "Security": re.compile(r"(?i)\bCVE-\d{4}-\d+|security|vulnerab|GHSA-"),
    "AKS/Azure": re.compile(r"(?i)\baks\b|azure"),
}


def compile_search(terms):
    """Build one case-insensitive regex from --search terms (/.../ = raw regex)."""
    parts = []
    for t in terms or []:
        t = t.strip()
        if not t:
            continue
        if len(t) > 2 and t.startswith("/") and t.endswith("/"):
            parts.append(t[1:-1])
        else:
            parts.append(re.escape(t))
    if not parts:
        return None
    # Longest first so "node image" wins over "node" when both are given.
    parts.sort(key=len, reverse=True)
    return re.compile("|".join(f"(?:{x})" for x in parts), re.IGNORECASE)


def highlight(text, rx):
    """HTML-escape text and wrap each search match in <mark>."""
    text = text or ""
    if not rx:
        return html.escape(text)
    out, last = [], 0
    for m in rx.finditer(text):
        if m.start() == m.end():
            continue
        out.append(html.escape(text[last:m.start()]))
        out.append(f"<mark>{html.escape(m.group(0))}</mark>")
        last = m.end()
    out.append(html.escape(text[last:]))
    return "".join(out)


def apply_search(results, rx, max_lines=15):
    """Annotate each release with its match count and matching lines from the full notes."""
    for _, _, items, _ in results:
        for i in items:
            if not rx:
                i["matches"], i["match_lines"] = 0, []
                continue
            haystack = "\n".join([i["title"], i["tag"], i["body"]])
            i["matches"] = sum(1 for m in rx.finditer(haystack) if m.group(0))
            lines = [l.strip() for l in i["body"].splitlines() if l.strip() and rx.search(l)]
            i["match_lines"] = lines[:max_lines] + (
                [f"... ({len(lines) - max_lines} more matching lines - see full notes)"]
                if len(lines) > max_lines else [])
    return results


def filter_matches(results):
    """Keep only releases that matched the search."""
    return [(k, repo, [i for i in items if i["matches"]], err) for k, repo, items, err in results]


def strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", "", s or "")
    s = re.sub(r"(?i)<br\s*/?>|</p>|</li>|</h\d>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


def fetch_feed(key, repo, token, cutoff, include_pre):
    url = f"https://github.com/{repo}/releases.atom"
    headers = {"User-Agent": "aks-release-report"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            root = ET.fromstring(r.read())
    except Exception as e:
        return key, repo, [], str(e)

    items = []
    for entry in root.findall(f"{ATOM}entry"):
        updated = entry.findtext(f"{ATOM}updated")
        when = dt.datetime.fromisoformat(updated.replace("Z", "+00:00"))
        if when < cutoff:
            continue
        title = (entry.findtext(f"{ATOM}title") or "").strip()
        link_el = entry.find(f"{ATOM}link")
        link = link_el.get("href") if link_el is not None else url
        tag = link.rsplit("/", 1)[-1]
        is_pre = bool(PRERELEASE_RE.search(title) or PRERELEASE_RE.search(tag))
        if is_pre and not include_pre:
            continue
        body = strip_html(entry.findtext(f"{ATOM}content") or "")
        flags = [name for name, rx in FLAGS.items() if rx.search(body) or rx.search(title)]
        items.append({
            "title": title, "tag": tag, "link": link, "date": when,
            "prerelease": is_pre, "flags": flags,
            "summary": summarize(body), "body": body,
            "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", body))),
        })
    items.sort(key=lambda i: i["date"], reverse=True)
    return key, repo, items, None


def summarize(body, max_lines=12):
    """Keep the most informative lines: headings and bullet points."""
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    picked = [l for l in lines if l.startswith(("-", "*", "•", "#")) or len(l) < 120]
    picked = picked or lines
    out = picked[:max_lines]
    if len(picked) > max_lines:
        out.append(f"... ({len(picked) - max_lines} more lines - see full notes)")
    return out


def build_markdown(results, days, now, terms=None):
    total = sum(len(r[2]) for r in results)
    md = [f"# AKS Component Release Report",
          f"_Window: last {days} days (since {(now - dt.timedelta(days=days)):%Y-%m-%d %H:%M} UTC) - "
          f"generated {now:%Y-%m-%d %H:%M} UTC_", "",
          f"**{total} release(s) across {sum(1 for r in results if r[2])} component(s).**", "",
          *([f"**Search:** {', '.join(terms)} - "
             f"{sum(1 for r in results for i in r[2] if i.get('matches'))} matching release(s)", ""] if terms else []),
          "| Category | Component | Releases | Flags |", "|---|---|---|---|"]
    for (cat, comp), repo, items, err in results:
        if items:
            flags = sorted({f for i in items for f in i["flags"]})
            md.append(f"| {cat} | {comp} | {', '.join(i['tag'] for i in items)} | {', '.join(flags) or '-'} |")
    quiet = [k[1] for k, _, items, err in results if not items and not err]
    errs = [(k[1], err) for k, _, items, err in results if err]
    md += ["", f"**No releases:** {', '.join(quiet) or 'none'}"]
    if errs:
        md += ["", "**Could not read:** " + "; ".join(f"{c} ({e})" for c, e in errs)]
    for (cat, comp), repo, items, err in results:
        for i in items:
            md += ["", f"## {comp} - {i['title']}",
                   f"[{i['tag']}]({i['link']}) - {i['date']:%Y-%m-%d %H:%M} UTC"
                   + (" - **pre-release**" if i["prerelease"] else "")
                   + (f" - flags: {', '.join(i['flags'])}" if i["flags"] else "")
                   + (f" - **{i['matches']} search match(es)**" if i.get("matches") else "")]
            if i["cves"]:
                md.append(f"CVEs: {', '.join(i['cves'])}")
            md += [""] + [f"> {l}" for l in i["summary"]]
            if i.get("match_lines"):
                md += ["", "Matching lines:"] + [f"- {l}" for l in i["match_lines"]]
    return "\n".join(md)


def build_html(results, days, now, rx=None, terms=None, search_only=False):
    total = sum(len(r[2]) for r in results)
    hits = sum(1 for r in results for i in r[2] if i.get("matches"))
    color = {"Breaking": "#c62828", "Security": "#ef6c00", "AKS/Azure": "#0078d4"}
    def badge(f): return f'<span style="background:{color[f]};color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;margin-right:4px">{f}</span>'
    def match_badge(n): return (f'<span class="hit">&#128269; {n} match{"es" if n != 1 else ""}</span>' if n else "")
    anchor = 0
    rows, details = [], []
    for (cat, comp), repo, items, err in results:
        if not items:
            continue
        flags = sorted({f for i in items for f in i["flags"]})
        tag_links = []
        comp_hits = 0
        for i in items:
            anchor += 1
            i["_anchor"] = f"r{anchor}"
            comp_hits += i.get("matches", 0)
            tag_links.append(f"<a href='#{i['_anchor']}'>{highlight(i['tag'], rx)}</a>"
                             + (" &#128269;" if i.get("matches") else ""))
        rows.append(f"<tr{' class=hitrow' if comp_hits else ''}><td>{html.escape(cat)}</td>"
                    f"<td><a href='https://github.com/{repo}/releases'>{highlight(comp, rx)}</a></td>"
                    f"<td>{'<br>'.join(tag_links)}</td>"
                    f"<td>{''.join(badge(f) for f in flags)}{match_badge(comp_hits)}</td></tr>")
        for i in items:
            details.append(
                f"<div class='rel{' hitrel' if i.get('matches') else ''}' id='{i['_anchor']}'>"
                f"<h3>{highlight(comp, rx)} &mdash; {highlight(i['title'], rx)}</h3>"
                f"<p><a href='{i['link']}'>{highlight(i['tag'], rx)}</a> &middot; {i['date']:%Y-%m-%d %H:%M} UTC "
                + ("&middot; <b>pre-release</b> " if i["prerelease"] else "")
                + "".join(badge(f) for f in i["flags"]) + match_badge(i.get("matches", 0)) + "</p>"
                + (f"<p><b>CVEs:</b> {highlight(', '.join(i['cves']), rx)}</p>" if i["cves"] else "")
                + "<pre>" + highlight("\n".join(i["summary"]), rx) + "</pre>"
                + (("<p><b>Matching lines in full release notes:</b></p><pre class='hits'>"
                    + highlight("\n".join(i["match_lines"]), rx) + "</pre>") if i.get("match_lines") else "")
                + "</div>")
    quiet = [k[1] for k, _, items, err in results if not items and not err]
    errs = [(k[1], err) for k, _, items, err in results if err]
    search_html = ""
    if terms:
        search_html = ("<p class='searchbox'><b>Search:</b> "
                       + ", ".join(f"<mark>{html.escape(t)}</mark>" for t in terms)
                       + f" &middot; <b>{hits}</b> of {total} release(s) match"
                       + (" (showing matching releases only)" if search_only else "") + "</p>")
    empty = "No matching releases in window" if search_only else "No releases in window"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>AKS Component Release Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:24px auto;color:#222}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}}
th{{background:#0078d4;color:#fff;text-align:left}}
pre{{white-space:pre-wrap;background:#f6f8fa;padding:8px;border-radius:6px}}
pre.hits{{background:#fffde7;border-left:4px solid #fbc02d}}
mark{{background:#ffeb3b;color:#000;padding:0 2px;border-radius:2px}}
.hit{{background:#fbc02d;color:#000;border-radius:4px;padding:1px 6px;font-size:11px;margin-right:4px}}
tr.hitrow td{{background:#fffde7}}
.hitrel{{border-left:4px solid #fbc02d;padding-left:10px}}
.searchbox{{background:#fffde7;border:1px solid #fbc02d;border-radius:6px;padding:8px 12px}}
</style></head><body>
<h1>AKS Component Release Report</h1>
<p>Last {days} days (since {(now - dt.timedelta(days=days)):%Y-%m-%d %H:%M} UTC) &middot; generated {now:%Y-%m-%d %H:%M} UTC</p>
{search_html}
<p><b>{total} release(s)</b> across {len(rows)} component(s).</p>
<table><tr><th>Category</th><th>Component</th><th>Releases</th><th>Flags</th></tr>{''.join(rows) or f'<tr><td colspan=4>{empty}</td></tr>'}</table>
<p><b>No releases:</b> {html.escape(', '.join(quiet)) or 'none'}</p>
{('<p><b>Could not read:</b> ' + html.escape('; '.join(f'{c} ({e})' for c, e in errs)) + '</p>') if errs else ''}
<h2>Details</h2>{''.join(details)}</body></html>"""


def post_to_teams(webhook, results, days, now):
    """Posts an Adaptive Card summary to a Teams Workflows webhook."""
    facts = []
    for (cat, comp), repo, items, err in results:
        for i in items:
            flag = f" [{', '.join(i['flags'])}]" if i["flags"] else ""
            facts.append({"type": "TextBlock", "wrap": True,
                          "text": f"**{comp}** [{i['tag']}]({i['link']}) - {i['date']:%m/%d}{flag}"})
    body = [{"type": "TextBlock", "size": "Large", "weight": "Bolder",
             "text": f"AKS component releases - last {days} days"},
            {"type": "TextBlock", "isSubtle": True, "text": f"Generated {now:%Y-%m-%d %H:%M} UTC"}]
    body += facts or [{"type": "TextBlock", "text": "No new releases in this window."}]
    payload = {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {"type": "AdaptiveCard", "version": "1.4",
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "body": body}}]}
    req = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        print(f"Teams post: HTTP {r.status}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--days", type=int, default=3)
    p.add_argument("--include-prerelease", action="store_true", help="include rc/alpha/beta releases (omitted by default)")
    p.add_argument("--out-root", default=".", help="parent folder; report goes in <out-root>/<yyyymmdd>/")
    p.add_argument("--out", default="aks_release_report", help="output file name prefix")
    p.add_argument("--teams-webhook", default=os.getenv("TEAMS_WEBHOOK_URL"))
    p.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN"))
    p.add_argument("--search", action="append", default=[], metavar="TERM",
                   help="term to highlight in the HTML report (case-insensitive, repeatable; /regex/ allowed)")
    p.add_argument("--search-only", action="store_true",
                   help="with --search, only include releases that match")
    a = p.parse_args()
    if a.search_only and not a.search:
        p.error("--search-only requires --search")
    try:
        rx = compile_search(a.search)
    except re.error as e:
        p.error(f"invalid --search regex: {e}")

    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=a.days)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda kv: fetch_feed(kv[0], kv[1], a.github_token, cutoff, a.include_prerelease),
                              FEEDS.items()))
    apply_search(results, rx)
    if rx and a.search_only:
        results = filter_matches(results)

    out_dir = os.path.join(a.out_root, dt.datetime.now().strftime("%Y%m%d"))
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, a.out)
    md = build_markdown(results, a.days, now, a.search)
    page = build_html(results, a.days, now, rx, a.search, a.search_only)
    with open(f"{base}.md", "w", encoding="utf-8") as f:
        f.write(md)
    with open(f"{base}.html", "w", encoding="utf-8") as f:
        f.write(page)
    total = sum(len(r[2]) for r in results)
    print(f"{total} release(s) in last {a.days} days -> {base}.html, {base}.md")
    if rx:
        hits = sum(1 for r in results for i in r[2] if i["matches"])
        print(f"Search {a.search}: {hits} matching release(s)")
    for k, repo, items, err in results:
        if err:
            print(f"  WARN {k[1]}: {err}", file=sys.stderr)
    if a.teams_webhook:
        post_to_teams(a.teams_webhook, results, a.days, now)


if __name__ == "__main__":
    main()
