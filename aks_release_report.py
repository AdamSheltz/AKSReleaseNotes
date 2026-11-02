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
            "summary": summarize(body),
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


def build_markdown(results, days, now):
    total = sum(len(r[2]) for r in results)
    md = [f"# AKS Component Release Report",
          f"_Window: last {days} days (since {(now - dt.timedelta(days=days)):%Y-%m-%d %H:%M} UTC) - "
          f"generated {now:%Y-%m-%d %H:%M} UTC_", "",
          f"**{total} release(s) across {sum(1 for r in results if r[2])} component(s).**", "",
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
                   + (f" - flags: {', '.join(i['flags'])}" if i["flags"] else "")]
            if i["cves"]:
                md.append(f"CVEs: {', '.join(i['cves'])}")
            md += [""] + [f"> {l}" for l in i["summary"]]
    return "\n".join(md)


def build_html(results, days, now):
    total = sum(len(r[2]) for r in results)
    color = {"Breaking": "#c62828", "Security": "#ef6c00", "AKS/Azure": "#0078d4"}
    def badge(f): return f'<span style="background:{color[f]};color:#fff;border-radius:4px;padding:1px 6px;font-size:11px;margin-right:4px">{f}</span>'
    rows, details = [], []
    for (cat, comp), repo, items, err in results:
        if not items:
            continue
        flags = sorted({f for i in items for f in i["flags"]})
        tag_links = [f"<a href='{i['link']}'>{html.escape(i['tag'])}</a>" for i in items]
        rows.append(f"<tr><td>{cat}</td><td><a href='https://github.com/{repo}/releases'>{html.escape(comp)}</a></td>"
                    f"<td>{'<br>'.join(tag_links)}</td>"
                    f"<td>{''.join(badge(f) for f in flags)}</td></tr>")
        for i in items:
            details.append(
                f"<h3>{html.escape(comp)} &mdash; {html.escape(i['title'])}</h3>"
                f"<p><a href='{i['link']}'>{html.escape(i['tag'])}</a> &middot; {i['date']:%Y-%m-%d %H:%M} UTC "
                + ("&middot; <b>pre-release</b> " if i["prerelease"] else "")
                + "".join(badge(f) for f in i["flags"]) + "</p>"
                + (f"<p><b>CVEs:</b> {', '.join(i['cves'])}</p>" if i["cves"] else "")
                + "<pre style='white-space:pre-wrap;background:#f6f8fa;padding:8px;border-radius:6px'>"
                + html.escape("\n".join(i["summary"])) + "</pre>")
    quiet = [k[1] for k, _, items, err in results if not items and not err]
    errs = [(k[1], err) for k, _, items, err in results if err]
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>AKS Component Release Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:24px auto;color:#222}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:6px;vertical-align:top}}
th{{background:#0078d4;color:#fff;text-align:left}}</style></head><body>
<h1>AKS Component Release Report</h1>
<p>Last {days} days (since {(now - dt.timedelta(days=days)):%Y-%m-%d %H:%M} UTC) &middot; generated {now:%Y-%m-%d %H:%M} UTC</p>
<p><b>{total} release(s)</b> across {len(rows)} component(s).</p>
<table><tr><th>Category</th><th>Component</th><th>Releases</th><th>Flags</th></tr>{''.join(rows) or '<tr><td colspan=4>No releases in window</td></tr>'}</table>
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
    a = p.parse_args()

    now = dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=a.days)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda kv: fetch_feed(kv[0], kv[1], a.github_token, cutoff, a.include_prerelease),
                              FEEDS.items()))

    out_dir = os.path.join(a.out_root, dt.datetime.now().strftime("%Y%m%d"))
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, a.out)
    md, page = build_markdown(results, a.days, now), build_html(results, a.days, now)
    with open(f"{base}.md", "w", encoding="utf-8") as f:
        f.write(md)
    with open(f"{base}.html", "w", encoding="utf-8") as f:
        f.write(page)
    total = sum(len(r[2]) for r in results)
    print(f"{total} release(s) in last {a.days} days -> {base}.html, {base}.md")
    for k, repo, items, err in results:
        if err:
            print(f"  WARN {k[1]}: {err}", file=sys.stderr)
    if a.teams_webhook:
        post_to_teams(a.teams_webhook, results, a.days, now)


if __name__ == "__main__":
    main()
