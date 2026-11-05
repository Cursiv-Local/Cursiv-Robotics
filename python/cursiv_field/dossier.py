"""Research dossier: a Markdown document (plus HTML and, when a browser is available, PDF) that
Cursiv can import (`add document <file>`) and turn into a research paper without inventing
anything.

Every number in it is either a recorded observation or a summary statistic recorded as a
derived observation that the independent verifier re-computed. Each is cited by its
observation id, and limitations are stated with Known / Inferred / Assumed / Unknown labels.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from cursiv_sim.identity import body_json

STATS = ("count", "mean", "min", "max", "stddev")
WRITER_RULES = """> **Instructions for anyone writing from this dossier (human or AI):**
> 1. Use only values that appear in this dossier, and cite their observation ids.
> 2. Keep each statement's label: *Known* (recorded or recomputed), *Inferred* (drawn from several records), *Assumed*, *Unknown*.
> 3. Do not upgrade an Unknown (for example calibration, uncertainty or clock accuracy) to a fact, and do not add causes, comparisons or literature values that are not cited here.
> 4. Keep the verification and limitations sections in any paper derived from this dossier."""


def records(package: Path) -> list[dict]:
    out = []
    for f in sorted((package / "data/robots").glob("*/records.jsonl")):
        out += [body_json(json.loads(line)) for line in f.read_text().splitlines() if line.strip()]
    return out


def _fmt(v, unit=""):
    if v is None:
        return "unknown"
    if isinstance(v, float):
        s = f"{v:.6g}"
    else:
        s = str(v)
    return f"{s} {unit}".strip()


def write(out_dir: Path, *, title: str, mission: str, package: Path, verification: dict, import_summary: dict,
          stats: dict, notes: str = "", qartod: dict | None = None, pdf: bool = True, trust: Path | None = None) -> dict:
    """Write dossier.md, dossier.html, (dossier.pdf) and data.csv into out_dir. Returns their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    recs = records(package)
    obs = [r["observation"] for r in recs if r["observation"]["mission_id"] == mission]   # the package may hold other missions
    real = [o for o in obs if o["provenance"]["source"] == "sensor"]
    synthetic = sum(o["synthetic"] for o in obs)
    ver, sci, rsn = verification["verification"], verification.get("science") or {}, verification.get("reasoning") or {}
    v = ver["verdicts"]
    bad = {f["observation_id"] for f in rsn.get("flags", []) if f["code"].startswith("derivation") and f["severity"] == "error"}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    times = sorted(o["sensor_time"] for o in real if o["sensor_time"])
    located = [o for o in real if o["location"]]
    md = [f"# {title}", "", f"Research dossier for mission `{mission}`. Generated {now} by cursiv-field from evidence package `{package.name}` "
          f"(the package's verification below covers every record in it; the sections after it describe this mission only).", ""]
    md.append("> **REAL SENSOR DATA** recorded with a phone." if not synthetic else
              f"> **SYNTHETIC DATA PRESENT** ({synthetic} of {len(obs)} records). Synthetic records are not real-world evidence.")
    md += ["", WRITER_RULES, ""]

    md += ["## 1. Evidence verification", "",
           "Checked by `cursiv-verify`, independently of the software that recorded the data. These checks show the records are unchanged and complete. They do not show that any measurement is correct.", "",
           "| Question | Result |", "|---|---|"]
    for label, key in (("Package structure", "structure"), ("Records unchanged since signing (integrity)", "integrity"),
                       ("Signed by enrolled keys (authenticity)", "authenticity"), ("No records missing (completeness)", "completeness"),
                       ("Original recordings present and unchanged", "attachments")):
        md.append(f"| {label} | {v[key].split(':')[0]} |")
    d = rsn.get("derivations", {})
    md += ["", f"Summary statistics recomputed by the verifier from the cited observations: {d.get('verified', 0)} match, "
               f"{d.get('mismatch', 0)} mismatch, {d.get('not_reproducible', 0)} not reproducible.", ""]

    md += ["## 2. Data collection (methods)", ""]
    for f in import_summary.get("files", []):
        md.append(f"- Recording `{f['file']}` (SHA-256 `{f['sha256']}`): phone *{f['device'] or 'model not reported'}*, phyphox {f['phyphox']}, "
                  f"data sets: {', '.join(f['sets'])}. Clock mapping in the export: {'yes' if f['time_reference'] else 'no (times unknown)'}.")
    sensors = sorted({(o["observation_type"], o["sensor"]["sensor_type"], o["sensor"]["model"] or "not reported") for o in real})
    md += ["", "| Quantity | Sensor | Reported model |", "|---|---|---|"] + [f"| {a} | {b} | {c} |" for a, b, c in sensors]
    hacc = sorted(o["location"]["horizontal_accuracy_m"] for o in located if o["location"].get("horizontal_accuracy_m") is not None)
    md += ["",
           f"- *Known:* {len(real)} sensor observations" + (f", from {times[0]} to {times[-1]} (phone clock)." if times else "; no sensor times."),
           f"- *Known:* {len(located)} observations have a location from the phone's GPS fixes"
           + (f" (median stated horizontal accuracy {hacc[len(hacc) // 2]:.3g} m)." if hacc else "."),
           "- *Known:* high-rate sensors were reduced to at most the stated rate by keeping the first sample in each window (no averaging); "
           "every kept value cites its original row, and the full original recording is attached.",
           "- *Unknown:* sensor calibration, measurement uncertainty and the accuracy of the phone's clock. Phones do not report them.",
           "- *Known:* custody. The phone does not sign data. Each recording was signed when this computer imported it, and the "
           "original export file is attached by SHA-256, so the evidence shows *this file was imported unchanged*, not that the phone produced it.", ""]
    if import_summary.get("notes"):
        md += ["Import notes:", ""] + [f"- {n}" for n in import_summary["notes"]] + [""]
    if notes:
        md += ["Field notes supplied by the operator (*not verified*):", "", f"> {notes}", ""]

    md += ["## 3. Results", "",
           "Each statistic is a signed derived observation; the verifier recomputed it from the cited inputs. Cite it by its id.", "",
           "| Quantity | n | Mean | Min | Max | Std. dev. | Recomputed | Mean observation id |", "|---|---|---|---|---|---|---|---|"]
    for key, s in sorted(stats.items()):
        unit = s["unit"]
        ok = "yes" if not any(s["ids"][k] in bad for k in s["ids"]) else "**NO**"
        md.append(f"| {key} | {_fmt(s['count'])} | {_fmt(s['mean'], unit)} | {_fmt(s['min'], unit)} | {_fmt(s['max'], unit)} | "
                  f"{_fmt(s.get('stddev'), unit)} | {ok} | `{s['ids']['mean']}` |")
    md += ["", "All observations, with ids, times, locations and values: `data.csv` (beside this dossier).", ""]

    md += ["## 4. Quality control", "", "Deterministic checks (no AI). A flag means the data needs attention; no flag does not mean a value is correct.", ""]
    counts = sci.get("counts", {})
    if counts:
        md += ["| Check | Count | Meaning |", "|---|---|---|"]
        meaning = {"type_unprofiled": "no expected range is defined for this quantity, so no range check (*Unknown*)",
                   "calibration_unknown": "calibration not recorded (*Unknown*)", "uncertainty_unknown": "uncertainty not recorded (*Unknown*)",
                   "location_unknown": "no GPS fix within the matching window (*Unknown*)", "sensor_time_unknown": "no sensor time (*Unknown*)",
                   "out_of_range": "outside the stated range (*Known*)", "out_of_order_time": "time went backwards (*Known*)",
                   "contradiction": "two sensors disagree beyond their uncertainty (*Known*)", "agreement_unassessable": "comparison impossible without uncertainty (*Unknown*)"}
        md += [f"| `{k}` | {n} | {meaning.get(k, '')} |" for k, n in sorted(counts.items())]
    if qartod and qartod.get("series"):
        md += ["", f"IOOS QARTOD tests ({qartod['qc_software']}); flags: 1 good, 2 not evaluated, 3 suspect, 4 fail.", "",
               "| Series | n | Tests run | Not evaluated | Aggregate flags |", "|---|---|---|---|---|"]
        for s in qartod["series"]:
            md.append(f"| {s['observation_type']} ({s['sensor_id']}) | {s['n']} | {', '.join(s['tests']) or 'none configured'} | "
                      f"{', '.join(s['not_evaluated']) or '-'} | {s['aggregate_counts']} |")
    md.append("")

    if rsn.get("findings"):
        md += ["## 5. Findings recorded with the evidence", "", "| Finding | Author | Label | Status |", "|---|---|---|---|"]
        md += [f"| {f['statement']} | {f['author']} ({f['author_kind']}{', ' + f['model'] if f.get('model') else ''}) | {f['epistemic']} | {f['status']} |"
               for f in rsn["findings"]]
        md.append("")

    md += ["## 6. Limitations", "",
           "- *Unknown:* calibration and uncertainty of every phone sensor, so no statement about accuracy is supported.",
           "- *Unknown:* whether the phone clock was synchronized; times are the phone's own.",
           "- *Assumed (by any analysis that combines them):* GPS fixes within the matching window describe where each reading was taken.",
           "- *Known:* resampled series omit samples; the omitted values remain in the attached original recording.",
           "- *Known:* integrity and authenticity establish custody of the data, not its scientific validity.", "",
           "## 7. Reproduction", "",
           f"Re-verify independently: `cursiv-verify package \"{package}\" --trust \"{trust or 'trust.json'}\" --science`", "",
           f"Package files are listed with SHA-256 in `{package.name}/manifest-sha256.txt` (BagIt, RFC 8493).", ""]
    n = iter(range(1, 100))                     # number sections in order (some are optional)
    md = [re.sub(r"^## \d+\. ", lambda _: f"## {next(n)}. ", line) for line in md]
    text = "\n".join(md)
    paths = {"markdown": out_dir / "dossier.md", "html": out_dir / "dossier.html", "csv": out_dir / "data.csv"}
    paths["markdown"].write_text(text, encoding="utf-8")
    paths["html"].write_text(to_html(text, title), encoding="utf-8")
    _write_csv(paths["csv"], obs)
    if pdf:
        p = to_pdf(paths["html"], out_dir / "dossier.pdf")
        if p:
            paths["pdf"] = p
    return {k: str(v) for k, v in paths.items()}


def _write_csv(path: Path, obs: list[dict]) -> None:
    import csv
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["observation_id", "robot_id", "observation_type", "sensor_time_utc", "value", "unit", "lat", "lon",
                    "horizontal_accuracy_m", "source", "synthetic"])
        for o in obs:
            m, l = o.get("measurement") or {}, o.get("location") or {}
            w.writerow([o["observation_id"], o["robot_id"], o["observation_type"], o.get("sensor_time") or "", m.get("value", ""),
                        m.get("unit", ""), l.get("lat", ""), l.get("lon", ""), l.get("horizontal_accuracy_m", "") or "",
                        o["provenance"]["source"], o["synthetic"]])


def to_html(md: str, title: str) -> str:
    """Small Markdown-to-HTML conversion for the dossier's own constructs (headings, tables, lists, quotes)."""
    def inline(s):
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        return re.sub(r"\*([^*]+)\*", r"<em>\1</em>", s)
    out, table, lst, quote = [], [], False, []
    def flush():
        nonlocal table, lst, quote
        if table:
            rows = [r for r in table if not re.fullmatch(r"\|[-| ]+\|", r)]
            cells = [[c.strip() for c in r.strip("|").split("|")] for r in rows]
            out.append("<table><thead><tr>" + "".join(f"<th>{inline(c)}</th>" for c in cells[0]) + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in r) + "</tr>" for r in cells[1:]) + "</tbody></table>")
            table = []
        if lst:
            out.append("</ul>")
            lst = False
        if quote:
            out.append("<blockquote>" + "<br>".join(inline(q) for q in quote) + "</blockquote>")
            quote = []
    for line in md.split("\n"):
        if line.startswith("|"):
            table.append(line)
            continue
        if line.startswith("> "):
            if table or lst:
                flush()
            quote.append(line[2:])
            continue
        if line.startswith("- "):
            if table or quote:
                flush()
            if not lst:
                out.append("<ul>")
                lst = True
            out.append(f"<li>{inline(line[2:])}</li>")
            continue
        flush()
        if line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.strip():
            out.append(f"<p>{inline(line)}</p>")
    flush()
    css = ("body{font-family:Georgia,serif;max-width:52rem;margin:2rem auto;padding:0 1rem;color:#111;line-height:1.45}"
           "h1,h2{font-family:Helvetica,Arial,sans-serif}h2{border-bottom:1px solid #999;margin-top:2rem}"
           "table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.6rem 0}td,th{border:1px solid #bbb;padding:.25rem .4rem;text-align:left;vertical-align:top}"
           "th{background:#eee}code{font-size:.8rem;word-break:break-all}blockquote{border-left:4px solid #555;margin:1rem 0;padding:.4rem .8rem;background:#f4f4f4}"
           "@media print{body{margin:0;max-width:none}}")
    return f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>{css}</style></head><body>{"".join(out)}</body></html>\n'


def _browsers() -> list[str]:
    cands = [os.environ.get("CURSIV_PDF_BROWSER", "")]
    for base in (os.environ.get("ProgramFiles(x86)", ""), os.environ.get("ProgramFiles", ""), os.environ.get("LOCALAPPDATA", "")):
        if base:
            cands += [str(Path(base) / "Microsoft/Edge/Application/msedge.exe"), str(Path(base) / "Google/Chrome/Application/chrome.exe")]
    cands += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
    cands += [shutil.which(n) or "" for n in ("msedge", "google-chrome", "chromium", "chromium-browser", "chrome")]
    return [c for c in cands if c and Path(c).exists()]


def to_pdf(html_path: Path, pdf_path: Path) -> Path | None:
    """Print the HTML to PDF with an installed Edge or Chrome (headless). None if no browser is found."""
    for exe in _browsers():
        try:
            subprocess.run([exe, "--headless", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
                            f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()],
                           capture_output=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if pdf_path.exists() and pdf_path.stat().st_size > 0:
            return pdf_path
    return None
