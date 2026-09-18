"""Generate reports: terminal, JSON, HTML, and score."""

import json
import html
from datetime import datetime

from topology_validator.constants import (
    SCORE_PENALTIES,
    GRADE_THRESHOLDS,
    GRADE_COLORS,
)


# ---------- Score ----------

def calculate_score(findings):
    """
    Compute a 0-100 security score and letter grade from findings.

    Args:
        findings (list): List of finding dicts.

    Returns:
        dict: {
            "score": int (0-100),
            "grade": str (A-F),
            "counts": {severity: int, ...},
            "deductions": {severity: points, ...},
        }
    """
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    deductions = {
        sev: counts.get(sev, 0) * penalty
        for sev, penalty in SCORE_PENALTIES.items()
    }
    total_deduction = sum(deductions.values())
    score = max(0, 100 - total_deduction)

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if score >= threshold:
            grade = letter
            break

    return {
        "score": score,
        "grade": grade,
        "counts": counts,
        "deductions": deductions,
    }


# ---------- Terminal report (unchanged) ----------

def generate_report(findings):
    """
    Print a formatted security report to stdout.

    Groups findings by severity (critical -> high -> medium -> low),
    prints a summary header, then each finding with its devices.
    """
    print("=" * 60)
    print("  NETWORK TOPOLOGY SECURITY REPORT")
    print("=" * 60)

    if not findings:
        print("\n  [OK] No security design flaws detected.")
        print("=" * 60)
        return

    score = calculate_score(findings)
    counts = score["counts"]

    total = len(findings)
    print(f"\n  Total findings: {total}")
    for severity in ("critical", "high", "medium", "low"):
        if severity in counts:
            print(f"    {severity.upper():<8} : {counts[severity]}")

    print(f"\n  Security Score: {score['score']} / 100   (Grade: {score['grade']})")

    for severity in ("critical", "high", "medium", "low"):
        group = [f for f in findings if f["severity"] == severity]
        if not group:
            continue

        print("\n" + "-" * 60)
        print(f"  {severity.upper()} ({len(group)})")
        print("-" * 60)

        for i, f in enumerate(group, start=1):
            devices_str = ", ".join(f["devices"])
            print(f"\n  {i}. {f['message']}")
            print(f"     Affected devices: {devices_str}")

    print("\n" + "=" * 60)


# ---------- JSON report ----------

def build_report_dict(findings, score, source_file):
    """
    Build a JSON-serializable report dict.
    """
    return {
        "source_file": source_file,
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "score": score["score"],
        "grade": score["grade"],
        "counts": score["counts"],
        "deductions": score["deductions"],
        "findings": findings,
    }


def generate_json_report(findings, score, source_file, output_path):
    """
    Write a JSON report to disk.

    Returns:
        str: The output_path.
    """
    report = build_report_dict(findings, score, source_file)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return output_path


# ---------- HTML report ----------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Topology Security Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f5f6fa; color: #2c3e50; margin: 0; padding: 40px; }}
  .container {{ max-width: 900px; margin: 0 auto; background: white;
                border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);
                padding: 32px; }}
  h1 {{ margin-top: 0; font-size: 22px; }}
  .meta {{ color: #7f8c8d; font-size: 13px; margin-bottom: 24px; }}
  .score {{ display: flex; align-items: center; gap: 24px;
             padding: 20px; border-radius: 8px; margin-bottom: 24px;
             background: #f8f9fa; }}
  .score-number {{ font-size: 48px; font-weight: 700; line-height: 1; }}
  .score-grade {{ font-size: 32px; font-weight: 700; }}
  .score-label {{ color: #7f8c8d; font-size: 13px; text-transform: uppercase;
                  letter-spacing: 1px; }}
  .counts {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .count-pill {{ padding: 8px 14px; border-radius: 999px; font-size: 13px;
                 font-weight: 600; color: white; }}
  .pill-critical {{ background: #8e44ad; }}
  .pill-high     {{ background: #e74c3c; }}
  .pill-medium   {{ background: #f39c12; }}
  .pill-low      {{ background: #3498db; }}
  .finding {{ border-left: 4px solid #ddd; padding: 12px 16px;
              margin-bottom: 12px; background: #fafbfc; border-radius: 4px; }}
  .finding.critical {{ border-left-color: #8e44ad; }}
  .finding.high     {{ border-left-color: #e74c3c; }}
  .finding.medium   {{ border-left-color: #f39c12; }}
  .finding.low      {{ border-left-color: #3498db; }}
  .finding .sev {{ font-size: 11px; font-weight: 700; letter-spacing: 1px;
                    text-transform: uppercase; color: #7f8c8d; }}
  .finding .msg {{ margin: 4px 0 6px 0; }}
  .finding .devices {{ font-size: 12px; color: #7f8c8d; font-family: monospace; }}
  .clean {{ text-align: center; padding: 40px 0; color: #27ae60;
             font-size: 18px; font-weight: 600; }}
  img.topology {{ max-width: 100%; border-radius: 6px; margin: 24px 0; }}
  h2 {{ margin-top: 32px; font-size: 16px; color: #34495e;
        border-bottom: 1px solid #ecf0f1; padding-bottom: 8px; }}
</style>
</head>
<body>
<div class="container">
  <h1>Network Topology Security Report</h1>
  <div class="meta">
    Source: <code>{source_file}</code> &middot; Generated: {generated_at}
  </div>

  <div class="score">
    <div>
      <div class="score-label">Security Score</div>
      <div class="score-number" style="color: {grade_color};">{score}/100</div>
    </div>
    <div>
      <div class="score-label">Grade</div>
      <div class="score-grade" style="color: {grade_color};">{grade}</div>
    </div>
  </div>

  {counts_html}

  {topology_html}

  {findings_html}
</div>
</body>
</html>
"""


def generate_html_report(findings, score, source_file, output_path, png_path=None):
    """
    Write a standalone HTML report to disk.

    Args:
        findings (list): List of finding dicts.
        score (dict): Output of calculate_score().
        source_file (str): Original topology filename.
        output_path (str): Where to write the HTML.
        png_path (str, optional): Path to a topology PNG to embed.

    Returns:
        str: The output_path.
    """
    grade_color = GRADE_COLORS.get(score["grade"], "#7f8c8d")

    # Counts pills
    if findings:
        pills = []
        for sev in ("critical", "high", "medium", "low"):
            count = score["counts"].get(sev, 0)
            if count:
                pills.append(
                    f'<span class="count-pill pill-{sev}">'
                    f'{count} {sev.upper()}</span>'
                )
        counts_html = '<div class="counts">' + "".join(pills) + "</div>"
    else:
        counts_html = ""

    # Topology image
    if png_path:
        png_abs = png_path  # keep as-is; assumes relative to HTML location
        topology_html = f'<h2>Topology</h2><img class="topology" src="{html.escape(png_abs)}" alt="Topology diagram">'
    else:
        topology_html = ""

    # Findings list
    if not findings:
        findings_html = '<div class="clean">[OK] No security design flaws detected.</div>'
    else:
        blocks = []
        for sev in ("critical", "high", "medium", "low"):
            for f in findings:
                if f["severity"] != sev:
                    continue
                devices = html.escape(", ".join(f["devices"]))
                message = html.escape(f["message"])
                blocks.append(
                    f'<div class="finding {sev}">'
                    f'<div class="sev">{sev}</div>'
                    f'<div class="msg">{message}</div>'
                    f'<div class="devices">Affected devices: {devices}</div>'
                    f'</div>'
                )
        findings_html = "<h2>Findings</h2>" + "".join(blocks)

    report = _HTML_TEMPLATE.format(
        source_file=html.escape(source_file),
        generated_at=datetime.utcnow().isoformat(timespec="seconds") + "Z",
        score=score["score"],
        grade=score["grade"],
        grade_color=grade_color,
        counts_html=counts_html,
        topology_html=topology_html,
        findings_html=findings_html,
    )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    return output_path