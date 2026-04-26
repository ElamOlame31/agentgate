"""
Compliance Report Generator.

Produces a professional PDF or CSV audit report suitable for SOC2 / ISO 27001 reviews.

PDF sections:
  1. Cover page    -  period, generated timestamp, org stats
  2. Executive summary  -  permit/deny/escalate breakdown, threat count, top agents
  3. Threat incidents   -  every request that raised attack flags (detailed)
  4. Full decision log  -  every request, color-coded, paginated
  5. Per-agent summary  -  one row per agent with totals

CSV: flat export of the full decision log with all fields.
"""

import csv
import io
import json
import time
from datetime import datetime, timezone
from fpdf import FPDF, XPos, YPos

# ── Colors (RGB) ──────────────────────────────────────────────────────────────
C_BG        = (10,  11,  13)
C_PANEL     = (15,  17,  23)
C_BORDER    = (30,  37,  48)
C_TEXT      = (232, 237, 242)
C_TEXT2     = (139, 150, 163)
C_GREEN     = (0,   208, 132)
C_RED       = (255, 59,  92)
C_ORANGE    = (255, 149, 0)
C_CYAN      = (0,   212, 255)
C_WHITE     = (255, 255, 255)
C_DARK_ROW  = (20,  25,  34)
C_ALT_ROW   = (26,  32,  44)


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _decision_color(decision: str) -> tuple:
    return {"PERMIT": C_GREEN, "DENY": C_RED, "ESCALATE": C_ORANGE, "PENDING": C_CYAN}.get(decision, C_TEXT2)


_UNICODE_MAP = str.maketrans({
    "—": "--",   # em dash
    "–": "-",    # en dash
    "‘": "'",    # left single quote
    "’": "'",    # right single quote
    "“": '"',    # left double quote
    "”": '"',    # right double quote
    "…": "...",  # ellipsis
    "→": "->",   # right arrow
    "←": "<-",   # left arrow
    "·": ".",    # middle dot
})

def _safe(s: str) -> str:
    """Replace characters outside latin-1 range so fpdf Helvetica doesn't crash."""
    s = s.translate(_UNICODE_MAP)
    return s.encode("latin-1", errors="replace").decode("latin-1")

def _truncate(s: str, n: int) -> str:
    s = _safe(s)
    return s if len(s) <= n else s[:n - 1] + "..."


class AgentGatePDF(FPDF):
    def __init__(self, period_from: str, period_to: str):
        super().__init__(orientation="L", unit="mm", format="A4")
        self.period_from = period_from
        self.period_to   = period_to
        self.set_auto_page_break(auto=True, margin=14)
        self.set_margins(14, 14, 14)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_fill_color(*C_PANEL)
        self.rect(0, 0, 297, 12, style="F")
        self.set_text_color(*C_CYAN)
        self.set_font("Helvetica", "B", 8)
        self.set_xy(14, 3)
        self.cell(80, 6, "AGENTGATE  -  Compliance Audit Report", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_text_color(*C_TEXT2)
        self.set_font("Helvetica", "", 7)
        self.set_xy(120, 3)
        self.cell(80, 6, f"Period: {self.period_from}  -  {self.period_to}", new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_xy(240, 3)
        self.cell(40, 6, f"Page {self.page_no()}", align="R")

    def footer(self):
        self.set_y(-10)
        self.set_text_color(*C_TEXT2)
        self.set_font("Helvetica", "", 7)
        generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        self.cell(0, 6, f"Generated {generated}  .  CONFIDENTIAL  -  For internal audit use only", align="C")


def _cover_page(pdf: AgentGatePDF, stats: dict, period_from: str, period_to: str, row_count: int):
    pdf.add_page()
    # Dark background
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 0, 297, 210, style="F")

    # Accent bar
    pdf.set_fill_color(*C_CYAN)
    pdf.rect(0, 0, 6, 210, style="F")

    # Title
    pdf.set_xy(18, 30)
    pdf.set_text_color(*C_CYAN)
    pdf.set_font("Helvetica", "B", 28)
    pdf.cell(200, 14, "AGENTGATE", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(18)
    pdf.set_text_color(*C_TEXT)
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(200, 8, "Compliance Audit Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(18)
    pdf.set_text_color(*C_TEXT2)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(200, 7, "Policy Decision Point  -  Agent Authorization & Security", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Divider
    pdf.set_draw_color(*C_BORDER)
    pdf.set_line_width(0.3)
    pdf.line(18, 74, 279, 74)

    # Period
    pdf.set_xy(18, 80)
    pdf.set_text_color(*C_TEXT2)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(60, 6, "REPORT PERIOD")
    pdf.set_xy(18, 87)
    pdf.set_text_color(*C_TEXT)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(120, 7, f"{period_from}  ->  {period_to}")

    # Stats boxes
    box_data = [
        ("TOTAL REQUESTS", str(row_count),       C_CYAN),
        ("PERMITTED",      str(stats["permits"]), C_GREEN),
        ("BLOCKED",        str(stats["denials"]), C_RED),
        ("ESCALATED",      str(stats.get("escalations", 0)), C_ORANGE),
        ("THREATS FLAGGED",str(stats["attack_flags_raised"]), C_RED),
        ("AVG TRUST SCORE",f'{stats["avg_trust_score"]}/100', C_CYAN),
    ]
    bx, by, bw, bh, gap = 18, 110, 41, 28, 5
    for i, (label, value, color) in enumerate(box_data):
        x = bx + i * (bw + gap)
        pdf.set_fill_color(*C_PANEL)
        pdf.set_draw_color(*C_BORDER)
        pdf.set_line_width(0.2)
        pdf.rect(x, by, bw, bh, style="FD")
        pdf.set_xy(x, by + 5)
        pdf.set_text_color(*color)
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(bw, 10, value, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_x(x)
        pdf.set_text_color(*C_TEXT2)
        pdf.set_font("Helvetica", "", 6.5)
        pdf.cell(bw, 5, label, align="C")

    # Classification footer
    pdf.set_xy(18, 190)
    pdf.set_fill_color(*C_RED)
    pdf.set_text_color(*C_WHITE)
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(263, 7, "  CONFIDENTIAL  -  FOR INTERNAL AUDIT USE ONLY", fill=True)


def _section_header(pdf: AgentGatePDF, title: str):
    pdf.set_fill_color(*C_PANEL)
    pdf.rect(14, pdf.get_y(), 269, 9, style="F")
    pdf.set_text_color(*C_CYAN)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_x(17)
    pdf.cell(260, 9, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def _executive_summary(pdf: AgentGatePDF, rows: list[dict], stats: dict):
    pdf.add_page()
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 0, 297, 210, style="F")

    pdf.set_xy(14, 16)
    _section_header(pdf, "EXECUTIVE SUMMARY")
    pdf.ln(4)

    # Threat breakdown
    threats = [r for r in rows if json.loads(r.get("attack_flags", "[]"))]
    agents_seen = {}
    for r in rows:
        aid = r["agent_id"]
        agents_seen.setdefault(aid, {"permit": 0, "deny": 0, "escalate": 0, "flags": 0})
        d = r["decision"]
        if d == "PERMIT":    agents_seen[aid]["permit"] += 1
        elif d == "DENY":    agents_seen[aid]["deny"] += 1
        elif d == "ESCALATE":agents_seen[aid]["escalate"] += 1
        if json.loads(r.get("attack_flags", "[]")):
            agents_seen[aid]["flags"] += 1

    # Summary text
    pdf.set_xy(14, pdf.get_y())
    pdf.set_text_color(*C_TEXT)
    pdf.set_font("Helvetica", "", 9)
    total = len(rows)
    deny_pct  = round(stats["denials"] / max(total, 1) * 100, 1)
    threat_pct = round(len(threats) / max(total, 1) * 100, 1)
    pdf.multi_cell(269, 5.5,
        f"This report covers {total} authorization requests processed by the AgentGate Policy Decision Point "
        f"during the specified period. {stats['denials']} requests ({deny_pct}%) were blocked. "
        f"{len(threats)} requests ({threat_pct}%) raised security flags. "
        f"Average agent trust score: {stats['avg_trust_score']}/100.",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT
    )
    pdf.ln(4)

    # Per-agent table
    _section_header(pdf, "PER-AGENT BREAKDOWN")
    pdf.ln(2)

    col_w = [70, 30, 30, 30, 30, 79]
    headers = ["AGENT ID", "PERMITTED", "BLOCKED", "ESCALATED", "FLAGS RAISED", "DECLARED PURPOSE"]
    pdf.set_fill_color(*C_BORDER)
    pdf.set_text_color(*C_TEXT2)
    pdf.set_font("Helvetica", "B", 7)
    for i, h in enumerate(headers):
        pdf.set_x(14 + sum(col_w[:i]))
        pdf.cell(col_w[i], 7, h, fill=True)
    pdf.ln(7)

    for idx, (aid, cnts) in enumerate(sorted(agents_seen.items())):
        fill_color = C_DARK_ROW if idx % 2 == 0 else C_ALT_ROW
        pdf.set_fill_color(*fill_color)
        pdf.set_text_color(*C_TEXT)
        pdf.set_font("Helvetica", "", 7.5)
        row_y = pdf.get_y()
        values = [
            _truncate(aid, 28),
            str(cnts["permit"]),
            str(cnts["deny"]),
            str(cnts["escalate"]),
            str(cnts["flags"]),
            "",
        ]
        for i, v in enumerate(values):
            color = C_TEXT
            if i == 1 and cnts["permit"] > 0: color = C_GREEN
            if i == 2 and cnts["deny"] > 0:   color = C_RED
            if i == 3 and cnts["escalate"] > 0: color = C_ORANGE
            if i == 4 and cnts["flags"] > 0:  color = C_RED
            pdf.set_xy(14 + sum(col_w[:i]), row_y)
            pdf.set_text_color(*color)
            pdf.set_fill_color(*fill_color)
            pdf.cell(col_w[i], 6, v, fill=True)
        pdf.ln(6)
        if pdf.get_y() > 185:
            pdf.add_page()
            pdf.set_fill_color(*C_BG)
            pdf.rect(0, 0, 297, 210, style="F")


def _threat_incidents(pdf: AgentGatePDF, rows: list[dict]):
    threats = [r for r in rows if json.loads(r.get("attack_flags", "[]"))]
    if not threats:
        return

    pdf.add_page()
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 0, 297, 210, style="F")
    pdf.set_xy(14, 16)
    _section_header(pdf, f"THREAT INCIDENTS  ({len(threats)} flagged requests)")
    pdf.ln(4)

    for idx, r in enumerate(threats):
        if pdf.get_y() > 175:
            pdf.add_page()
            pdf.set_fill_color(*C_BG)
            pdf.rect(0, 0, 297, 210, style="F")
            pdf.set_xy(14, 16)

        flags = json.loads(r.get("attack_flags", "[]"))
        dec = r["decision"]
        dec_color = _decision_color(dec)

        # Incident block
        start_y = pdf.get_y()
        pdf.set_fill_color(*C_PANEL)
        pdf.set_draw_color(*C_BORDER)
        # Will draw rect after we know height
        pdf.set_xy(17, start_y + 2)

        # Header row
        pdf.set_text_color(*dec_color)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(18, 5, dec)
        pdf.set_text_color(*C_CYAN)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(65, 5, _truncate(r["agent_id"], 26))
        pdf.set_text_color(*C_TEXT2)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.cell(50, 5, f"{r['action'].upper()}  {_truncate(r['resource'], 30)}")
        pdf.set_text_color(*C_TEXT2)
        pdf.cell(40, 5, _ts(r["timestamp"]))
        pdf.set_text_color(*C_CYAN)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.cell(30, 5, f"Score: {r['trust_score']}/100")
        pdf.ln(5)

        # Flags
        pdf.set_xy(17, pdf.get_y())
        pdf.set_text_color(*C_RED)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(269, 4.5, _safe("  [!]  " + "   .   ".join(flags)), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Explanation
        expl = r.get("explanation", "")
        if expl:
            pdf.set_xy(17, pdf.get_y())
            pdf.set_text_color(*C_TEXT2)
            pdf.set_font("Helvetica", "", 7)
            pdf.multi_cell(269, 4, _truncate(expl, 200), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        end_y = pdf.get_y()
        pdf.rect(14, start_y, 269, end_y - start_y + 1, style="FD")
        pdf.ln(3)


def _full_decision_log(pdf: AgentGatePDF, rows: list[dict]):
    pdf.add_page()
    pdf.set_fill_color(*C_BG)
    pdf.rect(0, 0, 297, 210, style="F")
    pdf.set_xy(14, 16)
    _section_header(pdf, f"FULL DECISION LOG  ({len(rows)} requests)")
    pdf.ln(2)

    col_w = [38, 46, 22, 56, 22, 55, 30]
    headers = ["TIMESTAMP", "AGENT", "DECISION", "RESOURCE", "ACTION", "FLAGS", "TRUST SCORE"]

    def draw_table_header():
        pdf.set_fill_color(*C_BORDER)
        pdf.set_text_color(*C_TEXT2)
        pdf.set_font("Helvetica", "B", 6.5)
        for i, h in enumerate(headers):
            pdf.set_x(14 + sum(col_w[:i]))
            pdf.cell(col_w[i], 6, h, fill=True)
        pdf.ln(6)

    draw_table_header()

    for idx, r in enumerate(rows):
        if pdf.get_y() > 188:
            pdf.add_page()
            pdf.set_fill_color(*C_BG)
            pdf.rect(0, 0, 297, 210, style="F")
            pdf.set_xy(14, 16)
            draw_table_header()

        dec = r["decision"]
        fill_color = C_DARK_ROW if idx % 2 == 0 else C_ALT_ROW
        dec_color  = _decision_color(dec)
        flags_raw  = json.loads(r.get("attack_flags", "[]"))
        flag_str   = _truncate(", ".join(flags_raw), 38) if flags_raw else " - "

        pdf.set_fill_color(*fill_color)
        row_y = pdf.get_y()

        values = [
            datetime.fromtimestamp(r["timestamp"], tz=timezone.utc).strftime("%m-%d %H:%M:%S"),
            _truncate(r["agent_id"], 20),
            dec,
            _truncate(r["resource"], 28),
            r["action"].upper(),
            flag_str,
            f'{r["trust_score"]}/100',
        ]
        colors = [C_TEXT2, C_TEXT, dec_color, C_TEXT, C_TEXT, (C_RED if flags_raw else C_TEXT2), C_CYAN]

        for i, (v, c) in enumerate(zip(values, colors)):
            pdf.set_xy(14 + sum(col_w[:i]), row_y)
            pdf.set_text_color(*c)
            pdf.set_font("Helvetica", "B" if i == 2 else "", 7)
            pdf.set_fill_color(*fill_color)
            pdf.cell(col_w[i], 5.5, v, fill=True)
        pdf.ln(5.5)


# ── Public API ────────────────────────────────────────────────────────────────

def generate_pdf(rows: list[dict], stats: dict, from_ts: float, to_ts: float) -> bytes:
    period_from = _ts(from_ts)
    period_to   = _ts(to_ts)

    pdf = AgentGatePDF(period_from, period_to)
    pdf.set_compression(True)

    _cover_page(pdf, stats, period_from, period_to, len(rows))
    _executive_summary(pdf, rows, stats)
    _threat_incidents(pdf, rows)
    _full_decision_log(pdf, rows)

    return bytes(pdf.output())


def generate_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    fieldnames = [
        "timestamp_utc", "agent_id", "action", "resource",
        "decision", "trust_score", "identity_score", "delegation_score",
        "purpose_score", "behavioral_score", "resource_sensitivity",
        "attack_flags", "explanation"
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        writer.writerow({
            "timestamp_utc": _ts(r["timestamp"]),
            "agent_id": r["agent_id"],
            "action": r["action"],
            "resource": r["resource"],
            "decision": r["decision"],
            "trust_score": r["trust_score"],
            "identity_score": r.get("identity_score", ""),
            "delegation_score": r.get("delegation_score", ""),
            "purpose_score": r.get("purpose_score", ""),
            "behavioral_score": r.get("behavioral_score", ""),
            "resource_sensitivity": r.get("resource_sensitivity", ""),
            "attack_flags": r.get("attack_flags", "[]"),
            "explanation": r.get("explanation", ""),
        })
    return buf.getvalue()
