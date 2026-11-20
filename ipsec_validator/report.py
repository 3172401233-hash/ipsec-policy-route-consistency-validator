"""Human-readable rendering of validation verdicts."""

from typing import List

from .engine import Verdict


def format_verdicts(verdicts: List[Verdict], now: float) -> str:
    lines = ["evaluation time: %.0f" % now, ""]
    for verdict in verdicts:
        status = "OK" if verdict.ok else "FAULT"
        lines.append("[%s] %s" % (status, verdict.cell.describe()))
        lines.append(
            "  policy_action=%s final_action=%s policy=%s sa=%s"
            % (
                verdict.policy_action,
                verdict.final_action,
                verdict.policy_id or "-",
                ("0x%08x" % verdict.sa_spi) if verdict.sa_spi is not None else "-",
            )
        )
        if verdict.route:
            lines.append("  route: %s" % verdict.route)
        for fault in verdict.faults:
            lines.append("  fault: %s" % fault)
        for note in verdict.notes:
            lines.append("  note:  %s" % note)
        lines.append("")
    faulty = sum(1 for v in verdicts if not v.ok)
    lines.append(
        "summary: %d range(s), %d ok, %d with faults"
        % (len(verdicts), len(verdicts) - faulty, faulty)
    )
    return "\n".join(lines)
