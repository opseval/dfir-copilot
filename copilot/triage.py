#!/usr/bin/env python3
"""Deterministic DFIR triage assistant — NO LLM.
Runs the pre-extraction rules over tool output and produces the analyst-facing report directly:
verdict (from the highest-severity finding), the priority finding, all findings with evidence, and
the suggested next commands (already encoded in each finding). This is the 'no-model' product path.

Usage:  triage.py < tool_output.txt      (or)   triage.py file.txt
"""
import sys, json
sys.path.insert(0, __import__("os").path.dirname(__file__))
import preextract as PX

SEV_TO_VERDICT = {"malicious": "MALICIOUS", "suspicious": "SUSPICIOUS", "benign-signal": "BENIGN"}

def triage(raw):
    F = PX.extract(raw)
    if not F:
        return {"verdict": "undetermined",
                "report": "VERDICT: UNDETERMINED — no known indicators matched.\n"
                          "Manual review of the raw output is required (no rule fired).",
                "findings": []}
    verdict = SEV_TO_VERDICT.get(F[0]["severity"], "REVIEW")
    top = F[0]
    out = [f"VERDICT: {verdict}",
           f"PRIORITY: [{top['severity']}] {top['indicator']}",
           f"   why: {top['why']}",
           "FINDINGS:"]
    for f in F:
        out.append(f"  - [{f['severity']}] {f['indicator']}  (evidence: {f['evidence']})")
    out.append("SUGGESTED NEXT COMMANDS:")
    for f in F[:3]:
        out.append(f"  - {f['next']}")
    return {"verdict": verdict.lower().replace("benign", "benign"), "report": "\n".join(out), "findings": F}

if __name__ == "__main__":
    raw = open(sys.argv[1]).read() if sys.argv[1:] else sys.stdin.read()
    print(triage(raw)["report"])
