#!/usr/bin/env python3
"""Stage the IP Sentinel demo video, one on-camera event per command.

    python3 demo_prep.py reset        # fresh inventor folder + empty ledger (run before every take)
    python3 demo_prep.py revise       # edit claims.txt and add a v4 CAD file
    python3 demo_prep.py late-delete  # delete a file after you scanned (edge case: commit is refused)
    python3 demo_prep.py tamper       # forge block 0 of the ledger, the way a careful forger would
    python3 demo_prep.py restore      # undo the forgery
    python3 demo_prep.py status       # print what the ledger looks like right now

Everything lives in ./demo_data next to this script. Restart the dashboard after `reset`.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from ip_sentinel import CHAIN_FILE_NAME, IPSentinel, compute_block_hash

HERE = Path(__file__).resolve().parent
DEMO_ROOT = HERE / "demo_data"
WORKSPACE = DEMO_ROOT / "solidcell-prototype"
LEDGER_DIR = DEMO_ROOT / "ledger"
CHAIN = LEDGER_DIR / CHAIN_FILE_NAME
BACKUP = DEMO_ROOT / ".custody_chain.before-tamper.json"
MARKER = DEMO_ROOT / ".ip-sentinel-demo"
PORT = 8787

CLAIMS_V1 = """\
SolidCell - draft claims (working copy, not filed)

1. A solid-state battery cell comprising a sulfide electrolyte layer between a
   lithium-metal anode and a high-nickel cathode, wherein the electrolyte layer
   is between 18 and 30 micrometres thick.

2. The cell of claim 1, wherein the anode/electrolyte interface carries a
   lithium-indium interlayer of less than 2 micrometres.

3. The cell of claim 1, further comprising a stack pressure of 2 to 5 MPa
   maintained by a spring-loaded housing.
"""

CLAIM_4 = """
4. The cell of claim 3, wherein the housing applies the stack pressure through a
   wave-spring sized so that pressure varies by less than 10% over 500 cycles.
"""

FILES = {
    "notes/2026-10-02_lab-journal.md": """\
# Lab journal - 2 Oct 2026

Pressed a 25 um sulfide electrolyte film for the first time without cracking.
Key change: dried the powder at 120 C for 4 h before pressing.

Next: try the Li-In interlayer on the anode side to stop dendrites at the edge.
""",
    "notes/2026-10-19_lab-journal.md": """\
# Lab journal - 19 Oct 2026

Li-In interlayer (~1.5 um) works. Cell 7 ran 180 cycles before fading.
Edge dendrites gone. Stack pressure seems to matter more than expected:
cells at 4 MPa beat cells at 1 MPa by a wide margin.

Idea: spring-loaded housing so pressure stays constant as the cell breathes.
""",
    "notes/scratch-ideas.txt": """\
scratch - delete later
- wave spring vs disc spring?
- ask the machinist about 0.2 mm tolerance on the housing lid
""",
    "drafts/claims.txt": CLAIMS_V1,
    "drafts/provisional-application_draft.md": """\
# Provisional patent application - DRAFT

## Title
Pressure-stabilised solid-state battery cell with a lithium-indium interlayer

## Background
Solid-state cells lose capacity when stack pressure drifts as electrodes expand
and contract during cycling...

## Summary
A sulfide-electrolyte cell whose housing holds stack pressure within a narrow
band, combined with a thin Li-In interlayer that suppresses edge dendrites.
""",
    "data/cycle-test_2026-10-28.csv": """\
cell_id,stack_pressure_mpa,interlayer,cycles_to_80pct,notes
C05,1.0,none,42,edge dendrites
C06,1.0,Li-In,95,
C07,4.0,Li-In,180,
C08,4.0,Li-In,176,
C09,4.0,none,61,edge dendrites
""",
    "cad/cell-housing_v3.step": """\
ISO-10303-21;
HEADER;
FILE_DESCRIPTION(('SolidCell housing v3 - spring-loaded lid'),'2;1');
FILE_NAME('cell-housing_v3.step','2026-10-24T16:02:00',('SolidCell'),(''),'','','');
FILE_SCHEMA(('AUTOMOTIVE_DESIGN { 1 0 10303 214 1 1 1 1 }'));
ENDSEC;
DATA;
#1=CARTESIAN_POINT('',(0.,0.,0.));
#2=DIRECTION('',(0.,0.,1.));
#3=CYLINDRICAL_SURFACE('housing_body',#4,10.5);
#4=AXIS2_PLACEMENT_3D('',#1,#2,$);
#5=CIRCLE('lid_seat',#4,10.2);
ENDSEC;
END-ISO-10303-21;
""",
    "sketches/electrode-stack.svg": """\
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 200" font-family="sans-serif" font-size="12">
  <rect x="40" y="30" width="240" height="22" fill="#9aa5b1"/><text x="290" y="45">lid + wave spring</text>
  <rect x="40" y="60" width="240" height="26" fill="#d9822b"/><text x="290" y="77">cathode</text>
  <rect x="40" y="90" width="240" height="14" fill="#f2c94c"/><text x="290" y="101">sulfide electrolyte</text>
  <rect x="40" y="106" width="240" height="4" fill="#6fcf97"/><text x="290" y="112">Li-In interlayer</text>
  <rect x="40" y="114" width="240" height="26" fill="#828282"/><text x="290" y="131">Li metal anode</text>
</svg>
""",
}

HOUSING_V4 = FILES["cad/cell-housing_v3.step"].replace("v3", "v4").replace(
    "spring-loaded lid", "wave-spring lid, 0.2 mm lid tolerance"
).replace("10.2);", "10.2);\n#6=CIRCLE('wave_spring_seat',#4,9.8);")


def _write(rel: str, text: str) -> None:
    path = WORKSPACE / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _launch_hint() -> str:
    return f"python3 sentinel_gui.py --storage {LEDGER_DIR} --port {PORT}"


def reset() -> None:
    if DEMO_ROOT.exists():
        if not MARKER.exists():
            sys.exit(f"Refusing to delete {DEMO_ROOT}: it was not created by demo_prep.py")
        shutil.rmtree(DEMO_ROOT)
    LEDGER_DIR.mkdir(parents=True)
    MARKER.write_text("created by demo_prep.py\n", encoding="utf-8")
    for rel, text in FILES.items():
        _write(rel, text)
    print(f"Fresh demo folder: {WORKSPACE}  ({len(FILES)} files)")
    print(f"Empty ledger:      {LEDGER_DIR}")
    print("\nRestart the dashboard so it forgets the old session, then paste the folder path on camera:")
    print(f"  {_launch_hint()}")


def revise() -> None:
    claims = WORKSPACE / "drafts/claims.txt"
    if CLAIM_4.strip() in claims.read_text(encoding="utf-8"):
        sys.exit("Already revised. Run `reset` to start over.")
    claims.write_text(CLAIMS_V1 + CLAIM_4, encoding="utf-8")
    _write("cad/cell-housing_v4.step", HOUSING_V4)
    print("Modified drafts/claims.txt (added claim 4)")
    print("Added    cad/cell-housing_v4.step")


def late_delete() -> None:
    target = WORKSPACE / "notes/scratch-ideas.txt"
    if not target.exists():
        sys.exit("notes/scratch-ideas.txt is already gone.")
    target.unlink()
    print("Deleted notes/scratch-ideas.txt (after your scan). Now click Commit: it should be refused.")


def tamper() -> None:
    data = json.loads(CHAIN.read_text(encoding="utf-8"))
    blocks = data["blocks"]
    if len(blocks) < 2:
        sys.exit("Commit at least two blocks first: a forged block 0 is only caught by block 1's link.")
    if BACKUP.exists():
        sys.exit("Ledger is already tampered. Run `restore` first.")
    # The forger wants claim 4 to look like it existed at the first commit.
    revised = next((e for e in blocks[1]["entries"] if e["relative_path"] == "drafts/claims.txt"), None)
    original = next((e for e in blocks[0]["entries"] if e["relative_path"] == "drafts/claims.txt"), None)
    if not revised or not original or revised["sha256_hash"] == original["sha256_hash"]:
        sys.exit("Expected claims.txt to change between block 0 and block 1. Run `revise` before the second commit.")
    shutil.copy2(CHAIN, BACKUP)
    original["sha256_hash"] = revised["sha256_hash"]
    original["size_bytes"] = revised["size_bytes"]
    blocks[0]["block_hash"] = compute_block_hash(blocks[0])  # a careful forger re-seals the block
    CHAIN.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Forged block 0: claims.txt now carries the hash of the version with claim 4,")
    print("and block 0's own hash was recomputed. Block 1 still links to the original.")
    print("The dashboard re-checks every 5 seconds.")


def restore() -> None:
    if not BACKUP.exists():
        sys.exit("Nothing to restore.")
    shutil.copy2(BACKUP, CHAIN)
    BACKUP.unlink()
    print("Ledger restored to the honest version.")


def status() -> None:
    sentinel = IPSentinel(storage_dir=LEDGER_DIR)
    chain = sentinel.get_chain()
    print(f"Workspace: {WORKSPACE}")
    print(f"Blocks:    {len(chain)}")
    for block in chain:
        print(f"  #{block['index']}  {block['timestamp']}  {block['file_count']} files  {block['block_hash'][:16]}…")
    print(f"Integrity: {sentinel.verify_integrity()}")
    print(f"Tampered backup present: {BACKUP.exists()}")
    print(f"\nDashboard: {_launch_hint()}")


COMMANDS = {"reset": reset, "revise": revise, "late-delete": late_delete,
            "tamper": tamper, "restore": restore, "status": status}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    COMMANDS[sys.argv[1]]()
