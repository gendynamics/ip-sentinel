import shutil
import tempfile
import json
import os

from ip_sentinel import IPSentinel

print("=== [STARTING MASTER DEMO: IP SENTINEL] ===\n")

# 1. Fresh state setup
demo_storage = './demo_sentinel_data'
if os.path.exists(demo_storage):
    shutil.rmtree(demo_storage)

demo_sentinel = IPSentinel(storage_dir=demo_storage)

with tempfile.TemporaryDirectory() as demo_workspace:
    print(f"[Step 1] Initialized clean local workspace: {demo_workspace}")

    # Create initial intellectual property documents
    cad_path = os.path.join(demo_workspace, "battery_v1.cad")
    notes_path = os.path.join(demo_workspace, "draft_patent.txt")

    with open(cad_path, "w") as f:
        f.write("ORIGINAL SPEC: Volts = 3.7, Chemistry = Solid-State")
    with open(notes_path, "w") as f:
        f.write("Inventor's journal entry: initial research breakthrough on cell density.")

    print("Generated initial prototype documents.")

    # 2. Scan and commit initial states
    print("\n[Step 2] Scanning workspace for new IP...")
    scan_0 = demo_sentinel.scan_and_discover(demo_workspace)
    for item in scan_0:
        print(f"  - Found file: {item['file_name']} (SHA-256: {item['sha256_hash'][:16]}...)")

    block_0 = demo_sentinel.commit_custody_log(scan_0, author="Solo Founder <founder@domain.local>")
    print(f"\n[IP Sentinel] Generated Genesis Block (Block #0).")
    print(f"  -> Timestamp: {block_0['timestamp']}")
    print(f"  -> Previous Link: {block_0['previous_block_hash'][:16]}...")

    # 3. Simulate updates (The Revision Stage)
    print("\n[Step 3] Modifying battery_v1.cad with optimization updates...")
    with open(cad_path, "w") as f:
        f.write("OPTIMIZED SPEC: Volts = 3.82, Chemistry = Solid-State with silicon-anode")

    print("Scanning workspace for detected changes...")
    scan_1 = demo_sentinel.scan_and_discover(demo_workspace)
    for item in scan_1:
        print(f"  - Found file: {item['file_name']} (SHA-256: {item['sha256_hash'][:16]}...)")

    block_1 = demo_sentinel.commit_custody_log(scan_1, author="Solo Founder <founder@domain.local>")
    print(f"\n[IP Sentinel] Generated Increment Block (Block #1).")
    print(f"  -> Timestamp: {block_1['timestamp']}")
    print(f"  -> Linked to Block 0 Hash: {block_1['previous_block_hash'][:16]}...")

    # 4. Verify cryptographic chain integrity
    print("\n[Step 4] Auditing database integrity status...")
    status = demo_sentinel.verify_integrity()
    print(f"  -> Audit Result: {status}")

    # 5. Export Proof Package
    print("\n[Step 5] Exporting verifiable timestamp proof package...")
    proof = demo_sentinel.generate_verification_package()
    print("===============================================")
    print(json.dumps(proof, indent=2))
    print("===============================================")

print("\n=== [MASTER DEMO COMPLETE: SUCCESS] ===")
