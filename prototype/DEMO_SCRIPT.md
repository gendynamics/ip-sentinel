# IP Sentinel demo video: run sheet

About 3 minutes of narration at a relaxed pace. The flow follows your proposal's user flow (section 4) and shows the edge case from section 9 working. If the video limit is shorter, cut the scenes marked **(cut first)**.

Every step below was rehearsed end to end in Chrome at 1920×1080 and at 125% zoom.

---

## Before you record

1. **Stop any running dashboard** (Ctrl+C in its terminal).
2. Reset the demo data:

   ```sh
   cd /Applications/Ip-sentinel/prototype
   python3 demo_prep.py reset
   ```

3. Start the dashboard. It opens your default browser on port 8787:

   ```sh
   python3 sentinel_gui.py --storage /Applications/Ip-sentinel/prototype/demo_data/ledger
   ```

4. **Browser:** use Chrome (it's what was rehearsed). Zoom to **125%** (Cmd + twice), hide the bookmarks bar (Cmd+Shift+B), close other tabs, and make the window fill the recording area. Dark theme is the default.
5. **Clipboard:** copy this folder path. You'll paste it on camera:
   `/Applications/Ip-sentinel/prototype/demo_data/solidcell-prototype`
6. **Finder:** open a window at `demo_data/solidcell-prototype/cad` so you can drag `cell-housing_v3.step` into the browser in scene 6.
7. **Terminal:** keep a second terminal in `/Applications/Ip-sentinel/prototype` for the `demo_prep.py` cues. Either keep it off camera and cut around it, or show it with a large font.
8. Turn on Do Not Disturb.
9. Do one full dry run. Then repeat steps 1–3 before the real take, so the ledger, activity log and workspace selection all start empty.

> The Author field is remembered by the browser. After a dry run it will be prefilled. Clear it if you want to type your name on camera.

---

## Scenes

| # | Time | On screen | You do |
| --- | --- | --- | --- |
| 1 | 0:00 | Overview, empty ledger | Nothing. Let it sit. |
| 2 | 0:20 | Workspace | Click **Workspace**, paste the path, **Set workspace**, then **Scan**. |
| 3 | 0:45 | Workspace → dialog → Chain | Scroll down, type your name in **Author**, click **Commit 8 files to ledger**, pause on the dialog, click **Commit block**, then open **Chain**. |
| 4 | 1:05 | Workspace | Terminal: `python3 demo_prep.py revise`. Back in the browser: **Workspace** → **Scan**. |
| 5 | 1:25 | Workspace → Chain | Terminal: `python3 demo_prep.py late-delete`. Scroll down and click **Commit 9 files…** → **Commit block**. The yellow warning appears. Click **Rescan**, then commit again (8 files). Open **Chain**. |
| 6 | 1:50 | Verify | Drag `cell-housing_v3.step` from Finder onto the drop zone. Click **Run integrity audit**. |
| 7 | 2:10 | Export | Click **Download proof package**. Point at the yellow clock notice. |
| 8 | 2:30 | Overview → Chain → Verify | Terminal: `python3 demo_prep.py tamper`. Wait about 5 seconds; the dashboard turns red by itself. Open **Chain**, then **Verify** → **Run integrity audit**. |
| 9 | 2:55 | Overview or a title card | Off camera: `python3 demo_prep.py restore`. Close. |

Scene 4 also works if you edit `drafts/claims.txt` live in a text editor instead of running `revise`. The `revise` command adds a fourth claim and a new file, `cad/cell-housing_v4.step`.

---

## Narration

**1 · The problem** (Overview, empty)
> Solo inventors keep their most valuable work in a folder: lab notes, CAD files, patent drafts. When a question comes up about who invented what, and when, a folder of files whose dates anyone can edit proves very little. IP Sentinel builds a tamper-evident custody log of that folder, and the files never leave your storage.

**2 · Choose the folder, preview** (Workspace, scan results)
> I point it at my project folder: lab journals, a CAD housing, test data and a draft provisional patent. Scan computes a SHA-256 fingerprint of every file. Nothing has been written yet. This is a preview of exactly what will be recorded.

**3 · Approve, genesis block** (dialog, then Chain)
> I add my name and commit. It asks me to confirm before writing anything. Block zero, the genesis block, now holds all eight fingerprints, my name and a timestamp.

**4 · A revision** (Workspace, rescan)
> A week later I add a fourth claim and a new version of the housing. I rescan: one new, one modified, seven unchanged. It knows exactly what changed.

**5 · Edge case: files change after review** (yellow warning, then Chain) **(cut first)**
> Now something changes after I've reviewed the scan: a scratch file gets deleted. When I commit, IP Sentinel rescans first, sees the folder no longer matches what I approved, and refuses. Nothing is written. I rescan, review and commit. Block one stores the fingerprint of block zero. That's the chain.

**6 · Prove a file** (Verify)
> Months later I need to show this CAD file existed. I drop it in. It's hashed right here in the browser, never uploaded, and matched to block zero with the date it was first recorded. The full audit passes: every block, every link.

**7 · Proof package and anchoring** (Export)
> For a third party, I export one proof package: every block, every fingerprint, and the steps to check it. It contains no file contents. The timestamps come from this machine's clock, so the final step is to anchor the head hash with an independent timestamp service. That single hash is the only thing that ever leaves the device.

**8 · The forger** (red dashboard, broken link, FAIL)
> Now I'll play the forger. This script edits block zero so claim four looks like it existed on day one. It even recomputes block zero's fingerprint to cover its tracks. Within seconds the dashboard catches it: block one still points at the original block zero, so the link breaks. New blocks are refused on top of a tampered history. And a forger who rebuilt every block from scratch would end up with a head hash that no longer matches one you've anchored.

**9 · Where this goes** (Overview or title card)
> That's the custody engine, working today. On a UGREEN AI NAS, the Skill is designed to run these same steps with the NAS's own tools: file-agent to find files, document-agent for metadata, and knowledge-agent to store the chain. Everything stays read-only until you confirm. Next comes testing on real NAS hardware. IP Sentinel: proof of what you made and when, without your ideas leaving home.

---

## Shots worth holding for a beat

- **Scene 3 dialog:** "Links to: Genesis marker (64 zeros)". It explains chaining without a word.
- **Scene 5:** the Chain page with the green "✓ Linked" next to block #1's pointer to block #0.
- **Scene 8:** the dashed red line between the blocks with "× Broken", and the red **Tampered** pill in the top-right corner.

## If something goes wrong

| Symptom | Fix |
| --- | --- |
| Workspace is already set, or old activity shows at the start | You didn't restart the dashboard after `reset`. Ctrl+C, then start it again. |
| `revise` says "Already revised" | Run `reset` and restart the dashboard. |
| `tamper` says to commit two blocks first | A commit was skipped. Run `reset` and start over. |
| `tamper` says "already tampered" | Run `restore` first. |
| Dashboard didn't turn red | It re-checks every 5 seconds. Wait, or click **Run integrity audit**. |
| "Port 8787 is busy" | The dashboard picks a free port instead. Use the URL it prints. |
| You want a retake | Ctrl+C the dashboard, `reset`, start it again, and reload the browser tab. |

`python3 demo_prep.py status` prints the current blocks and the integrity result at any point.
