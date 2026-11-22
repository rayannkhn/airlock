# AirLock: Demo Script (about 4 minutes, one command)

Everything runs from one page in the browser. You only type:

```bash
cd ~/Documents/IS_PROJECT && source .venv/bin/activate && airlock ui
```

The page opens by itself and has four tabs: **How it works · 1 Send · 2 Receive · 3 Attacks**.

## Before the examiner arrives (5 minutes)

1. Run `airlock ui`. At the bottom of the page, click **↺ Reset demo**.
2. **1 · Send** → choose a small text file (for example `notes.txt` with one
   sentence) → click **⬇ For the phone (.gif, plays everywhere)**.
3. Copy the downloaded GIF to the phone with the USB cable. Set the phone
   to full brightness and open it in the gallery (it loops by itself).
4. Leave the browser on **How it works**.

## During the demo

| Time | Tab / click | Say this (in your own words) |
|---|---|---|
| 0:00–0:45 | **How it works** | "Alice sends Bob a file with no Wi-Fi or Bluetooth. Her phone shows it as QR codes and his camera reads them. Anyone can film that screen, so the file is *locked* so that only Bob can open it, and *sealed* so that Bob knows it came from Alice." Point at the five boxes: Lock → Seal → Show → Check → Confirm. |
| 0:45–1:15 | **1 · Send** (already prepared) | "This is what Alice did: the file is locked, sealed and cut into QR codes. Remember this code." Point at the big code and the moving QR. |
| 1:15–2:30 | **2 · Receive** → **▶ Start camera**, then show the GIF on the phone, 20–40 cm away | Let the checklist tick by itself and read the green lines aloud: "trusted sender… signature valid… not a replay… only Bob can unlock it." When the yellow box appears: "Last check is done by a person. The codes match," then click **✓ Yes**. "Only now is the file saved." |
| 2:30–2:50 | **2 · Receive** → **▶ Start camera** again, show the same GIF | "An attacker who filmed the screen plays it again…" The red result line: *already received, someone is replaying an old recording.* |
| 2:50–3:40 | **3 · Attacks** → **▶ Run all 6 attacks** | "Six attacks, scripted. Look at the second one: the same attack against a version **without** signatures *works*. The attacker turns 100 dollars into 9999. Against AirLock every attack is blocked." Open one "Show the technical log" if asked. |
| 3:40–4:00 | (talk) | "It's tested against these attacks, not proven secure. One honest limitation: in this one-way mode, if Bob's key were stolen later, old recordings could be read." |

## If something goes wrong

- **Camera won't read the phone:** move closer (the QR should fill about
  half of the picture), tilt the phone to remove glare, or make the video
  slower: `airlock send notes.txt --render out.gif --hold 12`.
- **Camera doesn't work at all:** on **2 · Receive**, click **Use a video
  or GIF file** and pick the same `.gif`. Say: *"Same video, decoded from the file
  instead of the live camera."* Every check runs exactly the same.
- **A transfer was already used** (red replay message when you didn't mean
  to show it): click **↺ Reset demo**, then prepare a new video on
  **1 · Send**.
- **Phone won't open the file:** use the `.gif` (every gallery and browser
  shows it). The `.mp4` only plays on phones that support MPEG-4 Part 2
  video, unless ffmpeg is installed on the laptop (`sudo apt install
  ffmpeg`), in which case AirLock writes H.264 automatically.

## Likely questions → where to point

| Question | Answer / where |
|---|---|
| "Why can't the attacker just read the QR codes?" | They can, but the codes only contain locked data. Attacks tab → Eavesdropper |
| "What if someone pretends to be Alice?" | Bob only trusts keys checked in person. Attacks → MITM vs AirLock |
| "Why compare codes if you have signatures?" | Defence in depth: the MITM log, scenario E, shows the codes differ even with all signature checks disabled |
| "How fast is it?" | About 500 bytes/s from a video file, and small files take seconds. Report §6.4 |
| "Why not RSA?" | Same security, a handshake 6.5× smaller (2 QR codes instead of 13). Report §6.2 |
| "Is the web page itself safe?" | It only listens on this laptop (127.0.0.1) and refuses requests from other websites and other host names |
