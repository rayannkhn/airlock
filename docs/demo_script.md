# AirLock: Demo Script (5 minutes)

**Devices:** the laptop on the projector, your phone, and one paired
"receiver" phone held by a classmate. All have the app installed from
https://rayannkhn.github.io/airlock/ and are paired.

**Before the class:**
1. Install the app on each device, pair them, and do one test transfer.
2. Switch **airplane mode on** for every AirLock device.
3. On your phone, prepare the Send screen with the message `Pay Ali 100 PKR`.
4. On the laptop, open **Receive → 🧪 Attack lab** and check that all
   sliders are at 0 and both boxes are unticked.

---

## 1. Hook (20 s)
**Say:** "Last week you saw a USB stick empty a locked laptop in seconds.
That's exactly why secure sites ban USB. So how do you move a file into
a room like that? With light, and only light."

## 2. The broadcast (90 s): the whole room is the attacker
1. **Laptop → Send:** type a secret sentence, tick **Projector mode**,
   choose the classmate's phone as recipient, and start. The projector
   fills with QR codes.
2. **Say:** "Everyone, take out your phones and scan the screen."
   They get gibberish (`LB8%50*…`).
3. **The classmate's phone → Receive → Start camera.** The mosaic fills
   square by square, the checks tick green, and the secret appears.
4. **Say:** "Every one of you received exactly the same light. Only one
   phone could open it."

## 3. Hack me (90 s): encryption is not integrity
1. **Phone → Send** `Pay Ali 100 PKR` with **⚠ Insecure demo** ticked.
   **Laptop → Receive**, with *Mallory rewrites 100 → 999* and *Accept
   insecure demo* ticked.
   → The laptop shows **"Pay Ali 999 PKR"**. **Say:** "Mallory never
   read the message. She flipped bits in the ciphertext. Encryption
   alone didn't stop her."
2. **Send the same message again, insecure demo unticked** (real
   AirLock), with Mallory still rewriting.
   → *"Mallory’s edit was caught… AirLock delivers nothing rather than
   a lie."*
3. **Untick Mallory.** The genuine message arrives and the codes match.

## 4. Stress test (60 s): drag the sliders live
1. Send a longer file (about 2 KB). Drag **"Mallory flips bits" to 30%**.
   The red counter climbs, yet the mosaic still fills and the file
   arrives intact.
2. Drag **"injects fake pieces" to 10/s**. It aborts in about 3 seconds
   with "Someone is injecting fake data", and nothing is saved.

## 5. Close (30 s): "Can it be cracked?"
Drag the slider to **1 billion computers**: a weak password falls in under
a second, and an AirLock key would take 5.4 × 10¹¹ years. **Say:** "The
danger is never guessing the key. It's weak passwords, stolen devices and
bugs. AirLock was tested against these attacks; it's not proven secure."

---

## If something goes wrong
- **The projector is too far for the classmate's camera:** they walk
  closer, or you press **Slower**.
- **Camera trouble on the laptop:** the CLI fallback is
  `airlock receive --video <file>`. Say so honestly.
- **A replay message appears when you didn't want one:** start a fresh
  Send. Each new transfer is new.

## Likely questions
| Question | Answer |
|---|---|
| "Why did the insecure version accept 999?" | CTR encryption is malleable: XOR into the ciphertext flips the same bits of the plaintext. GCM's tag detects any change. |
| "Could Mallory just change the CRC?" | Yes, the attack lab does exactly that. CRC is for noise, not security; the GCM tag is the check. |
| "Why abort after 32 fakes?" | A flood means someone is actively attacking; continuing would waste time and memory. |
| "Is the 10¹¹ years real?" | It's an average with a generous 10 billion guesses per second per machine, at 128-bit security. |
