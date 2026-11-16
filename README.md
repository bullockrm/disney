# Disney World Trip Plan

A passcode-protected trip page. The plan is stored encrypted in `data/plan.enc.json` and is only decrypted in the browser after the passcode is entered.

## Use

Open the site and enter the passcode. Nothing is saved in the browser.

## Updating the plan

1. Edit the plan as JSON (structure follows `data/plan.enc.json` before encryption: `days`, `lightning`, `dining`, `rooms`, `flights`, `passes`, `open_items`).
2. Encrypt it with the passcode:

   ```
   PASSCODE='your-passcode' node scripts/encrypt.mjs plan.json data/plan.enc.json
   ```

3. Commit and push `data/plan.enc.json`. Do not commit the plaintext JSON.

Keep the plaintext file out of the repo. Use a longer passcode than a short PIN, because the encrypted file can be copied and guessed offline.
