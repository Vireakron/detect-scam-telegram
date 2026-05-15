# Telegram Account Scam Detector

A small Telethon-based scam detector for a personal Telegram account. It listens for incoming messages and flags suspicious scam patterns such as fake delivery notices, crypto scams, impersonation attempts, suspicious links, and blacklisted domains.

This is a user account client, not a Telegram bot.

## Author

Created by [Vireakron](https://github.com/Vireakron). Website: [ronvireak.com](https://ronvireak.com).

## Safety Notes

- Do not commit `.env`.
- Do not commit `*.session` files. They can contain Telegram login session data.
- Start with `DRY_RUN=true` until you trust your rules.
- Detection rules can create false positives. Review the behavior before enabling delete, warning, or block actions.
- If you previously exposed Telegram API credentials, replace them before publishing your project.

## Setup

1. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

4. Get Telegram API credentials from <https://my.telegram.org> and fill in `.env`:

   ```env
   TELEGRAM_API_ID=123456
   TELEGRAM_API_HASH=your_api_hash_here
   ```

5. Run the detector:

   ```bash
   python main.py
   ```

On the first run, Telethon will ask you to log in. That creates a local `.session` file, which is ignored by Git.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `DRY_RUN` | `true` | Logs detections without deleting, warning, or blocking. |
| `AUTO_DELETE` | `true` | Deletes suspicious messages when `DRY_RUN=false`. |
| `AUTO_WARN` | `true` | Sends a warning reply when `DRY_RUN=false`. |
| `AUTO_BLOCK` | `false` | Blocks private senders when `DRY_RUN=false`. |
| `BLACKLIST_PATH` | `blacklist.txt` | File containing blocked domains or URL fragments. |
| `TELEGRAM_SESSION_NAME` | `scam_detector_session` | Local Telethon session filename. |

## Customizing Rules

- Add known scam domains to `blacklist.txt`.
- Edit `SCAM_KEYWORDS` in `main.py` for phrase-based detection.
- Edit `SUSPICIOUS_TLDS` in `main.py` for risky domain endings.
- Edit `SCAM_PATTERNS` in `main.py` for regex-based detection.

## Before Publishing

Run these checks before pushing to a public repository:

```bash
find . -name "*.session" -o -name ".env"
git status --short
```

Only publish source files, docs, examples, and safe sample data. Never publish real credentials or Telegram session files.
