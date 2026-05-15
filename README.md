# Telegram Account Scam Detector

Public-safe release for a Telethon-based Telegram scam detector.

Use the cleaned project package here:

[public_release](public_release)

## Author

Created by [Vireakron](https://github.com/Vireakron). Website: [ronvireak.com](https://ronvireak.com).

## Safety

- Real Telegram API credentials are not stored in this repository.
- Telegram `.session` files are ignored and should never be committed.
- The public code starts in dry-run mode by default.
- Read [public_release/README.md](public_release/README.md) before enabling delete, warn, or block actions.

## Quick Start

```bash
cd public_release
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python main.py
```
