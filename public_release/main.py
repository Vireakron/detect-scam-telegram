import os
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from dotenv import load_dotenv
from telethon import TelegramClient, events
from telethon.errors import RPCError


BASE_DIR = Path(__file__).resolve().parent

SCAM_KEYWORDS = [
    "courier",
    "unable to deliver",
    "package today",
    "redelivery fee",
    "postal service",
    "shipping update",
    "track your parcel",
    "delivery failed",
    "unpaid shipping",
    "reschedule delivery",
    "dhl update",
    "fedex alert",
    "earn money",
    "crypto investment",
    "double your money",
    "guaranteed profit",
    "binance giveaway",
    "airdrop",
    "mining pool",
    "usdt bonus",
    "trust wallet",
    "seed phrase",
    "private key",
    "passive income",
    "telegram admin",
    "official support",
    "account verification",
    "security alert",
    "violation of terms",
    "confirm your identity",
    "copyright infringement",
    "account will be deleted",
    "customer service",
    "is this you?",
    "wrong number but",
    "professional assistant",
    "business opportunity",
    "free iphone",
    "claim reward",
    "congratulations winner",
    "gift card",
    "cash prize",
]

SUSPICIOUS_TLDS = [
    ".zip",
    ".mov",
    ".top",
    ".biz",
    ".xyz",
    ".click",
    ".win",
    ".icu",
    ".monster",
]

SCAM_PATTERNS = [
    (re.compile(r"\$\s?\d{1,}\.\d{2}"), "money amount"),
    (re.compile(r"\$\s?\d{3,}"), "large money amount"),
    (re.compile(r"t\.me/\+[\w-]{10,}"), "private Telegram invite"),
    (re.compile(r"wa\.me/\d+"), "WhatsApp contact link"),
    (re.compile(r"([a-z]\s?\.){3,}"), "spaced-out text"),
]


@dataclass(frozen=True)
class Settings:
    api_id: int
    api_hash: str
    session_name: str
    blacklist_path: Path
    dry_run: bool
    auto_delete: bool
    auto_warn: bool
    auto_block: bool


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def path_from_env(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else BASE_DIR / value


def load_settings() -> Settings:
    load_dotenv(BASE_DIR / ".env")

    return Settings(
        api_id=int(required_env("TELEGRAM_API_ID")),
        api_hash=required_env("TELEGRAM_API_HASH"),
        session_name=os.getenv("TELEGRAM_SESSION_NAME", str(BASE_DIR / "scam_detector_session")),
        blacklist_path=path_from_env("BLACKLIST_PATH", "blacklist.txt"),
        dry_run=env_bool("DRY_RUN", True),
        auto_delete=env_bool("AUTO_DELETE", True),
        auto_warn=env_bool("AUTO_WARN", True),
        auto_block=env_bool("AUTO_BLOCK", False),
    )


def normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def script_name(char: str) -> str:
    name = unicodedata.name(char, "")
    if "LATIN" in name:
        return "LATIN"
    if "CYRILLIC" in name:
        return "CYRILLIC"
    if "GREEK" in name:
        return "GREEK"
    return ""


def has_mixed_confusable_scripts(text: str) -> bool:
    scripts = {script_name(char) for char in text}
    scripts.discard("")
    return "LATIN" in scripts and bool(scripts & {"CYRILLIC", "GREEK"})


def extract_links(text: str) -> list[str]:
    return re.findall(r"https?://[^\s<>()]+", text)


def load_blacklist(path: Path) -> list[str]:
    try:
        return [
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except FileNotFoundError:
        return []


def detect_scam(text: str, blacklist_entries: Iterable[str] = ()) -> list[str]:
    if not text:
        return []

    reasons: list[str] = []
    text_lower = normalize_text(text)

    matched_keywords = [keyword for keyword in SCAM_KEYWORDS if keyword in text_lower]
    if matched_keywords:
        reasons.append(f"keyword: {matched_keywords[0]}")

    if has_mixed_confusable_scripts(text):
        reasons.append("mixed Latin/confusable characters")

    for pattern, reason in SCAM_PATTERNS:
        if pattern.search(text_lower):
            reasons.append(reason)

    for link in extract_links(text_lower):
        hostname = urlparse(link).hostname or ""

        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reasons.append(f"suspicious domain: {hostname}")

        if any(entry in link for entry in blacklist_entries):
            reasons.append(f"blacklisted link: {hostname or link}")

    return reasons


def is_scam(text: str, blacklist_entries: Iterable[str] = ()) -> bool:
    return bool(detect_scam(text, blacklist_entries))


async def handle_event(event, client: TelegramClient, settings: Settings, blacklist_entries: list[str]) -> None:
    if event.out:
        return

    reasons = detect_scam(event.raw_text, blacklist_entries)
    if not reasons:
        return

    sender = await event.get_sender()
    name = getattr(sender, "first_name", None) or "User"
    reason_text = ", ".join(reasons)

    if settings.dry_run:
        print(f"DRY RUN: Possible scam from {name} ({event.sender_id}): {reason_text}")
        return

    print(f"Possible scam from {name} ({event.sender_id}): {reason_text}")

    try:
        if settings.auto_delete:
            await event.delete()

        if settings.auto_warn:
            await event.respond(
                f"Security filter: a suspicious message from {name} was detected and handled."
            )

        if settings.auto_block and event.is_private:
            await client.block_user(event.sender_id)
            print(f"Blocked private sender: {event.sender_id}")
    except RPCError as error:
        print(f"Telegram API error while handling message: {error}")
    except Exception as error:
        print(f"Unexpected error while handling message: {error}")


def main() -> None:
    settings = load_settings()
    blacklist_entries = load_blacklist(settings.blacklist_path)

    client = TelegramClient(settings.session_name, settings.api_id, settings.api_hash)

    @client.on(events.NewMessage)
    async def on_new_message(event):
        await handle_event(event, client, settings, blacklist_entries)

    mode = "dry run" if settings.dry_run else "active protection"
    print(f"Telegram scam detector running in {mode} mode.")
    client.start()
    client.run_until_disconnected()


if __name__ == "__main__":
    main()
