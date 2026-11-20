import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RELEASE_TAG = re.compile(r"v\d+\.\d+\.\d+(?:-rc\.\d+)?")
NOTES_DIR = Path(__file__).resolve().parents[1] / "docs" / "releases"


def github_api(endpoint, payload=None):
    command = ["gh", "api", endpoint]
    if payload is not None:
        command.extend(["--method", "PATCH", "--input", "-"])
    result = subprocess.run(
        command,
        input=json.dumps(payload) if payload is not None else None,
        encoding="utf-8",
        check=True,
        stdout=subprocess.PIPE,
    )
    return json.loads(result.stdout)


def build_message(tag, release):
    notes_file = NOTES_DIR / f"{tag}.md"
    notes = notes_file.read_text(encoding="utf-8") if notes_file.is_file() else (release.get("body") or "")
    heading = f"mtevil {tag}"
    bullets = []
    for line in notes.splitlines():
        bullet = re.match(r"^\s*[-*]\s+(.+)$", line)
        if not bullet:
            continue
        summary = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", bullet[1])
        summary = re.split(r"\s+by @\S+\s+in https?://", summary, maxsplit=1)[0]
        summary = summary.strip().replace("`", "")
        if not summary or summary.lower().startswith("full changelog") or summary.startswith(("@", "http")):
            continue
        bullets.append("• " + (summary if len(summary) <= 180 else summary[:177].rstrip() + "…"))
        if len(bullets) == 4:
            break
    if not bullets:
        bullets.append("Обновление опубликовано. Список изменений доступен на GitHub.")
    return heading + "\n\n" + "\n".join(bullets)


def send_telegram(token, chat, thread_id, text, release_url):
    payload = {
        "chat_id": chat,
        "message_thread_id": thread_id,
        "text": text,
        "reply_markup": {"inline_keyboard": [[{"text": "Релиз на GitHub", "url": release_url}]]},
    }
    request = Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.load(response)
    except HTTPError as error:
        delivery = "rejected" if 400 <= error.code < 500 else "unknown"
        return delivery, f"Telegram HTTP {error.code}"
    except (URLError, OSError, ValueError):
        return "unknown", "Telegram transport or response error"
    if isinstance(result, dict) and result.get("ok") is True:
        return "sent", str(result["result"]["message_id"])
    if isinstance(result, dict) and result.get("ok") is False:
        return "rejected", f"Telegram API {result.get('error_code', 'error')}"
    return "unknown", "Unexpected Telegram response"


def main(tag):
    if not RELEASE_TAG.fullmatch(tag):
        print("Telegram announcements cover stable and RC tags only.")
        return 0
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("::warning::TELEGRAM_BOT_TOKEN is missing. Release announcement was skipped.")
        return 0
    chat = os.environ.get("TELEGRAM_CHAT_ID", "@mtevil_chat")
    topic = os.environ.get("TELEGRAM_MESSAGE_THREAD_ID", "")
    if not re.fullmatch(r"@[A-Za-z0-9_]+|-\d+", chat) or not topic.isascii() or not topic.isdecimal() or int(topic) <= 1:
        print("::error::Set TELEGRAM_CHAT_ID and TELEGRAM_MESSAGE_THREAD_ID to a forum group and its release topic.")
        return 1
    thread_id = int(topic)
    marker = f"<!-- mtevil-telegram-announced {chat}/{thread_id} -->"
    releases = f"repos/{os.environ['GITHUB_REPOSITORY']}/releases"
    release = github_api(f"{releases}/tags/{tag}")
    if release.get("draft"):
        print("::error::Publish the GitHub release before announcing it.")
        return 1
    body = release.get("body") or ""
    if marker in body:
        print(f"Skipping {tag}: announcement already attempted in this Telegram topic.")
        return 0

    text = build_message(tag, release)
    release_endpoint = f"{releases}/{release['id']}"
    github_api(release_endpoint, {"body": body + "\n\n" + marker + "\n"})
    delivery, detail = send_telegram(token, chat, thread_id, text, release["html_url"])
    if delivery == "sent":
        print(f"Announced {tag} in Telegram topic {thread_id} (message {detail}).")
        return 0
    if delivery == "rejected":
        github_api(release_endpoint, {"body": body})
        print(f"::error::{detail}. Check the bot and channel permissions before retrying.")
    else:
        print(f"::error::{detail}. Check the channel before removing the announcement marker and retrying.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
