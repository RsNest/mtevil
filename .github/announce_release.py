import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


RELEASE_TAG = re.compile(
    r"v(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
NOTES_DIR = Path(__file__).resolve().parents[1] / "docs" / "releases"
TELEGRAM_MAX_LEN = 3800


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


def md_inline_to_html(text):
    """Convert basic Markdown inline spans (**bold**, `code`, [label](url)) to Telegram HTML."""
    code_spans = []

    def stash_code(m):
        idx = len(code_spans)
        code_spans.append(f"<code>{html.escape(m.group(1))}</code>")
        return f"\x00CODE{idx}\x00"

    masked = re.sub(r"`([^`]+)`", stash_code, text)
    escaped = html.escape(masked)
    escaped = re.sub(r"\[([^\]]+)\]\((https?://[^)]+)\)", r'<a href="\2">\1</a>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    for idx, code_html in enumerate(code_spans):
        escaped = escaped.replace(f"\x00CODE{idx}\x00", code_html)
    return escaped


def build_message(tag, release):
    notes_file = NOTES_DIR / f"{tag}.md"
    notes = notes_file.read_text(encoding="utf-8") if notes_file.is_file() else (release.get("body") or "")
    is_rc = "-rc." in tag
    badge = "🧪" if is_rc else "🚀"
    rc_label = " <i>(предварительный релиз)</i>" if is_rc else ""
    header = f"{badge} <b>mtevil {html.escape(tag)}</b>{rc_label}"

    blocks = []
    intro_lines = []
    current_bullets = []
    current_section = None
    seen_section = False

    def flush_section():
        if not current_bullets:
            return
        if current_section:
            blocks.append(f"<b>{html.escape(current_section)}</b>\n" + "\n".join(current_bullets))
        else:
            blocks.append("\n".join(current_bullets))
        current_bullets.clear()

    for raw_line in notes.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("# ") and not seen_section and not current_bullets:
            continue
        sec_match = re.match(r"^#{2,3}\s+(.+)$", line)
        if sec_match:
            flush_section()
            seen_section = True
            current_section = sec_match.group(1).strip()
            continue
        bullet = re.match(r"^[-*]\s+(.+)$", line)
        if bullet:
            seen_section = True
            summary = re.split(r"\s+by @\S+\s+in https?://", bullet[1], maxsplit=1)[0].strip()
            if not summary or summary.lower().startswith("full changelog") or summary.startswith(("@", "http")):
                continue
            current_bullets.append("• " + md_inline_to_html(summary))
            continue
        if not seen_section:
            quote = re.sub(r"^>\s*", "", line)
            intro_lines.append(md_inline_to_html(quote))

    flush_section()

    if not blocks:
        blocks.append("• Обновление опубликовано. Подробный список изменений доступен на GitHub.")

    update_cmd = "mtevilctl update --prerelease" if is_rc else "mtevilctl update"
    footer = (
        "<b>Как обновиться:</b>\n"
        f"<code>{update_cmd}</code>"
    )

    parts = [header]
    if intro_lines:
        parts.append("<i>" + " ".join(intro_lines) + "</i>")
    parts.extend(blocks)
    parts.append(footer)

    message = "\n\n".join(parts)
    if len(message) > TELEGRAM_MAX_LEN:
        # Trim middle blocks cleanly if a future changelog is unusually long.
        trimmed_parts = [header]
        if intro_lines:
            trimmed_parts.append("<i>" + " ".join(intro_lines) + "</i>")
        budget = TELEGRAM_MAX_LEN - len(header) - len(footer) - 64
        for blk in blocks:
            if len("\n\n".join(trimmed_parts)) + len(blk) <= budget:
                trimmed_parts.append(blk)
            else:
                break
        trimmed_parts.append(footer)
        message = "\n\n".join(trimmed_parts)
    return message


def send_telegram(token, chat, thread_id, text, release_url):
    payload = {
        "chat_id": chat,
        "message_thread_id": thread_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {
            "inline_keyboard": [
                [
                    {"text": "📦 Релиз на GitHub", "url": release_url},
                    {"text": "📖 Документация", "url": "https://github.com/RsNest/mtevil#readme"},
                ]
            ]
        },
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
        print("Telegram announcements cover SemVer release and pre-release tags only.")
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
