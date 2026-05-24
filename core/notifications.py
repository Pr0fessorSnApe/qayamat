"""Notification helpers for scan lifecycle events."""

from __future__ import annotations

import os
from typing import Any, Dict, List

import requests


def _coerce_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def notify_webhook(url: str, text: str) -> bool:
    """Send a message to a Discord/Slack/generic webhook endpoint."""
    if not url:
        return False

    try:
        if "hooks.slack.com" in url:
            response = requests.post(url, json={"text": text}, timeout=10)
        elif "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url:
            response = requests.post(url, json={"content": text}, timeout=10)
        elif "ntfy.sh/" in url:
            response = requests.post(
                url,
                data=text.encode("utf-8"),
                headers={"Title": "QAYAMAT Scan Complete"},
                timeout=10,
            )
        else:
            response = requests.post(
                url,
                json={"message": text, "text": text, "content": text},
                timeout=10,
            )
        return response.status_code < 300
    except Exception:
        return False


def notify_telegram(bot_token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram bot message."""
    if not bot_token or not chat_id:
        return False
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=10,
        )
        return response.status_code < 300
    except Exception:
        return False


class NotificationManager:
    """Collect configured channels and fan out a notification message."""

    def __init__(self, config: Dict[str, Any] | None = None, logger=None):
        self.config = config or {}
        self.logger = logger

    def _webhook_urls(self) -> List[str]:
        notifications = self.config.get("notifications", {})
        monitor = self.config.get("monitor", {})
        urls: List[str] = []
        urls.extend(_coerce_list(monitor.get("webhook_url")))
        urls.extend(_coerce_list(notifications.get("webhook_urls")))
        urls.extend(_coerce_list(os.getenv("NOTIFY_WEBHOOK_URLS", "")))

        env_map = {
            "discord_webhook": "DISCORD_WEBHOOK_URL",
            "slack_webhook": "SLACK_WEBHOOK_URL",
        }
        for key, env_name in env_map.items():
            value = notifications.get(key) or os.getenv(env_name, "")
            if value:
                urls.append(value)

        # Preserve the legacy single-webhook setting if users still rely on it.
        legacy = os.getenv("WEBHOOK_URL", "")
        if legacy:
            urls.append(legacy)

        deduped: List[str] = []
        seen = set()
        for url in urls:
            if url and url not in seen:
                seen.add(url)
                deduped.append(url)
        return deduped

    def _telegram_config(self) -> tuple[str, str]:
        notifications = self.config.get("notifications", {})
        telegram = notifications.get("telegram", {}) or {}
        bot_token = telegram.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")
        chat_id = telegram.get("chat_id") or os.getenv("TELEGRAM_CHAT_ID", "")
        return bot_token, chat_id

    def send(self, text: str) -> Dict[str, Any]:
        delivered: List[str] = []
        failed: List[str] = []

        for url in self._webhook_urls():
            if notify_webhook(url, text):
                delivered.append(url)
            else:
                failed.append(url)

        bot_token, chat_id = self._telegram_config()
        if bot_token and chat_id:
            if notify_telegram(bot_token, chat_id, text):
                delivered.append("telegram")
            else:
                failed.append("telegram")

        if self.logger:
            if delivered:
                self.logger.info("Notification delivery complete", delivered=delivered, failed=failed)
            elif failed:
                self.logger.warning("Notification delivery failed", failed=failed)

        return {"delivered": delivered, "failed": failed}

    def has_destinations(self) -> bool:
        bot_token, chat_id = self._telegram_config()
        return bool(self._webhook_urls() or (bot_token and chat_id))
