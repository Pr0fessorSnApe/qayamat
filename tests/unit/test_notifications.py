import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


def test_notify_webhook_uses_discord_payload(monkeypatch):
    from core.notifications import notify_webhook

    called = {}

    class Resp:
        status_code = 204

    def fake_post(url, json=None, timeout=0, **kwargs):
        called["url"] = url
        called["json"] = json
        called["timeout"] = timeout
        return Resp()

    monkeypatch.setattr("core.notifications.requests.post", fake_post)
    assert notify_webhook("https://discord.com/api/webhooks/1/2", "scan complete") is True
    assert called["json"] == {"content": "scan complete"}


def test_notification_manager_sends_webhook_and_telegram(monkeypatch):
    from core.notifications import NotificationManager

    webhook_calls = []
    telegram_calls = []

    monkeypatch.setattr(
        "core.notifications.notify_webhook",
        lambda url, text: webhook_calls.append((url, text)) or True,
    )
    monkeypatch.setattr(
        "core.notifications.notify_telegram",
        lambda token, chat_id, text: telegram_calls.append((token, chat_id, text)) or True,
    )

    manager = NotificationManager(
        config={
            "notifications": {
                "webhook_urls": ["https://example.test/hook"],
                "telegram": {"bot_token": "bot-token", "chat_id": "12345"},
            }
        }
    )

    result = manager.send("scan finished")
    assert webhook_calls == [("https://example.test/hook", "scan finished")]
    assert telegram_calls == [("bot-token", "12345", "scan finished")]
    assert "telegram" in result["delivered"]
