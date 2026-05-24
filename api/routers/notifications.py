"""QAYAMAT — Notifications Router"""

import os
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.notifications import NotificationManager, notify_telegram, notify_webhook

router = APIRouter()


class SlackMessage(BaseModel):
    message: str
    webhook_url: str = ""


class DiscordMessage(BaseModel):
    content: str
    webhook_url: str = ""


class TelegramMessage(BaseModel):
    message: str
    bot_token: str = ""
    chat_id: str = ""


@router.post("/notifications/discord")
async def send_discord(req: DiscordMessage):
    webhook = req.webhook_url or os.getenv("DISCORD_WEBHOOK_URL", "")
    if not webhook:
        raise HTTPException(status_code=400, detail="No Discord webhook URL configured")
    if not notify_webhook(webhook, req.content):
        raise HTTPException(status_code=502, detail="Discord delivery failed")
    return {"sent": True}


@router.post("/notifications/slack")
async def send_slack(req: SlackMessage):
    webhook = req.webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")
    if not webhook:
        raise HTTPException(status_code=400, detail="No Slack webhook URL configured")
    if not notify_webhook(webhook, req.message):
        raise HTTPException(status_code=502, detail="Slack delivery failed")
    return {"sent": True}


@router.post("/notifications/telegram")
async def send_telegram(req: TelegramMessage):
    bot_token = req.bot_token or os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = req.chat_id or os.getenv("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        raise HTTPException(status_code=400, detail="Telegram bot token and chat ID are required")
    if not notify_telegram(bot_token, chat_id, req.message):
        raise HTTPException(status_code=502, detail="Telegram delivery failed")
    return {"sent": True}


@router.post("/notifications/test")
async def send_test_notification(req: SlackMessage):
    manager = NotificationManager()
    result = manager.send(req.message)
    if not result["delivered"]:
        raise HTTPException(status_code=502, detail="No configured notification channel accepted the message")
    return result
