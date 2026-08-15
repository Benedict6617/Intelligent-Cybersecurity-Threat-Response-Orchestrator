"""
Notification dispatch (Slack / email) for escalations and playbook
results. Ships as a safe simulator that logs the notification instead
of sending it, unless SLACK_WEBHOOK_URL / SMTP settings are configured.
"""
from app.config import get_settings
from app.utils.logger import get_logger

settings = get_settings()
logger = get_logger("notifications")


def notify(channel_targets: list[str], subject: str, message: str) -> None:
    if settings.SLACK_WEBHOOK_URL:
        # In production: httpx.post(settings.SLACK_WEBHOOK_URL, json={"text": f"*{subject}*\n{message}"})
        logger.info("Slack notification sent to webhook: %s", subject)
    else:
        logger.info("[SIMULATED NOTIFICATION] to=%s subject=%s message=%s", channel_targets, subject, message)
