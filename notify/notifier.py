"""
通知模块 - 推送情报到各种渠道
"""
import os
import requests
from dotenv import load_dotenv

load_dotenv()


def send_webhook(title, content):
    """
    通过 Webhook 推送（企业微信/钉钉/飞书通用）
    
    在 .env 中配置 WEBHOOK_URL
    """
    url = os.getenv("WEBHOOK_URL", "")
    if not url:
        print("⚠️ 未配置 WEBHOOK_URL，跳过推送")
        return False

    payload = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "text": content,
        },
    }

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        print("✅ Webhook 推送成功")
        return True
    except Exception as e:
        print(f"❌ Webhook 推送失败: {e}")
        return False


def send_email(subject, body):
    """
    通过邮件发送报告（SMTP）
    
    在 .env 中配置 SMTP_HOST/PORT/USER/PASS/NOTIFY_EMAIL
    """
    import smtplib
    from email.mime.text import MIMEText

    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "465"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASS", "")
    notify_email = os.getenv("NOTIFY_EMAIL", "")

    if not all([smtp_host, smtp_user, notify_email]):
        print("⚠️ 邮件配置不完整，跳过")
        return False

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = notify_email

    try:
        with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        print(f"✅ 邮件已发送到 {notify_email}")
        return True
    except Exception as e:
        print(f"❌ 邮件发送失败: {e}")
        return False
