import ssl
import socket
import datetime
import requests
import os

def check_ssl_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.datetime.utcnow()).days
                return days_until_expiry
    except Exception as e:
        print(f"Error checking SSL for {domain}: {e}")
        return None

def send_slack_alert(domain, days_until_expiry, slack_webhook):
    alert_message = (
        f":rotating_light: **SSL Certificate Expiry Alert** :rotating_light:\n"
        f"Domain: `{domain}`\n"
        f"Certificate will expire in: **{days_until_expiry} days**"
    )

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": alert_message
                }
            }
        ]
    }

    response = requests.post(slack_webhook, json=payload)
    if response.status_code != 200:
        print(f"Failed to send Slack alert for {domain}")

if __name__ == "__main__":
    domains = ["google.com", "facebook.com"]  
    slack_webhook = os.environ["SLACK_WEBHOOK_URL"]  

    for domain in domains:
        days_until_expiry = check_ssl_expiry(domain)
        if days_until_expiry is not None and days_until_expiry <= 30:
            send_slack_alert(domain, days_until_expiry, slack_webhook)
