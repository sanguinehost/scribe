import requests
import time
import sys
import argparse

BASE_URL = "https://api.staging.scribe.sanguinehost.com/api"
AUTH_URL = f"{BASE_URL}/auth/login"
ME_URL = f"{BASE_URL}/auth/me"
HEALTH_URL = f"{BASE_URL}/health"

# Credentials for the test user provided by USER
TEST_USER = {
    "identifier": "paperboy",
    "password": "foxtrotter"
}

def get_auth_session():
    session = requests.Session()
    print(f"Logging in as {TEST_USER['identifier']}...")
    try:
        resp = session.post(AUTH_URL, json=TEST_USER, timeout=10)
        if resp.status_code == 200:
            print("Login successful.")
            return session
        else:
            print(f"Login failed: {resp.text}")
            return None
    except Exception as e:
        print(f"Login exception: {e}")
        return None

def trigger_auth_failures(count=25, spoof_ip=False):
    print(f"Triggering {count} auth failures at {AUTH_URL}...")
    payload = {
        "identifier": "alert_test_user",
        "password": "definitely_wrong_password"
    }

    for i in range(count):
        headers = {}
        if spoof_ip:
            # Use a stable IP so that grouping by client_ip exceeds the threshold
            fake_ip = "203.0.113.55"
            headers["X-Forwarded-For"] = fake_ip

        try:
            resp = requests.post(AUTH_URL, json=payload, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code} (IP: {headers.get('X-Forwarded-For', 'default')})")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.2)

def trigger_auth_polling(count=105, authenticated=False, spoof_ip=False):
    session = None
    if authenticated:
        session = get_auth_session()
        if not session:
            print("Skipping authenticated polling due to login failure.")
            return

    requester = session if session else requests
    print(f"Triggering {count} auth polling requests at {ME_URL} (Auth: {authenticated})...")

    for i in range(count):
        headers = {}
        if spoof_ip:
            fake_ip = "198.51.100.22"
            headers["X-Forwarded-For"] = fake_ip

        try:
            resp = requester.get(ME_URL, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_error_rate(count=25, spoof_ip=False):
    print(f"Triggering {count} health checks to see if we can get errors at {HEALTH_URL}...")
    for i in range(count):
        headers = {}
        if spoof_ip:
            headers["X-Forwarded-For"] = "192.0.2.88"

        try:
            resp = requests.get(HEALTH_URL, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.2)

def trigger_webhook_failures(count=8):
    WEBHOOK_URL = f"{BASE_URL}/payment/webhook/paddle"
    print(f"Triggering {count} webhook signature failures at {WEBHOOK_URL}...")
    headers = {
        "Paddle-Signature": "invalid_signature_for_testing",
        "Content-Type": "application/json"
    }
    payload = {"foo": "bar"}

    for i in range(count):
        try:
            resp = requests.post(WEBHOOK_URL, json=payload, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.2)

def trigger_500_errors(count=25, spoof_ip=False):
    ERROR_URL = f"{BASE_URL}/health/error"
    print(f"Triggering {count} Internal Server Errors (500) at {ERROR_URL}...")

    for i in range(count):
        headers = {}
        if spoof_ip:
            headers["X-Forwarded-For"] = "192.0.2.99"
        try:
            resp = requests.get(ERROR_URL, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_high_latency(count=5):
    SLOW_URL = f"{BASE_URL}/health/slow"
    print(f"Triggering {count} high latency requests (>2s) at {SLOW_URL}...")

    for i in range(count):
        try:
            start = time.time()
            resp = requests.get(SLOW_URL, timeout=15)
            duration = time.time() - start
            print(f"Request {i+1}: Status {resp.status_code} (took {duration:.2f}s)")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_credit_anomaly():
    ANOMALY_URL = f"{BASE_URL}/health/anomaly"
    print(f"Triggering credit operation anomaly at {ANOMALY_URL}...")
    try:
        resp = requests.get(ANOMALY_URL, timeout=10)
        print(f"Response: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"Failed to trigger anomaly: {e}")

def trigger_ttft(count=6):
    TTFT_URL = f"{BASE_URL}/health/ttft"
    print(f"Triggering {count} LLM TTFT anomalies (>3s) at {TTFT_URL}...")
    for i in range(count):
        try:
            resp = requests.get(TTFT_URL, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_llm_failure(count=6):
    LLM_FAIL_URL = f"{BASE_URL}/health/llm_failure"
    print(f"Triggering {count} LLM generation failures at {LLM_FAIL_URL}...")
    for i in range(count):
        try:
            resp = requests.get(LLM_FAIL_URL, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_db_failure(count=12):
    DB_FAIL_URL = f"{BASE_URL}/health/db_error"
    print(f"Triggering {count} database error mocks at {DB_FAIL_URL}...")
    for i in range(count):
        try:
            resp = requests.get(DB_FAIL_URL, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_payment_failure(count=5):
    PAYMENT_FAIL_URL = f"{BASE_URL}/health/payment_fail"
    print(f"Triggering {count} payment failure mocks at {PAYMENT_FAIL_URL}...")
    for i in range(count):
        try:
            resp = requests.get(PAYMENT_FAIL_URL, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_frontend_errors(count=5, spoof_ip=False):
    TELEMETRY_URL = f"{BASE_URL}/telemetry"
    print(f"Triggering {count} frontend client errors at {TELEMETRY_URL}...")
    payload = {
        "component": "ChatContainer",
        "error_message": "TypeError: Cannot read properties of undefined (reading 'text')",
        "route": "/chat/123",
        "severity": "fatal"
    }
    for i in range(count):
        headers = {}
        if spoof_ip:
            headers["X-Forwarded-For"] = "192.168.1.10"
        try:
            resp = requests.post(TELEMETRY_URL, json=payload, headers=headers, timeout=10)
            print(f"Request {i+1}: Status {resp.status_code}")
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
        time.sleep(0.1)

def trigger_diagnostics():
    ROOT_BASE = "https://api.staging.scribe.sanguinehost.com"
    print(f"Running diagnostics...")
    endpoints = [
        f"{ROOT_BASE}/probe/ping",
        f"{ROOT_BASE}/probe/root",
        f"{ROOT_BASE}/ping",
        f"{BASE_URL}/ping",
        f"{BASE_URL}/health",
        f"{BASE_URL}/health/debug",
        f"{BASE_URL}/health/error",
        f"{BASE_URL}/health/slow",
        f"{BASE_URL}/health/anomaly",
        f"{BASE_URL}/health/ttft",
        f"{BASE_URL}/payment/webhook/paddle",
    ]

    for url in endpoints:
        try:
            print(f"Testing {url}...")
            if "webhook" in url:
                resp = requests.post(url, json={"test": True}, timeout=10)
            else:
                resp = requests.get(url, timeout=10)
            print(f"  Response: {resp.status_code}")
        except Exception as e:
            print(f"  Error testing {url}: {e}")
        time.sleep(0.5)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trigger OpenObserve Alerts')
    parser.add_argument('--all', action='store_true', help='Trigger all alerts')
    parser.add_argument('--auth', action='store_true', help='Trigger auth failures')
    parser.add_argument('--polling', action='store_true', help='Trigger auth polling')
    parser.add_argument('--error', action='store_true', help='Trigger error rate (500s)')
    parser.add_argument('--latency', action='store_true', help='Trigger high latency')
    parser.add_argument('--anomaly', action='store_true', help='Trigger credit anomaly')
    parser.add_argument('--webhook', action='store_true', help='Trigger webhook security')
    parser.add_argument('--ttft', action='store_true', help='Trigger LLM high TTFT mock')
    parser.add_argument('--llm', action='store_true', help='Trigger LLM generation failure mock')
    parser.add_argument('--frontend', action='store_true', help='Trigger frontend client errors')
    parser.add_argument('--debug', action='store_true', help='Run diagnostic ping tests')

    # New flags
    parser.add_argument('--authenticated', action='store_true', help='Use authenticated session for polling')
    parser.add_argument('--spoof-ip', action='store_true', help='Spoof X-Forwarded-For headers')

    args = parser.parse_args()

    if args.debug:
        trigger_diagnostics()
        sys.exit(0)

    if args.all or args.auth:
        trigger_auth_failures(spoof_ip=args.spoof_ip)
    if args.all or args.polling:
        authenticated = True if args.all else args.authenticated
        trigger_auth_polling(authenticated=authenticated, spoof_ip=args.spoof_ip)
    if args.all or args.latency:
        trigger_high_latency()
    if args.all or args.anomaly:
        trigger_credit_anomaly()
    if args.all or args.error:
        trigger_500_errors(spoof_ip=args.spoof_ip)
    if args.all or args.webhook:
        trigger_webhook_failures()
    if args.all or args.ttft:
        trigger_ttft()
    if args.all or args.llm:
        trigger_llm_failure()
    if args.all:
        trigger_db_failure()
        trigger_payment_failure()
    if args.all or args.frontend:
        trigger_frontend_errors(spoof_ip=args.spoof_ip)

    if not any(vars(args).values()):
        parser.print_help()
