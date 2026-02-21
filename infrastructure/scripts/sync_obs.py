#!/usr/bin/env python3
import os
import json
import glob
import urllib.request
import urllib.error
import urllib.parse
import base64
import argparse
import sys

# OpenObserve Config
OO_ENDPOINT = os.getenv('OO_ENDPOINT', 'https://api.openobserve.ai').rstrip('/')
OO_ORG = os.getenv('OO_ORG')
OO_USER = os.getenv('OO_USER')
OO_PASS = os.getenv('OO_PASS')

def make_request(url, method='GET', data=None, dry_run=False):
    if dry_run and method in ['POST', 'PUT', 'DELETE']:
        print(f"[DRY-RUN] Would {method} to {url} with {json.dumps(data) if data else 'no data'}")
        return {}

    auth_str = f"{OO_USER}:{OO_PASS}"
    auth_bytes = auth_str.encode('ascii')
    base64_auth = base64.b64encode(auth_bytes).decode('ascii')

    headers = {
        'Authorization': f'Basic {base64_auth}',
        'Content-Type': 'application/json'
    }

    body = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 204:
                return {}
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"HTTP Error {e.code}: {e.read().decode('utf-8')}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None

def sync_resources(resource_type, pattern, dry_run=False):
    # OpenObserve API path mapping
    # Note: Alerts are v2, Dashboards are v1
    is_v2 = resource_type == "alerts"
    api_path = "api/v2" if is_v2 else "api"

    # Get existing resources
    list_url = f"{OO_ENDPOINT}/{api_path}/{OO_ORG}/{resource_type}"
    print(f"Fetching existing {resource_type} from {list_url}")
    resp = make_request(list_url)

    if resp is None:
        print(f"Failed to fetch {resource_type}")
        return

    # v2 API returns a dictionary with a 'list' key, v1 dashboards returns 'dashboards'
    if is_v2 and isinstance(resp, dict) and 'list' in resp:
        existing_list = resp['list']
    elif isinstance(resp, dict) and 'dashboards' in resp:
        existing_list = resp['dashboards']
    elif isinstance(resp, list):
        existing_list = resp
    else:
        print(f"Unexpected response format for {resource_type}: {type(resp)}")
        existing_list = []

    # Map name to metadata (Dashboards use dashboard_id, Alerts v2 use alert_id)
    existing = {}
    for item in existing_list:
        if is_v2:
            name = item.get('name')
            item_id = item.get('alert_id')
            item_hash = None
        else:
            name = item.get('name') or item.get('title')
            item_id = item.get('dashboard_id')
            item_hash = item.get('hash')

        if name:
            existing[name] = {'id': item_id, 'hash': item_hash}

    files = glob.glob(pattern)
    for f in files:
        with open(f, 'r') as jf:
            try:
                data = json.load(jf)
                name = data.get('name')
                if not name:
                    # Fallback for older dashboards
                    name = data.get('title')

                if not name:
                    print(f"Skipping {f}: No name or title found")
                    continue

                if name in existing:
                    # Update
                    print(f"Updating {resource_type}: {name}")
                    item_info = existing[name]
                    item_id = item_info['id']
                    item_hash = item_info['hash']

                    # URL encode the item_id for the URL
                    update_url = f"{OO_ENDPOINT}/{api_path}/{OO_ORG}/{resource_type}/{urllib.parse.quote(item_id)}"

                    # Build query parameters
                    params = {}
                    if is_v2:
                        params['type'] = data.get('stream_type', 'logs')
                        # v2 update payload must include id
                        data['id'] = item_id
                        data['org_id'] = OO_ORG
                    elif item_hash:
                        params['hash'] = item_hash

                    if params:
                        update_url += "?" + urllib.parse.urlencode(params)

                    resp = make_request(update_url, method='PUT', data=data, dry_run=dry_run)
                else:
                    # Create
                    print(f"Creating {resource_type}: {name}")
                    create_url = f"{OO_ENDPOINT}/{api_path}/{OO_ORG}/{resource_type}"
                    if is_v2:
                        data['org_id'] = OO_ORG
                    resp = make_request(create_url, method='POST', data=data, dry_run=dry_run)
            except json.JSONDecodeError:
                print(f"Failed to parse {f}")

def main():
    parser = argparse.ArgumentParser(description='Sync OpenObserve alerts and dashboards')
    parser.add_argument('--dry-run', action='store_true', help='Dry run (do not make changes)')
    args = parser.parse_args()

    if not all([OO_ORG, OO_USER, OO_PASS]):
        print("Missing required environment variables: OO_ORG, OO_USER, OO_PASS")
        print("Example: export OO_ORG=default OO_USER=root@example.com OO_PASS=rootpw")
        sys.exit(1)

    sync_resources('alerts', 'infrastructure/monitoring/alerts/*.json', dry_run=args.dry_run)
    sync_resources('dashboards', 'infrastructure/monitoring/dashboards/*.json', dry_run=args.dry_run)

if __name__ == "__main__":
    main()
