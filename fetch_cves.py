import requests
import datetime
import os
import json
import time

# --- Config ---
API_KEY = os.env("NVD_API_KEY")
OUTPUT_DIR = "CVEs"
DAYS_BACK = 2196        # from 2020
BATCH_SIZE = 30
RESULTS_PER_PAGE = 200  # NVD max per request

LINUX_KERNEL_CPE = "cpe:2.3:o:linux:linux_kernel"
SEARCH_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

os.makedirs(OUTPUT_DIR, exist_ok=True)


def daterange(start_date, end_date, step_days):
    """Yield date ranges in step_days chunks."""
    current = start_date
    while current < end_date:
        yield current, min(current + datetime.timedelta(days=step_days), end_date)
        current += datetime.timedelta(days=step_days)


def extract_kernel_versions(cve_item):
    """Extract affected Linux kernel versions from CVE configurations."""
    versions = set()

    configurations = cve_item.get("cve", {}).get("configurations", [])
    if not configurations:
        configurations = cve_item.get("configurations", [])

    # Traverse configurations
    def walk_nodes(nodes):
        for node in nodes:
            for match in node.get("cpeMatch", []):
                cpe23 = match.get("criteria") or match.get("cpe23Uri")
                if not cpe23:
                    continue
                # CPE looks like: cpe:2.3:o:linux:linux_kernel:5.10.14:*:*:*:*:*:*:*
                if ":linux_kernel:" in cpe23:
                    parts = cpe23.split(":")
                    if len(parts) >= 6:
                        version = parts[5]
                        if version and version != "*":
                            versions.add(version)
            # Recursively walk children
            if "children" in node:
                walk_nodes(node["children"])

    if isinstance(configurations, list):
        walk_nodes(configurations)

    return sorted(versions)


def fetch_and_save_cves_in_range(start, end):
    """Fetch all CVEs for 'linux kernel' in the date range and save to JSON."""
    start_index = 0
    total_results = 1

    while start_index < total_results:
        params = {
            "keywordSearch": "linux kernel",
            #"virtualMatchString": LINUX_KERNEL_CPE,
            "pubStartDate": start.isoformat() + "T00:00:00.000Z",
            "pubEndDate": end.isoformat() + "T23:59:59.000Z",
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }

        headers = {"User-Agent": "CVE-Fetcher"}
        if API_KEY:
            headers["apiKey"] = API_KEY

        resp = requests.get(SEARCH_API_URL, params=params, headers=headers)
        if resp.status_code != 200:
            print(f"Error {resp.status_code} fetching range {start} to {end}")
            return

        data = resp.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)

        print(f"> Found {len(vulnerabilities)} CVEs from {start} to {end}")

        for item in vulnerabilities:
            cve_id = item["cve"]["id"]
            out_path = os.path.join(OUTPUT_DIR, f"{cve_id}.json")

            #if os.path.exists(out_path):
            #    continue

            # Extract affected kernel versions
            kernel_versions = extract_kernel_versions(item)

            # Add to JSON for convenience
            item["kernel_versions"] = kernel_versions

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(item, f, indent=2)

            print(f" Saved: {cve_id}  ({', '.join(kernel_versions) or 'no versions listed'})")

        start_index += RESULTS_PER_PAGE
        time.sleep(0.9)

def process_batches():
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=DAYS_BACK)

    for batch_start, batch_end in daterange(start_date, today, BATCH_SIZE):
        print(f"\n Processing batch: {batch_start} to {batch_end}")
        fetch_and_save_cves_in_range(batch_start, batch_end)

    print("\n Done.")


if __name__ == "__main__":
    process_batches()
