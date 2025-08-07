import requests

# Remote source URLs
SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
        "output": "disposable_domains.txt"
    },
    {
        "url": "https://raw.githubusercontent.com/martenson/disposable-email-domains/master/disposable_email_blacklist.conf",
        "output": "bad_domains.txt"
    }
]

def fetch_and_update_lists():
    for source in SOURCES:
        try:
            print(f"Fetching from {source['url']}...")
            response = requests.get(source["url"], timeout=10)
            response.raise_for_status()
            domains = set()

            for line in response.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())

            # Write unique, sorted domains to file
            with open(source["output"], "w") as f:
                for domain in sorted(domains):
                    f.write(domain + "\n")

            print(f"✅ Updated {source['output']} with {len(domains)} domains.")

        except Exception as e:
            print(f"❌ Error updating {source['output']} from {source['url']}: {e}")

if __name__ == "__main__":
    fetch_and_update_lists()
