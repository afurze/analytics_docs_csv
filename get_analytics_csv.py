import re
import pandas as pd
import requests
import sys
from config import (
    GITBOOK_API_BASE, GITBOOK_SPACE_ID, get_gitbook_token,
)
from google_sheets_export import authenticate_gspread, write_to_google_sheets


class GitBookClient:
    """Fetches alert content via the GitBook API (requires space ID and API token)."""

    def __init__(self, space_id, api_token):
        self.space_id = space_id
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_token}',
            'Accept': 'application/json',
        })

    def list_pages(self):
        url = f"{GITBOOK_API_BASE}/spaces/{self.space_id}/content/pages"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json().get('pages', [])

    def _collect_alert_pages(self, pages):
        """Recursively walk the page tree and collect individual alert pages."""
        alert_pages = []
        for page in pages:
            path = page.get('path', '')
            if path.startswith('alerts/') and path != 'alerts':
                alert_pages.append(page)
            children = page.get('pages', [])
            if children:
                alert_pages.extend(self._collect_alert_pages(children))
        return alert_pages

    def get_page_content(self, page_id):
        url = f"{GITBOOK_API_BASE}/spaces/{self.space_id}/content/page/{page_id}"
        resp = self.session.get(url, params={'format': 'markdown'})
        resp.raise_for_status()
        data = resp.json()
        return data.get('markdown', '') or data.get('document', {}).get('markdown', '')

    def fetch_all_alerts(self):
        print("Fetching page list from GitBook API...")
        all_pages = self.list_pages()
        alert_pages = self._collect_alert_pages(all_pages)
        print(f"Found {len(alert_pages)} alert pages")

        alerts = []
        for i, page in enumerate(alert_pages):
            title = page.get('title', '')
            page_id = page.get('id', '')
            if not page_id:
                continue
            markdown = self.get_page_content(page_id)
            alerts.append({'name': title, 'markdown': markdown})
            if (i + 1) % 100 == 0:
                print(f"  Fetched {i + 1}/{len(alert_pages)} pages...")

        print(f"Fetched all {len(alerts)} alert pages")
        return alerts



def _parse_markdown_table(table_text):
    """Parse a markdown table into a dict of field→value pairs."""
    data = {}
    for line in table_text.strip().split('\n'):
        line = line.strip()
        if not line.startswith('|') or '---' in line:
            continue
        cells = [c.strip() for c in line.split('|')]
        cells = [c for c in cells if c]
        if len(cells) >= 2:
            key = cells[0].replace('\\&', '&')
            value = cells[1].replace('\\&', '&').replace('\\_', '_')
            if key in ('Field', 'field'):
                continue
            if value:
                data[key] = value
    return data


def _clean_required_data(value):
    """Apply the same Required Data cleaning as the original scraper."""
    if not value:
        return value
    cleaned_parts = [part.strip().removesuffix('OR') for part in value.split(',')]
    value = ', '.join(p.strip() for p in cleaned_parts if p.strip())
    if 'XDR Agent' in value and 'eXtended Threat Hunting (XTH)' not in value:
        value += ', XDR Agent with eXtended Threat Hunting (XTH)'
    return value


def parse_alert_markdown(name, markdown_text):
    """Parse a single alert's markdown into a list of detector dicts (parent + variations)."""
    sections = re.split(r'^## ', markdown_text, flags=re.MULTILINE)

    synopsis_data = {}
    for section in sections:
        if section.startswith('Synopsis'):
            synopsis_data = _parse_markdown_table(section)
            break

    if 'Required Data' in synopsis_data:
        synopsis_data['Required Data'] = _clean_required_data(synopsis_data['Required Data'])

    main_detector = dict(synopsis_data)
    main_detector['Type'] = 'Detector'
    main_detector['Name'] = name

    results = [main_detector]

    variation_pattern = r'<details>\s*<summary>(.*?)</summary>(.*?)</details>'
    variations = re.findall(variation_pattern, markdown_text, flags=re.DOTALL)

    for var_name, var_body in variations:
        var_name = var_name.strip()
        var_data = _parse_markdown_table(var_body)
        if 'Required Data' in var_data:
            var_data['Required Data'] = _clean_required_data(var_data['Required Data'])

        complete_variation = dict(main_detector)
        complete_variation.update(var_data)
        complete_variation['Type'] = 'Variation'
        complete_variation['Name'] = var_name
        complete_variation['Parent Detector'] = name
        results.append(complete_variation)

    return results


def build_dataframe(alerts):
    """Convert parsed alert dicts into a DataFrame with dynamic data source columns."""
    all_detectors = []
    for alert in alerts:
        detectors = parse_alert_markdown(alert['name'], alert['markdown'])
        all_detectors.extend(detectors)

    df = pd.DataFrame(all_detectors)

    all_sources = df['Required Data'].dropna().str.split(',').explode().str.strip().unique()
    all_sources = sorted(all_sources)

    for source in all_sources:
        df.loc[:, source] = df['Required Data'].apply(
            lambda x, s=source: 'x' if pd.notna(x) and s in [p.strip() for p in x.split(',')] else ''
        )

    desired_order = [
        'Name',
        'Parent Detector',
        'Severity',
        'Activation Period',
        'Training Period',
        'Test Period',
        'Deduplication Period',
        'Detection Modules',
        'Detector Tags',
        'ATT&CK Tactic',
        'ATT&CK Technique',
        'Required Data',
        'Response playbooks'
    ]

    existing_ordered_cols = [col for col in desired_order if col in df.columns]
    final_column_order = existing_ordered_cols + list(all_sources)
    df = df[final_column_order]

    return df


def summary_statistics(df):
    stats = {}
    stats['count_by_sev.csv'] = df['Severity'].value_counts()
    stats['count_by_source.csv'] = df['Required Data'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_tactic.csv'] = df['ATT&CK Tactic'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_technique.csv'] = df['ATT&CK Technique'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_tag.csv'] = df['Detector Tags'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_module.csv'] = df['Detection Modules'].dropna().str.split(',').explode().str.strip().value_counts()
    return stats


def main():
    token = get_gitbook_token()
    if not token:
        print("Error: No GitBook API token found. Set GITBOOK_API_KEY or configure GCP Secret Manager.")
        sys.exit(1)
    if not GITBOOK_SPACE_ID:
        print("Error: No GitBook Space ID configured. Set GITBOOK_SPACE_ID.")
        sys.exit(1)

    print("Using GitBook API client")
    client = GitBookClient(GITBOOK_SPACE_ID, token)
    alerts = client.fetch_all_alerts()

    if not alerts:
        print("Error: No alerts fetched. Exiting.")
        sys.exit(1)

    df = build_dataframe(alerts)
    print(f"\nProcessed {len(df)} detector records")

    stats = summary_statistics(df)

    print("\nAuthenticating with Google Sheets...")
    gc = authenticate_gspread()

    print("Writing data to Google Sheets...")
    write_to_google_sheets(gc, df, stats)


if __name__ == '__main__':
    main()
