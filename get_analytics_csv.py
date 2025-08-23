from bs4 import BeautifulSoup
import json
from mitreattack.navlayers.core import Layer
from mitreattack.stix20 import MitreAttackData
import pandas as pd
import re
import requests
import sys


# Cortex Doc portal base URL
BASE_URL = "https://docs-cortex.paloaltonetworks.com/internal/api/webapp"


def get_page_ids():
    """Handles HTML request to get the page Ids which we can then use to get the topic Ids
    
    Args:
        None

    Returns:
        The response text as JSON
    """

    url = BASE_URL + "/pretty-url/reader"

    # There is an XDR and an XSIAM docs page, we'll use the XSIAM version (as far as I know
    # they're identitical, but this could change)
    data = {
        'prettyUrl': "Cortex-XSIAM/Cortex-XSIAM-Analytics-Alert-Reference-by-Alert-name",
        'forcedTocId': 'null'
    }

    resp = requests.post(url=url, json=data)
    if resp.status_code != 200:
        print("Error: " + json.dumps(resp.json()))
        sys.exit(1)
    return resp.json()

def get_topics(doc_ids):
    """Handles HTML request to get the topic Ids, which we can then use to
    request the actual contents
    
    Args:
        doc_ids: A JSON object containing all the page Ids we need topics for

    Returns:
        The response text as JSON
    """
    url = BASE_URL + "/maps/{0}/toc?".format(doc_ids['documentId'])

    resp = requests.get(url=url)
    return resp.json()

def parse_toc(topics):
    """Parse out the topic list so that we can make our requests to get content

    Args:
        topics: A JSON object containing the topic data

    Returns:
        An array of JSON objects containing the parsed topic data
    """
    detector_ids = []

    for x in topics['toc'][1:]:
        detector_ids.append({
            'detector': x,
            'tocId': x['topic']['tocId'],
            'contentId': x['topic']['link']['contentId'],
            'title': x['topic']['title'],
            'ratingGroupId': x['topic']['ratingGroupId'],
            # 'relativeTopicPivot': x['topic']['relativeTopicPivot']
        })


    return detector_ids

def get_reader_topic_request(doc_ids, detector_ids):
    """Handle sending HTML requests to get the actual page body for each detector
    
    Args:
        doc_ids: the page Ids we are requesting from
        detector_ids: the section Ids for each detector we are requesting
    
    Returns:
        The JSON object topics key which contains the raw page data
    """
    topics = []

    # Build the request data for each detector
    for x in detector_ids:
        topics.append({
            'sourceType': 'OFFICIAL',
            'originMapId': doc_ids['documentId'],
            'originTocId': x['tocId'],
            'contentId': x['contentId']
        })

    url = BASE_URL + "/reader/topics/request"
    data = {
        'topics': topics
    }
    resp = requests.post(url=url, json=data)

    return resp.json()['topics']

def parse_table_data(table_soup):
    """
    Parses a single HTML table and returns a dictionary of its key-value pairs.
    Handles nested lists by extracting text only from the innermost list items.
    """
    data = {}
    rows = table_soup.find_all('tr')
    for r in rows:
        cols = r.find_all('td')
        if len(cols) >= 2:
            key = cols[0].get_text(strip=True)
            value_cell = cols[1]

            # --- Step 1: Extract the value robustly ---
            # Find all list items ('li') and filter for the ones that do NOT
            # contain a nested list ('ul'). This isolates the innermost data.
            inner_list_items = [
                li.get_text(strip=True) for li in value_cell.find_all('li')
                if not li.find('ul')
            ]

            if inner_list_items:
                # If we found innermost list items, join their text.
                value = ", ".join(inner_list_items)
            else:
                # Otherwise, just get the cell's plain text.
                value = value_cell.get_text(strip=True)

            # --- Step 2: Conditionally clean the value for 'Required Data' ---
            if key == 'Required Data' and value:
                # Split the comma-separated string, clean each part, then rejoin.
                cleaned_parts = [part.strip().removesuffix('OR') for part in value.split(',')]
                value = ", ".join(cleaned_parts)

                # If 'XDR Agent' is present (and XTH isn't already), add the XTH version.
                if 'XDR Agent' in value and 'eXtended Threat Hunting (XTH)' not in value:
                    value += ", XDR Agent with eXtended Threat Hunting (XTH)"
            
            # Add the final key-value pair to our dictionary
            if value:
                data[key] = value
                
    return data

def parse_topics(topics):
    all_detectors_data = []
    for t in topics:
        soup = BeautifulSoup(t['topic']['text'], 'html.parser')
    
        # --- Part 1: Extract the Main Detector ---
        main_detector_data = {}
        # The main table is the first one in the HTML
        main_table = soup.find('table')
        if main_table:
            main_detector_data = parse_table_data(main_table)
            main_detector_data['Type'] = 'Detector'

        # Get the name of the main detector to use as a parent identifier
        # main_detector_name_tag = soup.find('a', class_='ft-expanding-block-link')
        # main_detector_name = main_detector_name_tag.get_text(strip=True) if main_detector_name_tag else 'Main Detector'

        # Add the name to the main detector's data
        main_detector_data['Name'] = t['topic']['title']

        # --- Part 2: Extract the Variations ---
        variations_data = []

        # Find all the variation sections by their class
        variations_sections = soup.find_all('div', class_='ft-expanding-block-content')

        for section in variations_sections:
            # Find the title of this variation using its data-target-id
            target_id = section.get('id')
            link_tag = soup.find('a', {'data-target-id': target_id})
            title = link_tag.get_text(strip=True) if link_tag else 'Untitled Variation'
            
            # Start with a copy of the parent's data as a base for the variation
            complete_variation = main_detector_data.copy()

            # Get the data specific to this variation
            variation_specific_data = parse_table_data(section)

            # Update the base with the variation's data, overwriting any shared keys
            complete_variation.update(variation_specific_data)

            # Set the correct metadata for the variation record
            complete_variation['Type'] = 'Variation'
            complete_variation['Name'] = title
            complete_variation['Parent Detector'] = main_detector_data.get('Name')

            variations_data.append(complete_variation)

        all_data_list = [main_detector_data] + variations_data
        all_detectors_data.extend(all_data_list)
    
    df = pd.DataFrame(all_detectors_data)
    
    # Define the desired order of columns
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
    
    # Create a list of columns that exist in the DataFrame, following the desired order
    existing_ordered_cols = [col for col in desired_order if col in df.columns]
    
    # Combine the lists to create the final column order and re-index the DataFrame
    # This ensures your preferred columns come first and no data is accidentally dropped.
    df = df[existing_ordered_cols]
    
    return df


def summary_statistics(df):
    """This function calculates the various summary statistics
    
    Args:
        df: The dataframe to calculate on.
    
    Returns:
        A dict of multiple dataframes containing each of the summaries, the key represents
        the filename that will be used to export each df.
    """
    stats = {}
    stats['count_by_sev.csv'] = df['Severity'].value_counts()
    stats['count_by_source.csv'] = df['Required Data'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_tactic.csv'] = df['ATT&CK Tactic'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_technique.csv'] = df['ATT&CK Technique'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_tag.csv'] = df['Detector Tags'].dropna().str.split(',').explode().str.strip().value_counts()
    stats['count_by_module.csv'] = df['Detection Modules'].dropna().str.split(',').explode().str.strip().value_counts()

    return stats

def generate_heatmap(df):
    # Initialize layer
    layer = Layer()
    layer.from_file('/output/layer_template.json')
    # layer.from_file('layer_template.json')

    # Enable Techniques
    all_technique_ids = set()
    for t in df['ATT&CK Technique'].explode():
        pattern = r"\(([^)]+)\)"
        match = re.search(pattern, t)

        if match:
            result = match.group(1)
            all_technique_ids.add(result)

    for t in layer.layer.techniques:
        if t.techniqueID in all_technique_ids:
            t.enabled = True
            t.color = "#31a354"

    return layer
            

def main():
    """This application is designed to extract all of the Cortex XSIAM Analytics detectors
    from the product documentation web app.  The web app makes it impossible to extract this data
    from it directly to a format that allows simplified filtering and searching, so this
    application was created as an aid for PANW employees and customers alike.
    """
    doc_ids = get_page_ids()
    topics = get_topics(doc_ids)
    detector_ids = parse_toc(topics)
    topics = get_reader_topic_request(doc_ids, detector_ids)
    df = parse_topics(topics)
    stats = summary_statistics(df)
    layer = generate_heatmap(df)

    # Export
    layer.to_file('/output/layer.json')
    for fname, statdf in stats.items():
        statdf.to_csv('/output/' + fname, index=True)
    df.to_csv('/output/analytics_alerts.csv', index=False)
    
if __name__ == '__main__':
    main()
