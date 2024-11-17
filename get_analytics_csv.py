from bs4 import BeautifulSoup
import json
import pandas as pd
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
            'relativeTopicPivot': x['topic']['relativeTopicPivot']
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

def parse_topics(topics):
    """This function is the meat and potatoes of this application.  We will use beautifulsoup
    to parse out the HTML and extract all the relevant data into a pandas DataFrame
    
    Args:
        topics: a JSON object containing the raw data about each detector
        
    Returns:
        A DataFrame containing all of the required data for each detector
    """

    # Build column headers list
    headers = [
        'Name',
        'Variant of',
        'Severity',
        'Activation Period',
        'Training Period',
        'Test Period',
        'Deduplication Period',
        'Detection Modules',
        'Detector Tags',
        'ATT&CK Tactic',
        'ATT&CK Technique',
        'AWS Audit Log',
        'AWS Flow Log',
        'AWS OCSF Flow Logs',
        'Azure Audit Log',
        'Azure Flow Log',
        'Azure SignIn Log',
        'AzureAD',
        'AzureAD Audit Log',
        'Box Audit Log',
        'DropBox',
        'Duo',
        'Gcp Audit Log',
        'Gcp Flow Log',
        'Google Workspace Audit Logs',
        'Google Workspace Authentication',
        'Health Monitoring Data',
        'Office 365 Audit',
        'Okta',
        'Okta Audit Log',
        'OneLogin',
        'Palo Alto Networks Global Protect',
        'Palo Alto Networks Platform Logs',
        'Palo Alto Networks Url Logs',
        'PingOne',
        'Third-Party Firewalls',
        'Third-Party VPNs',
        'Windows Event Collector',
        'XDR Agent',
        'XDR Agent with eXtended Threat Hunting (XTH)'
    ]

    data = {}

    df = pd.DataFrame(data, columns=headers)
    
    # Parse eatch topic
    for t in topics:
        soup = BeautifulSoup(t['topic']['text'], 'html.parser')
        
        # Data in the web page is organized with tables, need to extract
        table = []
        rows = soup.table.tbody.find_all('tr')
        for r in rows:
            cols = r.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            table.append([ele for ele in cols if ele])
        
        # Set some of the basic data about the detector
        detector = t['topic']['title']
        severity = [x for x in table if x[0] == 'Severity'][0][1]
        activation_period = [x for x in table if x[0] == 'Activation Period'][0][1]
        training_period = [x for x in table if x[0] == 'Training Period'][0][1]
        test_period = [x for x in table if x[0] == 'Test Period'][0][1]
        dedup_period = [x for x in table if x[0] == 'Deduplication Period'][0][1]
        required_data = [x for x in table if x[0] == 'Required Data'][0][1]
        try:
            tags = [x for x in table if x[0] == 'Detector Tags'][0][1]
        except:
            tags = ''
        try:
            detection_modules = [x for x in table if x[0] == 'Detection Modules'][0][1]
        except:
            detection_modules = ''

        # ATT&CK Tactic and Technique come from the table smashed together, we need to extract
        # them as lists so we can do some pivots later
        tactic = [x for x in table if x[0] == 'ATT&CK Tactic'][0][1].split(')')
        tactic = [t.strip() + ")" for t in tactic if t]
        technique = [x for x in table if x[0] == 'ATT&CK Technique'][0][1].split(')')
        technique = [t.strip() + ")" for t in technique if t]     

        # Start creating the dict of data for the detector
        row = {
            'Name': [detector],
            'Variant of': [''], # top level is not a variation
            'Severity': [severity],
            'Activation Period': [activation_period],
            'Training Period': [training_period],
            'Test Period': [test_period],
            'Deduplication Period': [dedup_period],
            'Detection Modules': [detection_modules],
            'Detector Tags': [tags],
            'ATT&CK Tactic': [tactic],
            'ATT&CK Technique': [technique]
        }           

        # Place an 'x' in the right data source column
        sources = {
            'AWS Audit Log': '',
            'AWS Flow Log': '',
            'AWS OCSF Flow Logs': '',
            'Azure Audit Log': '',
            'Azure Flow Log': '',
            'Azure SignIn Log': '',
            'AzureAD': '',
            'AzureAD Audit Log': '',
            'Box Audit Log': '',
            'DropBox': '',
            'Duo': '',
            'Gcp Audit Log': '',
            'Gcp Flow Log': '',
            'Google Workspace Audit Logs': '',
            'Google Workspace Authentication': '',
            'Health Monitoring Data': '',
            'Office 365 Audit': '',
            'Okta': '',
            'Okta Audit Log': '',
            'OneLogin': '',
            'Palo Alto Networks Global Protect': '',
            'Palo Alto Networks Platform Logs': '',
            'Palo Alto Networks Url Logs': '',
            'PingOne': '',
            'Third-Party Firewalls': '',
            'Third-Party VPNs': '',
            'Windows Event Collector': '',
            'XDR Agent': '',
            'XDR Agent with eXtended Threat Hunting (XTH)': ''
        }

        for k, v in sources.items():
            if k in required_data:
                sources[k] = ['X']

        if 'XDR Agent' in required_data and 'XTH' not in required_data:
            sources['XDR Agent'] = ['X']
            sources['XDR Agent with eXtended Threat Hunting (XTH)'] = ['X']
        else:
            sources['XDR Agent'] = ['']
        if 'eXtended Threat Hunting (XTH)' in required_data:
            sources['XDR Agent with eXtended Threat Hunting (XTH)'] = ['X']
        
        # Combine the 'old' dataframe and the 'new' dataframe
        row.update(sources)
        new_df = pd.DataFrame(row)
        df = pd.concat([df, new_df], ignore_index=True)

        # Check if this detector has variations, and parse them
        if 'Variations' in soup.text:
            variants = variations(soup)

            for v in variants:

                row = {
                    'Name': [v['detector']],
                    'Variant of': [detector], # top level is not a variation
                    'Severity': [v['severity']],
                    'Activation Period': [activation_period],
                    'Training Period': [training_period],
                    'Test Period': [test_period],
                    'Deduplication Period': [dedup_period],
                    'Detection Modules': [detection_modules],
                    'Detector Tags': [tags],
                    'ATT&CK Tactic': [v['tactic']],
                    'ATT&CK Technique': [v['technique']]
                }       

                # Combine the 'old' dataframe and the 'new' dataframe
                row.update(sources)
                new_df = pd.DataFrame(row)
                df = pd.concat([df, new_df], ignore_index=True)
            
    return df

def variations(soup):
    """Helper function to parse out variations table.  These are embedded as additional HTML
    tables in the parent 'topic' so we have to do some nasty looking finding
    
    Args:
        soup: the beautifulsoup object with the parent detector data, including the
            variations we need to extract
    
    Return:
        A dict with the data for each variation
    """
    # Do the aforementioned 'nasty looking finding'
    variations = soup.find(lambda tag: tag.name == 'h2' and 'Variations' in tag.text)
    variations = variations.find_all_next('a', class_='ft-expanding-block-link')

    # For each identified variation, extract out some basic data, we don't have to handle
    # the data source as this is the same as the parent detector
    res = []
    for var in variations:
        table = []
        rows = var.find_next('table').tbody.find_all('tr')
        for r in rows:
            cols = r.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            table.append([ele for ele in cols if ele])
    
        detector = var.text
        severity = [x for x in table if x[0] == 'Severity'][0][1]

        # Again, we have to create a list from the mashed together MITRE
        tactic = [x for x in table if x[0] == 'ATT&CK Tactic'][0][1].split(')')
        tactic = [t.strip() + ")" for t in tactic if t]
        technique = [x for x in table if x[0] == 'ATT&CK Technique'][0][1].split(')')
        technique = [t.strip() + ")" for t in technique if t] 

        res.append({
            'detector': detector,
            'severity': severity,
            'tactic': tactic,
            'technique': technique
        })


    return res

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
    df.to_csv('/output/analytics_alerts.csv', index=False)
    
if __name__ == '__main__':
    main()
