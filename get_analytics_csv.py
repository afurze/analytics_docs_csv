from bs4 import BeautifulSoup
import csv
import json
import pandas as pd
import requests
import sys


BASE_URL = "https://docs-cortex.paloaltonetworks.com/internal/api/webapp"

def get_page_ids():
    url = BASE_URL + "/pretty-url/reader"

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
    url = BASE_URL + "/maps/{0}/toc?".format(doc_ids['documentId'])

    resp = requests.get(url=url)
    return resp.json()

def parse_toc(topics):
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
    topics = []

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
    
    for t in topics:
        soup = BeautifulSoup(t['topic']['text'], 'html.parser')
        
        table = []
        rows = soup.table.tbody.find_all('tr')
        for r in rows:
            cols = r.find_all('td')
            cols = [ele.text.strip() for ele in cols]
            table.append([ele for ele in cols if ele])
        
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

        tactic = [x for x in table if x[0] == 'ATT&CK Tactic'][0][1]
        technique = [x for x in table if x[0] == 'ATT&CK Technique'][0][1]     

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
        
        row.update(sources)
        new_df = pd.DataFrame(row)
        df = pd.concat([df, new_df], ignore_index=True)

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

                row.update(sources)
                new_df = pd.DataFrame(row)
                df = pd.concat([df, new_df], ignore_index=True)
            
    return df

def variations(soup):
    variations = soup.find(lambda tag: tag.name == 'h2' and 'Variations' in tag.text)
    variations = variations.find_all_next('a', class_='ft-expanding-block-link')

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
        tactic = [x for x in table if x[0] == 'ATT&CK Tactic'][0][1]
        technique = [x for x in table if x[0] == 'ATT&CK Technique'][0][1]

        res.append({
            'detector': detector,
            'severity': severity,
            'tactic': tactic,
            'technique': technique
        })


    return res

def write_csv(csv_data):
    with open('/output/analytics_alerts.csv', 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(csv_data)

def main():
    doc_ids = get_page_ids()
    topics = get_topics(doc_ids)
    detector_ids = parse_toc(topics)
    topics = get_reader_topic_request(doc_ids, detector_ids)
    df = parse_topics(topics)
    write_csv(df.to_csv())
    
if __name__ == '__main__':
    main()
