from bs4 import BeautifulSoup
import csv
import json
import requests
import sys


BASE_URL = "https://docs-cortex.paloaltonetworks.com/internal/api/webapp"

def get_page_ids():
    url = BASE_URL + "/pretty-url/reader"

    data = {
        'prettyUrl': "Cortex-XDR/Cortex-XDR-Analytics-Alert-Reference-by-Alert-name/Cortex-XDR-Analytics-Alert-Reference",
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
    csv_data = [[
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
    ]]
    
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
                sources[k] = 'X'

        if 'XDR Agent' in required_data and 'XTH' not in required_data:
            sources['XDR Agent'] = 'X'
        if 'eXtended Threat Hunting (XTH)' in required_data:
            sources['XDR Agent with eXtended Threat Hunting (XTH)'] = 'X'
        
        row = [
            detector,
            '', # top level is not a variation
            severity,
            activation_period,
            training_period,
            test_period,
            dedup_period,
            detection_modules,
            tags,
            tactic,
            technique
        ]

        for k,v in sources.items():
            row.append(v)

        csv_data.append(row)

        if 'Variations' in soup.text:
            variants = variations(soup)

            for v in variants:
                row = [
                    v['detector'],
                    detector,
                    v['severity'],
                    activation_period,
                    training_period,
                    test_period,
                    dedup_period,
                    detection_modules,
                    tags,
                    v['tactic'],
                    v['technique']
                ]

                for k, v in sources.items():
                    row.append(v)

                csv_data.append(row)
            
    
    return csv_data

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
    csv_data = parse_topics(topics)
    write_csv(csv_data)
    
if __name__ == '__main__':
    main()
