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
        'XDR Agent',
        'XDR Agent (with XTH)',
        'Windows Event Collector',
        'PAN Platform Logs',
        'Azure Audit Logs',
        'GCP Audit Logs',
        'Azure AD',
        'Azure AD Audit Logs',
        'AWS Audit Logs',
        'Okta',
        'Ping',
        'OneLogin',
        'Google Workspace Audit Logs',
        'Office 365 Audit Logs',
        'Box Audit Logs',
        'DropBox Audit Logs',
        'PAN Global Protect/3rd Party VPN',
        'Health Monitoring Data'
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
        xdr_agent = ''
        xdr_agent_xth = ''
        wec = ''
        pan_platform = ''
        azure_audit = ''
        azure_ad = ''
        azure_ad_audit = ''
        aws_audit = ''
        gcp_audit = ''
        okta = ''
        ping = ''
        onelogin = ''
        google_workspace_audit = ''
        box = ''
        dropbox = ''
        o365_audit = ''
        pan_gp_vpn = ''
        pan_platform = ''
        health_mon = ''

        if 'XDR Agent' in required_data and 'XTH' not in required_data:
            xdr_agent = 'X'
        if 'eXtended Threat Hunting (XTH)' in required_data:
            xdr_agent_xth = 'X'
        if 'Windows Event Collector' in required_data:
            wec = 'X'
        if 'Palo Alto Networks Platform' in required_data:
            pan_platform = 'X'
        if 'Azure Audit Log' in required_data:
            azure_audit = 'X'
        if 'AzureAD' in required_data:
            azure_ad = 'X'
        if 'AzureAD Audit Log' in required_data:
            azure_ad_audit = 'X'
        if 'AWS Audit Log' in required_data:
            aws_audit = 'X'
        if 'Gcp' in required_data:
            gcp_audit = 'X'
        if 'Okta' in required_data:
            okta = 'X'
        if 'Ping' in required_data:
            ping = 'X'
        if 'OneLogin' in required_data:
            onelogin = 'X'
        if 'Google Workspace Audit Logs' in required_data:
            google_workspace_audit = 'X'
        if 'Box Audit' in required_data:
            box = 'X'
        if 'DropBox' in required_data:
            dropbox = 'X'
        if 'Global Protect' in required_data:
            pan_gp_vpn = 'X'
        if 'Office 365 Audit' in required_data:
            o365_audit = 'X'
        if 'Health Monitoring Data' in required_data:
            health_mon = 'X'
        
        csv_data.append([
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
            technique,
            xdr_agent,
            xdr_agent_xth,
            wec,
            pan_platform,
            azure_audit,
            gcp_audit,
            azure_ad,
            azure_ad_audit,
            aws_audit,
            okta,
            ping,
            onelogin,
            google_workspace_audit,
            o365_audit,
            box,
            dropbox,
            pan_gp_vpn,
            health_mon
        ])

        if 'Variations' in soup.text:
            variants = variations(soup)

            for v in variants:
                csv_data.append([
                    v['detector'],
                    detector, # variation of the current top level detector
                    v['severity'],
                    activation_period,
                    training_period,
                    test_period,
                    dedup_period,
                    detection_modules,
                    tags,
                    v['tactic'],
                    v['technique'],
                    xdr_agent,
                    xdr_agent_xth,
                    wec,
                    pan_platform,
                    azure_audit,
                    gcp_audit,
                    azure_ad,
                    azure_ad_audit,
                    aws_audit,
                    okta,
                    ping,
                    onelogin,
                    google_workspace_audit,
                    o365_audit,
                    box,
                    dropbox,
                    pan_gp_vpn,
                    health_mon
                ])
            
    
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
