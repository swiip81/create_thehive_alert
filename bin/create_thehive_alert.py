#!/usr/bin/env python

import os
import sys
import json
import gzip
import csv
import requests
import uuid
import re
from requests.auth import HTTPBasicAuth
from fnmatch import fnmatch


def field_type_guessing(key, value):
    print("DEBUG Entering Guessing function", file=sys.stderr)

    # Checking for splunk fields names already matching thehive default types
    defaulttypes = [
        "url",
        "other",
        "user-agent",
        "regexp",
        "mail_subject",
        "registry",
        "mail",
        "autonomous-system",
        "domain",
        "ip",
        "uri_path",
        "filename",
        "hash",
        "fqdn"
        ]
    if key in defaulttypes:
        return key, value

    # Checking for fields that are not to be sent to TheHive
    ignoredfields_list = re.split(r'\s*,\s*', config.get('ignoredfields',"").strip(' '))
    if key in ignoredfields_list:
        return ("other", "N/A")

    # Checking for fields names matching thehive custom types given at setup
    observables_list = re.split(r'\s*,\s*', config.get('observables',"").strip(' '))
    if key in observables_list:
        return key, value

    # Trying to match known splunk CIM fields names
    cim_ip = [
        "dest",
        "dest_ip",
        "dest_translated_ip",
        "dvc_ip",
        "orig_host_ip",
        "src",
        "src_ip",
        "src_translated_ip",
        "threat_ip"
        ]
    if key in cim_ip:
        return "ip", value

    cim_fqdn = [
        "dest_dns",
        "dns",
        "dvc_dns",
        "orig_host_dns",
        "src_dns"
        ]
    if key in cim_fqdn:
        return "fqdn", value

    cim_domain = [
        "dest_nt_domain",
        "dest_pci_domain",
        "dvc_pci_domain",
        "orig_host_pci_domain",
        "src_nt_domain",
        "src_pci_domain"
        ]
    if key in cim_domain:
        return "domain", value

    cim_filename = [
        "file",
        "file_name",
        "file_path"
        ]
    if key in cim_filename:
        return "filename", value

    cim_hash = [
        "file_hash",
        "md5",
        "sha1",
        "sha256"
        ]
    if key in cim_hash:
        return "hash", value

    cim_user_agent = [
        "http_user_agent"
        ]
    if key in cim_user_agent:
        return "user-agent", value

    # Tring to guess type with regexp ipv4
    if re.match("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", value):
        return "ip", value

    # Tring to guess type with regexp email
    if re.match("^[^@]+@[^@]+\.[^@]+$", value):
        return "mail", value

    # Tring to guess type with regexp url
    if re.match("^https?://", value):
        return "url", value

    # If no match then 'other' is our default category
    return "other", value


def create_alert(csv_rows, config):
    print("DEBUG Creating alert with config %s" % config, file=sys.stderr)

    # Get TheHive URL from Splunk configuration
    url = config.get('url', '')
    if not url.startswith('https:'):
        print("DEBUG the URL for thehive should use HTTPS.", file=sys.stderr)
        # Memo, have to test it first
        # sys.exit(2)

    # Get TheHive username from Splunk configuration
    username = config.get('username')
    # Get TheHive password from Splunk configuration
    password = config.get('password')
    # Get TheHive apikey from Splunk configuration
    apikey = config.get('apikey')
    # Generate unique identifier for alert
    sourceRef = str(uuid.uuid4())[0:13]
    # Get the flag for auto type discovering function
    autotypeflag = config.get('autotypes')
    # get additional values of search for fields description
    alert_severity = config.get('alert.severity')
    view_link = config.get('view_link')
    search = config.get('search')
    results_link = config.get('results_link')
    title=config.get('title', "No title")
    description = config.get('description', "")

    # Filter empty multivalue fields
    parsed_rows = {key: value for key, value in csv_rows.items() if not (key.startswith("__mv_") and not(value))}
    for k in [mvk.replace('__mv_','') for mvk in parsed_rows.keys() if (mvk.startswith("__mv_"))]:
        parsed_rows[k] = parsed_rows['__mv_'+k][1:-1]
        del parsed_rows['__mv_'+k]

    # Get list of fields to extract
    field_list = re.split(r'\s*,\s*', config.get('fields', '*').strip())

    # init severity and tags 
    severity = int(config.get('severity', 2))
    tags=[] if config.get('tags') is None else config.get('tags').split(",")

    artifacts = []
    seen_fields = set()
    for f in field_list:
        for key, value in parsed_rows.items():
            if key not in seen_fields and fnmatch(key, f):
                seen_fields.add(key)
                if value:
                    if key == "thehive_title":
                       title = title + ": " + value
                    elif key == "thehive_description":
                       description = description + "  \nScenario: " + value
                    elif key == "thehive_timelog":
                       description = description + "  \nTimelog: " + value
                    elif key == "thehive_severity":
                        if (value.isdigit() and (int(value) in [1,2,3,4])):
                            severity = int(value)
                        else:
                            print("WARNING thehive_severity value %s is not in [1,2,3,4] , will be ignored !" % value, file=sys.stderr)
                    elif key == "thehive_tags":
                        tags.extend(value.split(','))
                    else:
                        message = "Original field name: %s  \nAlert original severity: %s  \nLink to alert: %s  \nLink to result: %s  " % (
                            key,
                            alert_severity,
                            view_link,
                            results_link)
                        # Parsing TheHive custom observables
                        if key and value:
                            # Building observables dictionary
                            for sv in value.split(r'''$;$'''):
                                if autotypeflag == '1':
                                    key_new, sv_new = field_type_guessing(key, sv)
                                else:
                                    key_new, sv_new = key, sv
                                if (sv_new.lower() != "n/a"):
                                    artifacts.append(dict(dataType=key_new,data=sv_new, message=message))

    # Get the payload for the alert from the config, use defaults if they are not specified
    payload = json.dumps(dict(
        title=title,
        description=description,
        tags=tags,
        severity=severity,
        tlp=int(config.get('tlp', 2)),
        type=config.get('type', "alertType"),
        observables=artifacts,
        source=config.get('source', "Splunk"),
        caseTemplate=config.get('caseTemplate', "default"),
        sourceRef=sourceRef
    ))
    # Send the request to create the alert
    try:
        print('INFO Calling url="%s" with payload=%s' % (url, payload), file=sys.stderr)
        headers = {'Content-type': 'application/json'}
        if len(apikey) != 0 and apikey != "{apikey}":
            headers['Authorization'] = 'Bearer ' + apikey
            response = requests.post(url=url + "/api/v1/alert", headers=headers,
                                     data=payload, verify=False)
            print("INFO Using apikey for auth", file=sys.stderr)
        else:
            auth = requests.auth.HTTPBasicAuth(username=username, password=password)
            response = requests.post(url=url + "/api/v1/alert",
                                     headers=headers, data=payload,
                                     auth=auth, verify=False)
            print("INFO Using username and password for auth", file=sys.stderr)
        print("INFO TheHive server responded with HTTP status %s" % response.status_code, file=sys.stderr)
        response.raise_for_status()
        print("INFO theHive server response: %s" % response.json(), file=sys.stderr)
    except requests.exceptions.HTTPError as e:
        print("ERROR theHive server returned following error: %s" % e, file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print("ERROR Error creating alert: %s" % e, file=sys.stderr)


if __name__ == "__main__":
    # make sure we have the right number of arguments - more than 1; and first argument is "--execute"
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # read the payload from stdin as a json string
        payload = json.loads(sys.stdin.read())
        # extract the results file and alert config from the payload
        config = payload.get('configuration')
        results_file = payload.get('results_file')
        if os.path.exists(results_file):
            try:
                with gzip.open(results_file, "rt", encoding='utf-8') as file:
                    reader = csv.DictReader(file)
                    # iterate through each row, creating a alert for each and then adding the
                    # observables from that row to the alert that was created
                    for csv_rows in reader:
                        create_alert(csv_rows, config)
                sys.exit(0)
            except IOError as e:
                print("FATAL Results file exists but could not be opened/read", file=sys.stderr)
                sys.exit(3)
        else:
            print("FATAL Results file does not exist", file=sys.stderr)
            sys.exit(2)
    else:
        print("FATAL Unsupported execution mode (expected --execute flag)", file=sys.stderr)
        sys.exit(1)
