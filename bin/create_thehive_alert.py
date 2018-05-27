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

def create_alert(csv_rows, config):
	print >> sys.stderr, "DEBUG Creating alert with config %s" % config

	url = config.get('url', '') # Get TheHive URL from Splunk configuration
	if not url.startswith('https:'):
		print >> sys.stderr, "DEBUG the URL for thehive should use HTTPS."
		# Memo, have to test it first
		# sys.exit(2)

	username = config.get('username') # Get TheHive username from Splunk configuration
	password = config.get('password') # Get TheHive password from Splunk configuration
	auth = requests.auth.HTTPBasicAuth(username=username,password=password)
	sourceRef = str(uuid.uuid4())[0:6] # Generate unique identifier for alert

	# Filter empty multivalue fields
	parsed_rows = {key: value for key, value in csv_rows.iteritems() if not key.startswith("__mv_")}
	# Get list of fields to extract
	field_list = re.split(r'\s*,\s*', config.get('fields', '*').strip())

	artifacts = []
	seen_fields = set()
	for f in field_list:
		for key, value in parsed_rows.iteritems():
			if key not in seen_fields and fnmatch(key, f):
				seen_fields.add(key)
				artifacts.append(dict(
					dataType = key,
					data = value,
                        		message = "observed: %s" % key
				))

	# Get the payload for the alert from the config, use defaults if they are not specified
	payload = json.dumps(dict(
		title = config.get('title', "No title"),
		description = config.get('description', "No description provided."),
		tags = [] if config.get('tags') is None else config.get('tags').split(","),
		severity = int(config.get('severity', 2)),
		tlp = int(config.get('tlp', 2)),
		type = config.get('type', "alert"),
		artifacts = artifacts,
		source = config.get('source', "Splunk"),
		caseTemplate = config.get('caseTemplate', "default"),
		sourceRef = sourceRef
	))
	# Send the request to create the alert
	try:
		print >> sys.stderr, 'INFO Calling url="%s" with payload=%s' % (url, payload)
		headers = {'Content-type': 'application/json'}
		response = requests.post(url=url + "/api/alert", headers=headers, data=payload, auth=auth, verify=False)
		print >> sys.stderr, "INFO TheHive server responded with HTTP status %s" % response.status_code
		response.raise_for_status()
		print >> sys.stderr, "INFO theHive server response: %s" % response.json()
	except requests.exceptions.HTTPError as e:
		print >> sys.stderr, "ERROR theHive server returned following error: %s" % e
	except requests.exceptions.RequestException as e:
		print >> sys.stderr, "ERROR Error creating alert: %s" % e


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
				with gzip.open(results_file) as file:
					reader = csv.DictReader(file)
					# iterate through each row, creating a alert for each and then adding the observables from that row to the alert that was created
					for csv_rows in reader:
						create_alert(csv_rows, config)
				sys.exit(0)
			except IOError as e:
				print >> sys.stderr, "FATAL Results file exists but could not be opened/read"
				sys.exit(3)
		else:
			print >> sys.stderr, "FATAL Results file does not exist"
			sys.exit(2)
	else:
		print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
		sys.exit(1)
