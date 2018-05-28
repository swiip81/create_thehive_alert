# create_thehive_alert
Send alerts from Splunk to TheHive


This is a **fork**. Check original author GitHubpage.
Thank you to **Daniel Gallagher** for the initial share of this code.

For now, I am just trying to make it more friendly and usable for my usage.

I am **not** a developper, a noob in thehive, just a splunker.


# My test environment 
 ```
splunk  7.1.0
TheHive 3.0.5
 ```

## Installation
```
cd /opt/splunk/etc/apps/
wget 'https://github.com/swiip81/create_thehive_alert/archive/master.zip'
unzip master.zip 
rm -f master.zip
mv create_thehive_alert-master create_thehive_alert
/opt/splunk/bin/splunk restart
Or
https://yoursplunkserver:8000/en-US/debug/refresh
```
## Configuration
```
From menu:  Splunk > Settings > Alert actions > Create theHive Alert
Change Permissions from 'App' to 'All Apps' aka 'Global' and restrict usage with your users
Then "Setup Create TheHive Alert" by filling the url, username, and password

Note that in theHive, you have to create that dedicated user and password 
    permission : none  (yes you can keep none)
    Additional Permissions => Allow alerts creation :   YES  !! check it !!
```
## How I _test_ it
```
Run a splunk search like :
index="_internal" clientip="*" | head 1 | table clientip | rename clientip as ip
Save As	> Alert
Set a "Title"
Change from "Run Every Week" to "Run on Cron Schedule"
Cron Expression
  */2 * * * *
Add Actions
  Create theHive Alert
Save and look at 'Alerts' tab in theHive.
Don't forget to disable or delete the alert in splunk, with that cron it will generate an alert for thehive every 2 min forever.
```
## Recommendations
```
Splunk is providing a list of fieldname=value, thehive is waiting for a list of values matching Type(s) [ default + customs ]
I think this is an easy source of confusion. Also in thehive when you create a case from an alert only the definied Types are imported.

So it is probably preferable in splunk to produce a table matching of "Observables" Type names to be sent to thehive.
Check with :
(your search ) | table url other user-agent regexp mail_subject registry mail autonomous-system domain ip uri_path filename hash file fqdn

And use rename or eval to fill them :
(your search) | rename sourceip as ip | eval url=URL

Note: From a raw event and more than 20 fields it is difficult to deal with the view of the alert in theHive. 

Update: Note that now, you are allowed to define the fields to send to the alert.
```
## Debug
```
From menu:  Splunk > Settings > Alert actions > Create theHive Alert
you can get the following search to see what is going on :

index=_internal sourcetype=splunkd component=sendmodalert action="create_thehive_alert"
```
