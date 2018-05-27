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
```
## Configuration
```
From menu :  Splunk > Settings > Alert actions > Create theHive Alert
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
It is preferable in splunk to produce a table with final "Observables" names to be sent to thehive
With a raw event and more than 20 fields it is difficult to deal with the view of the alert in theHive. 
Update: Note that now, you are allowed to define fields to send to the alert.
```
## Debug
```
From menu :  Splunk > Settings > Alert actions > Create theHive Alert
you can get the following search to see what is going on :
index=_internal sourcetype=splunkd component=sendmodalert action="create_thehive_alert"
```
