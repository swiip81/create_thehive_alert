# create_thehive_alert
Send alerts from Splunk searches to TheHive


This is a **fork**. Check original author GitHubpage.
Thank you to **Daniel Gallagher** for the initial share of this code.

For now, I am just trying to make it more friendly and usable for my usage.

I am **not** a developer, a noob in TheHive, just a splunker.


# My test environment 
 ```
splunk  7.1.0
TheHive 3.0.5
 ```

## Installation
```
cd /opt/splunk/etc/apps/  # adapt if /opt is not where you are installing splunk
wget 'https://github.com/swiip81/create_thehive_alert/archive/master.zip'
unzip master.zip 
rm -f master.zip
mv create_thehive_alert-master create_thehive_alert
```
## Configuration  

In **TheHive**, you have to create a dedicated user and password  
 - Permission : **None**  (yes it is recommended)  
 - Additional Permissions : **Allow alerts creation**  

In **splunk** from menu : `Splunk > Settings > Alert actions > Create TheHive Alert`  
Change Permissions from `App` to `Global` and restrict the usage for your users  
Then `Setup Create TheHive Alert` and fill **url, username, and password**  
Note that _apikey_ is not usable for now  
  
## How I _test_ it  

Run that splunk search :  
`index="_internal" clientip="*" | head 1 | table clientip | rename clientip as ip`  
Save As	> `Alert`  
Set a `Title`  
Change from `Run Every Week` to `Run on Cron Schedule`  
Cron Expression `* * * * *`  
Add Actions `Create theHive Alert`  
Save and look at `Alerts` tab in TheHive.  

Don't forget to disable after your tests or it will keep generating alerts to TheHive every minute forever.

## Important recommendations

Splunk search is providing a list of `fieldname=value`, but TheHive is waiting for observable matching `Types`  
And this is an easy source of confusion !  
In TheHive when you create a case from an alert only the defined `Types` are imported.  
By default, allowed observable types are :  
`url other user-agent regexp mail_subject registry mail autonomous-system domain ip uri_path filename hash file fqdn`  

And for that reason, it is preferable in splunk to produce directly a table that match only Observable `Types`  
You can check this with :  
`(your search) | table url other user-agent regexp mail_subject registry mail autonomous-system domain ip uri_path filename hash file fqdn`

One solution to achieve that, is to use `rename` or `eval` splunk transformations to match those fields names :  
`(your search) | rename sourceip as ip | eval url=URL`  

## Useful optional settings

You are allowed to define the **Fields** to send to the alert :  
 - To keep every fields in the splunk alert but just send what is needed to TheHive  
_Tips_: from a raw event and more than 20 fields, it is difficult to deal with the view of the alert in TheHive...  
  
You are able to check the **Auto Types** discovering option, in that case we will try to guess them  
 - Some types like `ip`, `email` and `url` are easy detected by testing values with regexp  
 - Some fields names that are defined by the siem compatibility model are also moved to the right type  
Default category is `other` if no match is done  
Original field name is added in the description fields that is available by going into the observable from the case.  

## Debug

From menu:  `Splunk > Settings > Alert actions > Create theHive Alert`  
you can get the following search to see what is going on :  
`index=_internal sourcetype=splunkd component=sendmodalert action="create_thehive_alert"`  
