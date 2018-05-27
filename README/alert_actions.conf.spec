# This file contains values intended to be shared across
# all user-created Alert Action inputs.  These values will
# have corresponding entries in setup.xml, which defines the
# setup interface shown at Settings->Alert Actions->My Alert
# under the "Setup" column.

# The keys and value types specified here should match
# the keys and values in "default/alert_actions.conf".

# NOTE: This file and the corresponding setup.xml file are
# optional components.

[create_thehive_alert]
param.url = <string>
param.username = <string>
param.password = <string>

param.fields = <csv-list>
* List of fields for the hive.
* It is possible to use wildcards, such as "src_*"
