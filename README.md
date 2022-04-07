[comment]: # "Auto-generated SOAR connector documentation"
# Carbon Black Defense

Publisher: Splunk  
Connector Version: 2\.2\.0  
Product Vendor: Carbon Black  
Product Name: Defense  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.2\.0  

This app integrates with an instance of Carbon Black defense to run investigative and generic actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2018-2022 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
There are four different sets of credentials for this app - a SIEM key, a Custom API Key, an
Organization Key, and an API key. The action **get notifications** uses the SIEM key. This means the
**siem_connector_id** and the **siem_key** asset configuration parameters are required to run the
**get notifications** action. The actions **list processes** , **get event** , **list events** ,
**list devices** , **update device** , and **get alert** requires Custom API Key along with
Organization Key meaning the **custom_api_connecter_id** , **custom_api_key** , and **org_key** are
required to run these actions. All other actions use the API key, meaning that the
**api_connector_id** and **api_key** asset configuration parameters are required for those
actions.  
  
**NOTE:** Test connectivity will only check the API credentials, it will NOT check the SIEM Key
credentials, Organization Key, and Custom Key credentials.  
  
**To Generate Keys**  
To get started with the Carbon black Defense API to integrate with Phantom, log into the Carbon
black Defense web portal and go to Settings then API Access. From here you can retrieve ORG KEY, API
ID which is used as API Connector ID in Phantom app asset, and API Secret Key which is used as API
Key in Phantom app asset. To Generate SIEM Connector ID and SIEM Key select SIEM in the **Access
Level type** . To Generate API Connector ID and API Key select Live Response in the **Access Level
type** . To Generate Custom API Connector ID and Custom API Key select Custom in the **Access Level
type** and accordingly select **Custom Access Level** which has appropriate permissions.  
  
**Custom Access Levels required the following permissions**

-   For 'org.search.events' allow permission to 'CREATE' and 'READ'.
-   For 'device' allow permissions for 'READ'.
-   For 'device.policy' allow permissions for 'UPDATE'.
-   For 'device.bg-scan' allow permissions for 'EXECUTE'.
-   For 'device.bypass' allow permissions for 'EXECUTE'.
-   For 'device.quarantine' allow permissions for 'EXECUTE'.
-   For 'org.kits' allow permissions for 'EXECUTE'.
-   For 'device.uninstall' allow permissions for 'EXECUTE'.
-   For 'device.deregistered' allow permissions for 'DELETE'.
-   For 'org.alerts' allow permissions for 'READ'.
-   For 'org.alerts.dismiss' allow permissions for 'EXECUTE'.
-   For 'org.alerts.notes' allow permissions for 'CREATE', 'READ', and 'DELETE'.
-   For 'org.search.events', allow permission for 'CREATE' and 'READ'.

## Port Information

The app uses HTTP/HTTPS protocol for communicating with the Carbon Black Defense Server. Below are
the default ports used by Splunk SOAR.

| Service Name | Transport Protocol | Port |
|--------------|--------------------|------|
| http         | tcp                | 80   |
| https        | tcp                | 443  |


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Defense asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api\_url** |  required  | string | API URL \(e\.g\. https\://defense\.conferdeploy\.net\)
**ph\_0** |  optional  | ph | Placeholder
**api\_connector\_id** |  optional  | password | API Connector ID
**api\_key** |  optional  | password | API Key
**siem\_connector\_id** |  optional  | password | SIEM Connector ID
**siem\_key** |  optional  | password | SIEM Key
**custom\_api\_connector\_id** |  optional  | password | Custom API Connector ID
**custom\_api\_key** |  optional  | password | Custom API Key
**org\_key** |  optional  | password | Organization Key

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the supplied API Key  
[list devices](#action-list-devices) - List devices connected to CB Defense  
[update device](#action-update-device) - Change the policy of a device connected to CB Defense  
[list policies](#action-list-policies) - List policies that exist on CB Defense  
[add policy](#action-add-policy) - Create a new policy on CB Defense  
[delete policy](#action-delete-policy) - Delete a policy on CB Defense  
[add rule](#action-add-rule) - Add a rule to a policy on CB Defense  
[delete rule](#action-delete-rule) - Delete a rule from a policy on CB Defense  
[list processes](#action-list-processes) - List processes that match supplied filter criteria  
[list events](#action-list-events) - List events that match supplied filter criteria  
[get event](#action-get-event) - Get information about an event  
[get alert](#action-get-alert) - Get information about an alert  
[get notifications](#action-get-notifications) - Get notifications from CB Defense  
[update policy](#action-update-policy) - Updates an existing policy on the Carbon Black Defense server  
[get policy](#action-get-policy) - Retrieves an existing policy from the Carbon Black Defense server  

## action: 'test connectivity'
Validate the supplied API Key

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list devices'
List devices connected to CB Defense

Type: **investigate**  
Read only: **True**

The results of this action can be paged using the <b>start</b> and the <b>limit</b> parameters\. For example, to return the first 10 results, set the <b>start</b> to 1 and the <b>limit</b> to 10\. To return the next 10 results, set the <b>start</b> to 11 and keep the <b>limit</b> at 10\. This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start** |  optional  | Number of first result to return | numeric | 
**limit** |  optional  | Maximum number of results to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.start | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.email | string | 
action\_result\.data\.\*\.status | string | 
action\_result\.data\.\*\.base\_device | string | 
action\_result\.data\.\*\.nsx\_enabled | string | 
action\_result\.data\.\*\.quarantined | boolean | 
action\_result\.data\.\*\.cloud\_provider\_tags | string | 
action\_result\.data\.\*\.auto\_scaling\_group\_name | string | 
action\_result\.data\.\*\.virtual\_private\_cloud\_id | string | 
action\_result\.data\.\*\.cloud\_provider\_account\_id | string | 
action\_result\.data\.\*\.cloud\_provider\_resource\_id | string | 
action\_result\.data\.\*\.nsx\_distributed\_firewall\_policy | string | 
action\_result\.data\.\*\.activation\_code | string | 
action\_result\.data\.\*\.activation\_code\_expiry\_time | string | 
action\_result\.data\.\*\.ad\_group\_id | numeric | 
action\_result\.data\.\*\.appliance\_name | string | 
action\_result\.data\.\*\.appliance\_uuid | string | 
action\_result\.data\.\*\.av\_ave\_version | string | 
action\_result\.data\.\*\.av\_engine | string | 
action\_result\.data\.\*\.av\_last\_scan\_time | string | 
action\_result\.data\.\*\.av\_master | boolean | 
action\_result\.data\.\*\.av\_pack\_version | string | 
action\_result\.data\.\*\.av\_product\_version | string | 
action\_result\.data\.\*\.av\_status | string | 
action\_result\.data\.\*\.av\_update\_servers | string | 
action\_result\.data\.\*\.av\_vdf\_version | string | 
action\_result\.data\.\*\.cluster\_name | string | 
action\_result\.data\.\*\.current\_sensor\_policy\_name | string | 
action\_result\.data\.\*\.datacenter\_name | string | 
action\_result\.data\.\*\.deployment\_type | string | 
action\_result\.data\.\*\.deregistered\_time | string | 
action\_result\.data\.\*\.device\_meta\_data\_item\_list\.\*\.key\_name | string | 
action\_result\.data\.\*\.device\_meta\_data\_item\_list\.\*\.key\_value | string | 
action\_result\.data\.\*\.device\_meta\_data\_item\_list\.\*\.position | numeric | 
action\_result\.data\.\*\.device\_owner\_id | numeric | 
action\_result\.data\.\*\.encoded\_activation\_code | string | 
action\_result\.data\.\*\.esx\_host\_name | string | 
action\_result\.data\.\*\.esx\_host\_uuid | string | 
action\_result\.data\.\*\.first\_name | string | 
action\_result\.data\.\*\.golden\_device | string | 
action\_result\.data\.\*\.golden\_device\_id | string | 
action\_result\.data\.\*\.id | numeric |  `cb defense device id` 
action\_result\.data\.\*\.last\_contact\_time | string | 
action\_result\.data\.\*\.last\_device\_policy\_changed\_time | string | 
action\_result\.data\.\*\.last\_device\_policy\_requested\_time | string | 
action\_result\.data\.\*\.last\_external\_ip\_address | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.last\_internal\_ip\_address | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.last\_location | string | 
action\_result\.data\.\*\.last\_name | string | 
action\_result\.data\.\*\.last\_policy\_updated\_time | string | 
action\_result\.data\.\*\.last\_reported\_time | string | 
action\_result\.data\.\*\.last\_reset\_time | string | 
action\_result\.data\.\*\.last\_shutdown\_time | string | 
action\_result\.data\.\*\.linux\_kernel\_version | string | 
action\_result\.data\.\*\.login\_user\_name | string | 
action\_result\.data\.\*\.mac\_address | string | 
action\_result\.data\.\*\.middle\_name | string | 
action\_result\.data\.\*\.organization\_id | numeric | 
action\_result\.data\.\*\.organization\_name | string | 
action\_result\.data\.\*\.os | string | 
action\_result\.data\.\*\.os\_version | string | 
action\_result\.data\.\*\.passive\_mode | boolean | 
action\_result\.data\.\*\.policy\_id | numeric |  `cb defense policy id` 
action\_result\.data\.\*\.policy\_name | string | 
action\_result\.data\.\*\.policy\_override | boolean | 
action\_result\.data\.\*\.registered\_time | string | 
action\_result\.data\.\*\.scan\_last\_action\_time | string | 
action\_result\.data\.\*\.scan\_last\_complete\_time | string | 
action\_result\.data\.\*\.scan\_status | string | 
action\_result\.data\.\*\.sensor\_kit\_type | string | 
action\_result\.data\.\*\.sensor\_out\_of\_date | boolean | 
action\_result\.data\.\*\.sensor\_pending\_update | boolean | 
action\_result\.data\.\*\.sensor\_states | string | 
action\_result\.data\.\*\.sensor\_version | string | 
action\_result\.data\.\*\.target\_priority | string | 
action\_result\.data\.\*\.uninstall\_code | string | 
action\_result\.data\.\*\.vcenter\_host\_url | string | 
action\_result\.data\.\*\.vcenter\_name | string | 
action\_result\.data\.\*\.vcenter\_uuid | string | 
action\_result\.data\.\*\.vdi\_base\_device | string | 
action\_result\.data\.\*\.virtual\_machine | boolean | 
action\_result\.data\.\*\.virtualization\_provider | string | 
action\_result\.data\.\*\.vm\_ip | string | 
action\_result\.data\.\*\.vm\_name | string | 
action\_result\.data\.\*\.vm\_uuid | string | 
action\_result\.data\.\*\.vulnerability\_score | numeric | 
action\_result\.data\.\*\.vulnerability\_severity | string | 
action\_result\.data\.\*\.windows\_platform | string | 
action\_result\.summary\.num\_devices | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update device'
Change the policy of a device connected to CB Defense

Type: **generic**  
Read only: **False**

This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**device\_id** |  required  | ID of device to update | string |  `cb defense device id` 
**policy\_id** |  required  | ID of policy to assign to device | string |  `cb defense policy id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.device\_id | string |  `cb defense device id` 
action\_result\.parameter\.policy\_id | string |  `cb defense policy id` 
action\_result\.data\.\*\.message | string | 
action\_result\.summary\.device\_id | string |  `cb defense device id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list policies'
List policies that exist on CB Defense

Type: **investigate**  
Read only: **True**

This Action requires API Key and API Connector ID\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.orgId | numeric | 
action\_result\.data\.\*\.vdiAutoDeregInactiveIntervalMs | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.id | numeric |  `cb defense policy id` 
action\_result\.data\.\*\.latestRevision | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.policy\.avSettings\.apc\.enabled | boolean | 
action\_result\.data\.\*\.policy\.avSettings\.apc\.maxExeDelay | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.apc\.maxFileSize | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.apc\.riskLevel | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.features\.\*\.enabled | boolean | 
action\_result\.data\.\*\.policy\.avSettings\.features\.\*\.name | string | 
action\_result\.data\.\*\.policy\.avSettings\.onAccessScan\.profile | string | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.profile | string | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.scanCdDvd | string | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.scanUsb | string | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.schedule\.days | string | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.schedule\.rangeHours | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.schedule\.recoveryScanIfMissed | boolean | 
action\_result\.data\.\*\.policy\.avSettings\.onDemandScan\.schedule\.startHour | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.signatureUpdate\.schedule\.fullIntervalHours | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.signatureUpdate\.schedule\.initialRandomDelayHours | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.signatureUpdate\.schedule\.intervalHours | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.updateServers\.servers\.\*\.flags | numeric | 
action\_result\.data\.\*\.policy\.avSettings\.updateServers\.servers\.\*\.regId | string | 
action\_result\.data\.\*\.policy\.avSettings\.updateServers\.servers\.\*\.server | string |  `url` 
action\_result\.data\.\*\.policy\.avSettings\.updateServers\.serversForOffSiteDevices | string |  `url` 
action\_result\.data\.\*\.policy\.directoryActionRules | string | 
action\_result\.data\.\*\.policy\.directoryActionRules\.\*\.actions\.FILE\_UPLOAD | boolean | 
action\_result\.data\.\*\.policy\.directoryActionRules\.\*\.actions\.PROTECTION | boolean | 
action\_result\.data\.\*\.policy\.directoryActionRules\.\*\.path | string |  `file path` 
action\_result\.data\.\*\.policy\.id | numeric | 
action\_result\.data\.\*\.policy\.knownBadHashAutoDeleteDelayMs | string | 
action\_result\.data\.\*\.policy\.rules | string | 
action\_result\.data\.\*\.policy\.rules\.\*\.action | string | 
action\_result\.data\.\*\.policy\.rules\.\*\.application\.type | string | 
action\_result\.data\.\*\.policy\.rules\.\*\.application\.value | string |  `file path`  `file name` 
action\_result\.data\.\*\.policy\.rules\.\*\.id | numeric | 
action\_result\.data\.\*\.policy\.rules\.\*\.operation | string | 
action\_result\.data\.\*\.policy\.rules\.\*\.required | boolean | 
action\_result\.data\.\*\.policy\.sensorSettings\.\*\.name | string | 
action\_result\.data\.\*\.policy\.sensorSettings\.\*\.value | string | 
action\_result\.data\.\*\.priorityLevel | string | 
action\_result\.data\.\*\.systemPolicy | boolean | 
action\_result\.data\.\*\.version | numeric | 
action\_result\.summary\.num\_policies | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add policy'
Create a new policy on CB Defense

Type: **generic**  
Read only: **False**

The <b>json\_fields</b> parameter can be used to configure other fields in the created policy\. This parameter takes a JSON dictionary with the format of the policy field seen <a href="https\://developer\.carbonblack\.com/reference/cb\-defense/1/rest\-api/\#create\-new\-policy">here</a>\. In some negative scenarios action will fail with an API error message "Error creating policy \- Error modifying policy" but policy will be created on the server with the given name\. This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**name** |  required  | Name | string | 
**description** |  required  | Description | string | 
**priority** |  required  | Priority Level | string | 
**json\_fields** |  optional  | Other configuration fields in JSON format\. Defaults to '\{"sensorSettings"\: \[\]\}' if left empty | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.description | string | 
action\_result\.parameter\.json\_fields | string | 
action\_result\.parameter\.name | string | 
action\_result\.parameter\.priority | string | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.policyId | numeric |  `cb defense policy id` 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.policy\_id | numeric |  `cb defense policy id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete policy'
Delete a policy on CB Defense

Type: **generic**  
Read only: **False**

This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID | string |  `cb defense policy id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `cb defense policy id` 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.policy\_id | string |  `cb defense policy id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'add rule'
Add a rule to a policy on CB Defense

Type: **generic**  
Read only: **False**

This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | ID | string |  `cb defense policy id` 
**rules** |  required  | JSON dictionary containing rules configuration | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `cb defense policy id` 
action\_result\.parameter\.rules | string | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.ruleId | numeric | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.rule\_id | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'delete rule'
Delete a rule from a policy on CB Defense

Type: **generic**  
Read only: **False**

This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_id** |  required  | Policy ID | string |  `cb defense policy id` 
**rule\_id** |  required  | Rule ID | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.policy\_id | string |  `cb defense policy id` 
action\_result\.parameter\.rule\_id | string | 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.rule\_id | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list processes'
List processes that match supplied filter criteria

Type: **investigate**  
Read only: **True**

The examples for the <b>search\_span</b> parameter are <b>1d</b>, <b>1w</b>, <b>2y</b>, <b>2h</b>, <b>1m</b>, or <b>50s</b> \(where y=year, w=week, d=day, h=hour, m=minute, s=second\)\. The results of this action can be paged using the <b>start</b> and <b>limit</b> parameters\. For example, to return the first 10 results, set the <b>start</b> to 1 and the <b>limit</b> to 10\. To return the next 10 results, set the <b>start</b> to 11 and keep the <b>limit</b> at 10\. This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP | string |  `ip`  `ipv6` 
**host\_name** |  optional  | Host Name | string |  `host name` 
**owner** |  optional  | Owner | string | 
**search\_span** |  optional  | Number of days back to search | string | 
**start** |  optional  | Number of first result to return | numeric | 
**limit** |  optional  | Maximum number of results to return | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.host\_name | string |  `host name` 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.limit | numeric | 
action\_result\.parameter\.owner | string | 
action\_result\.parameter\.search\_span | string | 
action\_result\.parameter\.start | numeric | 
action\_result\.data\.\*\.legacy | boolean | 
action\_result\.data\.\*\.enriched | boolean | 
action\_result\.data\.\*\.blocked\_name | string | 
action\_result\.data\.\*\.blocked\_effective\_reputation | string | 
action\_result\.data\.\*\.alert\_category | string | 
action\_result\.data\.\*\.alert\_id | string |  `cb defense alert id` 
action\_result\.data\.\*\.backend\_timestamp | string | 
action\_result\.data\.\*\.childproc\_count | numeric | 
action\_result\.data\.\*\.crossproc\_count | numeric | 
action\_result\.data\.\*\.device\_group\_id | numeric | 
action\_result\.data\.\*\.device\_id | numeric |  `cb defense device id` 
action\_result\.data\.\*\.device\_name | string | 
action\_result\.data\.\*\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.device\_timestamp | string | 
action\_result\.data\.\*\.filemod\_count | numeric | 
action\_result\.data\.\*\.ingress\_time | numeric | 
action\_result\.data\.\*\.modload\_count | numeric | 
action\_result\.data\.\*\.netconn\_count | numeric | 
action\_result\.data\.\*\.org\_id | string | 
action\_result\.data\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.process\_guid | string | 
action\_result\.data\.\*\.process\_hash | string |  `sha256` 
action\_result\.data\.\*\.process\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.process\_pid | numeric | 
action\_result\.data\.\*\.process\_terminated | boolean | 
action\_result\.data\.\*\.process\_username | string | 
action\_result\.data\.\*\.regmod\_count | numeric | 
action\_result\.data\.\*\.scriptload\_count | numeric | 
action\_result\.data\.\*\.watchlist\_hit | string | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list events'
List events that match supplied filter criteria

Type: **investigate**  
Read only: **True**

The parameters <b>ip</b>, <b>host\_name</b>, <b>hash</b>, <b>application</b>, and <b>owner</b> apply only to the device the event came from\. Thus, for example, the <b>ip</b> parameters cannot be used to search for a destination IP\. The examples for the <b>search\_span</b> parameter are <b>1d</b>, <b>1w</b>, <b>2y</b>, <b>2h</b>, <b>1m</b>, or <b>50s</b> \(where y=year, w=week, d=day, h=hour, m=minute, s=second\)\. This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  optional  | IP | string |  `ip`  `ipv6` 
**host\_name** |  optional  | Host Name | string |  `host name` 
**hash** |  optional  | SHA\-256 Hash | string |  `hash`  `sha256` 
**application** |  optional  | Application Name | string | 
**event\_type** |  optional  | Event Type | string | 
**owner** |  optional  | Owner | string | 
**search\_span** |  optional  | Number of days back to search | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.application | string | 
action\_result\.parameter\.event\_type | string | 
action\_result\.parameter\.hash | string |  `hash`  `sha256` 
action\_result\.parameter\.host\_name | string |  `host name` 
action\_result\.parameter\.ip | string |  `ip`  `ipv6` 
action\_result\.parameter\.owner | string | 
action\_result\.parameter\.search\_span | string | 
action\_result\.data\.\*\.event\_network\_inbound | boolean | 
action\_result\.data\.\*\.event\_network\_location | string | 
action\_result\.data\.\*\.event\_network\_protocol | string | 
action\_result\.data\.\*\.event\_network\_local\_ipv4 | string | 
action\_result\.data\.\*\.event\_network\_remote\_ipv4 | string | 
action\_result\.data\.\*\.event\_network\_remote\_port | numeric | 
action\_result\.data\.\*\.backend\_timestamp | string | 
action\_result\.data\.\*\.device\_group\_id | numeric | 
action\_result\.data\.\*\.device\_id | numeric |  `cb defense device id` 
action\_result\.data\.\*\.device\_name | string | 
action\_result\.data\.\*\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.device\_timestamp | string | 
action\_result\.data\.\*\.enriched | boolean | 
action\_result\.data\.\*\.enriched\_event\_type | string | 
action\_result\.data\.\*\.event\_description | string | 
action\_result\.data\.\*\.event\_id | string |  `cb defense event id` 
action\_result\.data\.\*\.event\_type | string | 
action\_result\.data\.\*\.ingress\_time | numeric | 
action\_result\.data\.\*\.legacy | boolean | 
action\_result\.data\.\*\.org\_id | string | 
action\_result\.data\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.process\_guid | string | 
action\_result\.data\.\*\.process\_hash | string |  `sha256` 
action\_result\.data\.\*\.process\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.process\_pid | numeric | 
action\_result\.data\.\*\.process\_username | string | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get event'
Get information about an event

Type: **investigate**  
Read only: **True**

This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Event ID | string |  `cb defense event id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `cb defense event id` 
action\_result\.data\.\*\.netconn\_ipv4 | numeric | 
action\_result\.data\.\*\.netconn\_port | numeric | 
action\_result\.data\.\*\.netconn\_domain | string | 
action\_result\.data\.\*\.netconn\_inbound | boolean | 
action\_result\.data\.\*\.netconn\_location | string | 
action\_result\.data\.\*\.netconn\_protocol | string | 
action\_result\.data\.\*\.netconn\_local\_ipv4 | numeric | 
action\_result\.data\.\*\.netconn\_local\_port | numeric | 
action\_result\.data\.\*\.event\_network\_inbound | boolean | 
action\_result\.data\.\*\.event\_network\_location | string | 
action\_result\.data\.\*\.event\_network\_protocol | string | 
action\_result\.data\.\*\.event\_network\_local\_ipv4 | string | 
action\_result\.data\.\*\.event\_network\_remote\_ipv4 | string | 
action\_result\.data\.\*\.event\_network\_remote\_port | numeric | 
action\_result\.data\.\*\.backend\_timestamp | string | 
action\_result\.data\.\*\.childproc\_cmdline | string |  `file path` 
action\_result\.data\.\*\.childproc\_cmdline\_length | numeric | 
action\_result\.data\.\*\.childproc\_effective\_reputation | string | 
action\_result\.data\.\*\.childproc\_effective\_reputation\_source | string | 
action\_result\.data\.\*\.childproc\_guid | string | 
action\_result\.data\.\*\.childproc\_hash | string |  `sha256` 
action\_result\.data\.\*\.childproc\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.childproc\_pid | numeric | 
action\_result\.data\.\*\.childproc\_reputation | string | 
action\_result\.data\.\*\.device\_external\_ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.device\_group\_id | numeric | 
action\_result\.data\.\*\.device\_id | numeric | 
action\_result\.data\.\*\.device\_installed\_by | string |  `email` 
action\_result\.data\.\*\.device\_internal\_ip | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.device\_location | string | 
action\_result\.data\.\*\.device\_name | string | 
action\_result\.data\.\*\.device\_os | string | 
action\_result\.data\.\*\.device\_os\_version | string | 
action\_result\.data\.\*\.device\_policy | string | 
action\_result\.data\.\*\.device\_policy\_id | numeric | 
action\_result\.data\.\*\.device\_target\_priority | string | 
action\_result\.data\.\*\.device\_timestamp | string | 
action\_result\.data\.\*\.document\_guid | string | 
action\_result\.data\.\*\.enriched | boolean | 
action\_result\.data\.\*\.enriched\_event\_type | string | 
action\_result\.data\.\*\.event\_description | string | 
action\_result\.data\.\*\.event\_id | string |  `md5` 
action\_result\.data\.\*\.event\_report\_code | string | 
action\_result\.data\.\*\.event\_type | string | 
action\_result\.data\.\*\.ingress\_time | numeric | 
action\_result\.data\.\*\.legacy | boolean | 
action\_result\.data\.\*\.org\_id | string | 
action\_result\.data\.\*\.parent\_effective\_reputation | string | 
action\_result\.data\.\*\.parent\_effective\_reputation\_source | string | 
action\_result\.data\.\*\.parent\_guid | string | 
action\_result\.data\.\*\.parent\_hash | string |  `sha256` 
action\_result\.data\.\*\.parent\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.parent\_pid | numeric | 
action\_result\.data\.\*\.parent\_reputation | string | 
action\_result\.data\.\*\.process\_cmdline | string |  `file path` 
action\_result\.data\.\*\.process\_cmdline\_length | numeric | 
action\_result\.data\.\*\.process\_effective\_reputation | string | 
action\_result\.data\.\*\.process\_effective\_reputation\_source | string | 
action\_result\.data\.\*\.process\_guid | string | 
action\_result\.data\.\*\.process\_hash | string |  `sha256` 
action\_result\.data\.\*\.process\_name | string |  `file name`  `file path` 
action\_result\.data\.\*\.process\_pid | numeric | 
action\_result\.data\.\*\.process\_reputation | string | 
action\_result\.data\.\*\.process\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.process\_start\_time | string | 
action\_result\.data\.\*\.process\_username | string | 
action\_result\.summary\.num\_results | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get alert'
Get information about an alert

Type: **investigate**  
Read only: **True**

This Action requires Custom API Key, Custom API Connector ID, and Organization Key\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Alert ID/Legacy alert ID | string |  `cb defense alert id`  `cb defense legacy alert id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `cb defense alert id`  `cb defense legacy alert id` 
action\_result\.data\.\*\.num\_found | numeric | 
action\_result\.data\.\*\.num\_available | numeric | 
action\_result\.data\.\*\.reason\_code | string | 
action\_result\.data\.\*\.sensor\_action | string | 
action\_result\.data\.\*\.policy\_applied | string | 
action\_result\.data\.\*\.device\_location | string | 
action\_result\.data\.\*\.threat\_activity\_c2 | string | 
action\_result\.data\.\*\.created\_by\_event\_id | string | 
action\_result\.data\.\*\.threat\_activity\_dlp | string | 
action\_result\.data\.\*\.threat\_activity\_phish | string | 
action\_result\.data\.\*\.blocked\_threat\_category | string | 
action\_result\.data\.\*\.threat\_cause\_parent\_guid | string | 
action\_result\.data\.\*\.threat\_cause\_process\_guid | string | 
action\_result\.data\.\*\.not\_blocked\_threat\_category | string | 
action\_result\.data\.\*\.threat\_cause\_cause\_event\_id | string | 
action\_result\.data\.\*\.threat\_cause\_actor\_process\_pid | string | 
action\_result\.data\.\*\.category | string | 
action\_result\.data\.\*\.count | numeric | 
action\_result\.data\.\*\.create\_time | string | 
action\_result\.data\.\*\.device\_id | numeric |  `cb defense device id` 
action\_result\.data\.\*\.device\_name | string | 
action\_result\.data\.\*\.device\_os | string | 
action\_result\.data\.\*\.device\_os\_version | string | 
action\_result\.data\.\*\.device\_username | string |  `email`  `user name` 
action\_result\.data\.\*\.document\_guid | string | 
action\_result\.data\.\*\.first\_event\_time | string | 
action\_result\.data\.\*\.id | string |  `cb defense alert id` 
action\_result\.data\.\*\.ioc\_field | string | 
action\_result\.data\.\*\.ioc\_hit | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.ioc\_id | string | 
action\_result\.data\.\*\.last\_event\_time | string | 
action\_result\.data\.\*\.last\_update\_time | string | 
action\_result\.data\.\*\.legacy\_alert\_id | string |  `cb defense legacy alert id` 
action\_result\.data\.\*\.notes\_present | boolean | 
action\_result\.data\.\*\.org\_key | string | 
action\_result\.data\.\*\.policy\_id | numeric | 
action\_result\.data\.\*\.policy\_name | string | 
action\_result\.data\.\*\.process\_guid | string | 
action\_result\.data\.\*\.process\_name | string |  `file name` 
action\_result\.data\.\*\.reason | string | 
action\_result\.data\.\*\.report\_id | string | 
action\_result\.data\.\*\.report\_name | string | 
action\_result\.data\.\*\.run\_state | string | 
action\_result\.data\.\*\.severity | numeric | 
action\_result\.data\.\*\.tags | string | 
action\_result\.data\.\*\.target\_value | string | 
action\_result\.data\.\*\.threat\_cause\_actor\_md5 | string |  `md5` 
action\_result\.data\.\*\.threat\_cause\_actor\_name | string |  `file path`  `file name` 
action\_result\.data\.\*\.threat\_cause\_actor\_sha256 | string |  `sha256` 
action\_result\.data\.\*\.threat\_cause\_reputation | string | 
action\_result\.data\.\*\.threat\_cause\_threat\_category | string | 
action\_result\.data\.\*\.threat\_cause\_vector | string | 
action\_result\.data\.\*\.threat\_id | string |  `md5` 
action\_result\.data\.\*\.threat\_indicators\.\*\.process\_name | string |  `file name` 
action\_result\.data\.\*\.threat\_indicators\.\*\.sha256 | string |  `sha256` 
action\_result\.data\.\*\.threat\_indicators\.\*\.ttps | string | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.watchlists\.\*\.id | string | 
action\_result\.data\.\*\.watchlists\.\*\.name | string | 
action\_result\.data\.\*\.workflow\.changed\_by | string | 
action\_result\.data\.\*\.workflow\.comment | string | 
action\_result\.data\.\*\.workflow\.last\_update\_time | string | 
action\_result\.data\.\*\.workflow\.remediation | string | 
action\_result\.data\.\*\.workflow\.state | string | 
action\_result\.summary\.device | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get notifications'
Get notifications from CB Defense

Type: **investigate**  
Read only: **True**

This action retrieves the current list of notifications from CB Defense\. Once a notification is retrieved, it cannot be retrieved again\. This Action requires SIEM Key and SIEM Connector ID\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.deviceInfo\.deviceHostName | string |  `host name` 
action\_result\.data\.\*\.deviceInfo\.deviceId | numeric |  `cb defense device id` 
action\_result\.data\.\*\.deviceInfo\.deviceName | string | 
action\_result\.data\.\*\.deviceInfo\.deviceType | string | 
action\_result\.data\.\*\.deviceInfo\.deviceVersion | string | 
action\_result\.data\.\*\.deviceInfo\.email | string | 
action\_result\.data\.\*\.deviceInfo\.externalIpAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.deviceInfo\.groupName | string | 
action\_result\.data\.\*\.deviceInfo\.internalIpAddress | string |  `ip`  `ipv6` 
action\_result\.data\.\*\.deviceInfo\.targetPriorityCode | numeric | 
action\_result\.data\.\*\.deviceInfo\.targetPriorityType | string | 
action\_result\.data\.\*\.eventDescription | string | 
action\_result\.data\.\*\.eventTime | numeric | 
action\_result\.data\.\*\.ruleName | string | 
action\_result\.data\.\*\.threatInfo\.incidentId | string | 
action\_result\.data\.\*\.threatInfo\.indicators\.\*\.applicationName | string | 
action\_result\.data\.\*\.threatInfo\.indicators\.\*\.indicatorName | string | 
action\_result\.data\.\*\.threatInfo\.indicators\.\*\.sha256Hash | string |  `sha256` 
action\_result\.data\.\*\.threatInfo\.score | numeric | 
action\_result\.data\.\*\.threatInfo\.summary | string | 
action\_result\.data\.\*\.threatInfo\.time | numeric | 
action\_result\.data\.\*\.type | string | 
action\_result\.data\.\*\.url | string |  `url` 
action\_result\.summary\.num\_notifications | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'update policy'
Updates an existing policy on the Carbon Black Defense server

Type: **generic**  
Read only: **False**

This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy** |  required  | JSON object containing the policy details \(see https\://developer\.carbonblack\.com/reference/cb\-defense/1/rest\-api/\#create\-new\-policy\) | string | 
**policy\_id** |  required  | The ID of the policy to replace\. This ID must match the ID in the request URL | numeric |  `cb defense policy id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.policy | string | 
action\_result\.parameter\.policy\_id | string |  `cb defense policy id` 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.policy\_id | string |  `cb defense policy id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get policy'
Retrieves an existing policy from the Carbon Black Defense server

Type: **investigate**  
Read only: **True**

This Action requires API Key and API Connector ID\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**policy\_id** |  required  | The ID of the policy to retrieve | numeric |  `cb defense policy id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.policy\_id | string |  `cb defense policy id` 
action\_result\.data\.\*\.message | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.data\.\*\.policyInfo\.orgId | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.profile | string | 
action\_result\.data\.\*\.policyInfo\.policy\.knownBadHashAutoDeleteDelayMs | string | 
action\_result\.data\.\*\.policyInfo\.vdiAutoDeregInactiveIntervalMs | string | 
action\_result\.data\.\*\.policyInfo\.description | string | 
action\_result\.data\.\*\.policyInfo\.id | numeric | 
action\_result\.data\.\*\.policyInfo\.latestRevision | numeric | 
action\_result\.data\.\*\.policyInfo\.name | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.apc\.enabled | boolean | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.apc\.maxExeDelay | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.apc\.maxFileSize | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.apc\.riskLevel | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.features\.\*\.enabled | boolean | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.features\.\*\.name | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onAccessScan\.profile | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.scanCdDvd | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.scanUsb | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.schedule\.days | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.schedule\.rangeHours | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.schedule\.recoveryScanIfMissed | boolean | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.onDemandScan\.schedule\.startHour | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.signatureUpdate\.schedule\.fullIntervalHours | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.signatureUpdate\.schedule\.initialRandomDelayHours | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.signatureUpdate\.schedule\.intervalHours | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.updateServers\.servers\.\*\.flags | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.updateServers\.servers\.\*\.regId | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.updateServers\.servers\.\*\.server\.\*\.name | string | 
action\_result\.data\.\*\.policyInfo\.policy\.avSettings\.updateServers\.serversForOffSiteDevices\.\*\.name | string | 
action\_result\.data\.\*\.policyInfo\.policy\.id | numeric |  `cb defense policy id` 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.action | string | 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.application\.type | string | 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.application\.value | string | 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.id | numeric | 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.operation | string | 
action\_result\.data\.\*\.policyInfo\.policy\.rules\.\*\.required | boolean | 
action\_result\.data\.\*\.policyInfo\.policy\.sensorSettings\.\*\.name | string | 
action\_result\.data\.\*\.policyInfo\.policy\.sensorSettings\.\*\.value | string | 
action\_result\.data\.\*\.policyInfo\.priorityLevel | string | 
action\_result\.data\.\*\.policyInfo\.systemPolicy | boolean | 
action\_result\.data\.\*\.policyInfo\.version | numeric | 
action\_result\.summary\.policy\_id | string |  `cb defense policy id` 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 