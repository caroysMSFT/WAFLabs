# WAFLabs
For the Web Application Firewall lab code


## Log Analytics Queries

For checking relevant details of rule hits:

AzureDiagnostics
| where Category =="ApplicationGatewayFirewallLog"
| where TimeGenerated  > ago(10m)
| project TimeGenerated, requestUri_s, requestQuery_s, Message, details_data_s, details_file_s, details_line_s, details_message_s
