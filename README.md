# PSMadeEasy
Powershell Module for Dnsmadeeasy API
This Module was Created in order to automate some DNS processes (like certificate activation and more)
In order to use it import it to your script - 
Import-Module .\PSMadeEasy.ps1

In some cases there is an issue with the time compare between your local time and DNSMadeEasy time, use -offset for fixing that(Miliseconds).
Example of function with offset:

DME-GetZones -apikey xcxxcdsc-csdc-sdcsdc-9999-1231231 -secret 1231231231-asd123-asdad1-asd1-acaqsd124312 -offset 222000

That will return PSobject with all the zones under this API account. 

Current functions:

DME-Headers - Creates relevant headers for API access.

DME-GetZones - Get zones list.

DME-AddZone - Adds a Zone.

DME-AddMultiZones - Creates Multiple Zones at one call.

DME-RemoveMultiZones - Removes Multiple Zones at one call.

DME-GetRecords - Get records by Domain ID.

DME-NewRecord - Adds new record to zone. (supports 'A', 'AAAA', 'ANAME', 'CNAME', 'HTTPRED', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SPF','SOA')

DME-UpdateRecord - Updates a record by Record ID.

DME-DeleteRecord - Removes a record by Record ID.






