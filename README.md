# PSMadeEasy
Powershell Module for Dnsmadeeasy API
This Module was Created in order to automate some DNS processes (like certificate activation and more)
In order to use it import it to your script - 
Import-Module .\PSMadeEasy.ps1

In some cases there is an issue with the time compare between your local time and DNSMadeEasy time, use -offset for fixing that(Miliseconds).
Example of function with offset:

DME-GetZones -apikey xcxxcdsc-csdc-sdcsdc-9999-1231231 -secret 1231231231-asd123-asdad1-asd1-acaqsd124312 -offset 222000

That will return PSobject with all the zones under this API account. 

processMulti       : False
activeThirdParties : {}
folderId           : 2141
gtdEnabled         : False
pendingActionId    : 0
updated            : 1541624635670
created            : 1541548800000
name               : test00001.com
id                 : 887052





