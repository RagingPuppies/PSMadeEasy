function DME-Headers {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0
        )

    [string] $Date = (get-date -format R (get-date).AddHours(0-(Get-Date -UFormat "%Z")).AddMilliseconds(+$offset))
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA1
    $hmacsha.key = [Text.Encoding]::ASCII.GetBytes($Secret)
    $signature = $hmacsha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Date))
    $hash = [string]::join("", ($signature | % {([int]$_).toString('x2')}))

    $headers = @{
    "x-dnsme-apiKey" = $apikey;
    "x-dnsme-requestDate" = $Date;
    "x-dnsme-hmac" = $hash 
    }
    return $headers
}


function DME-GetZones {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox'
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/"

    try {



    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method GET -Uri $URI -Headers $headers -ContentType "application/json"

    $object = $response.content | ConvertFrom-Json
            
        return $object.data

        }

    catch {

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }


function DME-AddZone {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $domain
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/"

    try {

    $postParams = @{name=$domain} | ConvertTo-Json

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method POST -Uri $URI -Headers $headers -ContentType "application/json" -Body $postParams

    $object = $response.content | ConvertFrom-Json
    
    $status = $response.StatusDescription
        
        $zone_info = New-Object -TypeName psobject
        $zone_info | Add-Member -MemberType NoteProperty -Name Status -Value $status
        $zone_info | Add-Member -MemberType NoteProperty -Name Name -Value $object.name
        $zone_info | Add-Member -MemberType NoteProperty -Name ID -Value $object.id

        return $zone_info

        }

    catch {

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }


function DME-AddMultiZones {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $domains
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/"

    try {

    $postParams = @{names=$domains} | ConvertTo-Json

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method POST -Uri $URI -Headers $headers -ContentType "application/json" -Body $postParams

    $object = $response.content | ConvertFrom-Json
    
    $status = $response.StatusDescription

    $objects = @()

        foreach ($obj in $object) {

        $zone_info = New-Object -TypeName psobject
        $zone_info | Add-Member -MemberType NoteProperty -Name Status -Value $status
        $zone_info | Add-Member -MemberType NoteProperty -Name ID -Value $obj
            
            $objects += $zone_info

            }
        return $objects

        }

    catch {

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }

function DME-RemoveMultiZones {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $ids
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/"

    try {

    $ids = $($ids | sort -Unique) -join ","
    
    $postParams = "[$ids]"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $approve = read-host "Are you sure you want to DELETE?(type yes)"
    
    if ($approve -eq 'yes'){

    $response = Invoke-WebRequest -Method DELETE -Uri $URI -Headers $headers -ContentType "application/json" -Body $postParams
    
    }
    
    $status = $response.StatusDescription


        return "$ids Deleted"

        }

    catch {

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }



function DME-GetRecords {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $DomainID
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/$DomainID/records"

    try {

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method GET -Uri $URI -Headers $headers -ContentType "application/json"

    $object = $response.content | ConvertFrom-Json

        return $object.data

        }

    catch {
        

        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }


function DME-NewRecord {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $DomainID,
            [Parameter(Mandatory=$false)]
            [string]$Name,
            [Parameter(Mandatory=$false)]
            [string]$Value,
            [Parameter(Mandatory=$false)]
            [ValidateSet('false','true')]
            [string]$Failover = 'false',
            [Parameter(Mandatory=$false)]
            [ValidateSet('False','True')]
            [string]$Monitor = 'False',
            [Parameter(Mandatory=$false)]
            [int]$mxLevel = 0,
            [Parameter(Mandatory=$false)]
            [int]$weight = 0,
            [Parameter(Mandatory=$false)]
            [int]$priority = 0,
            [Parameter(Mandatory=$false)]
            [int]$port = 0,
            [Parameter(Mandatory=$true)]
            [ValidateSet('A', 'AAAA', 'ANAME', 'CNAME', 'HTTPRED', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SPF','SOA')]
            [string]$Type,
            [Parameter(Mandatory=$false)]
            [int]$TTL = 1800
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/$DomainID/records"

    try {

    $postParams = @{name=$Name;type=$Type;value=$Value;ttl=$TTL;gtdLocation='DEFAULT';weight=$weight;failover=$failover;mxLevel=$mxLevel;port=$port;priority=$priority;} | ConvertTo-Json

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method POST -Uri $URI -Headers $headers -ContentType "application/json" -Body $postParams

    $record = $response.content | ConvertFrom-Json  

        return $record

        }

    catch {
        
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }


function DME-UpdateRecord {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $DomainID,
            [Parameter(Mandatory=$true)]
            $RecordID,
            [Parameter(Mandatory=$false)]
            [string]$Name,
            [Parameter(Mandatory=$false)]
            [string]$Value,
            [Parameter(Mandatory=$false)]
            [ValidateSet('false','true')]
            [string]$Failover = 'false',
            [Parameter(Mandatory=$false)]
            [ValidateSet('False','True')]
            [string]$Monitor = 'False',
            [Parameter(Mandatory=$false)]
            [int]$mxLevel = 0,
            [Parameter(Mandatory=$false)]
            [int]$weight = 0,
            [Parameter(Mandatory=$false)]
            [int]$priority = 0,
            [Parameter(Mandatory=$false)]
            [int]$port = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('A', 'AAAA', 'ANAME', 'CNAME', 'HTTPRED', 'MX', 'NS', 'PTR', 'SRV', 'TXT', 'SPF','SOA')]
            [string]$Type,
            [Parameter(Mandatory=$false)]
            [int]$TTL = 1800
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/$DomainID/records/$RecordID"

    try {

    $postParams = @{name=$Name;type=$Type;value=$Value;ttl=$TTL;gtdLocation='DEFAULT';weight=$weight;failover=$failover;mxLevel=$mxLevel;port=$port;priority=$priority;id=$RecordID;} | ConvertTo-Json

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method PUT -Uri $URI -Headers $headers -ContentType "application/json" -Body $postParams

    if ($response.StatusDescription -eq 'OK'){

        return "Updated"

        }

        }

    catch {
        
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }


function DME-DeleteRecord {

     param(
            [Parameter(Mandatory=$true)]
            [string]$apikey,
            [Parameter(Mandatory=$true)]
            [string]$secret,
            [Parameter(Mandatory=$false)]
            [int]$offset = 0,
            [Parameter(Mandatory=$false)]
            [ValidateSet('api.sandbox','api')]
            [string]$APIEnvironment = 'api.sandbox',
            [Parameter(Mandatory=$true)]
            $DomainID,
            [Parameter(Mandatory=$true)]
            $RecordID
            
        )

    $headers = DME-Headers -apikey $apikey -secret $secret -offset $offset

    $URI = "https://$APIEnvironment.dnsmadeeasy.com/V2.0/dns/managed/$DomainID/records/$RecordID"

    try {

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method DELETE -Uri $URI -Headers $headers -ContentType "application/json" 

    if ($response.StatusDescription -eq 'OK'){

        return "Deleted"

        }

        }

    catch {
        
        $result = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($result)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        write-host -ForegroundColor Red "ERROR:" ($reader.ReadToEnd() | ConvertFrom-Json).error

    }

        }

