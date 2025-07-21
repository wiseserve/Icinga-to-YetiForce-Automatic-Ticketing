### Ticket Queue Legend (ID)
## "T10": "Monitoring"

### Ticket Status Legend
## "Closed": "Completed"

### Group
## "4": "Unassigned"

### Global variables

# --- Exceptions. The format is like this: Hostname!Servicename ---

$global:service_exceptions = ""

# --- Defined Expiry time for acknowledgements 24h ---

$global:expirytime = (Get-Date (Get-Date).addDays(1) -UFormat %s)

# --- YetiForce API ---

# --- Yeti Token Headers ---

$global:tokenheader = @{
  "x-api-key" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
  "Content-Type" = "application/x-www-form-urlencoded"
  "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
}

# --- Yeti Token Body ---

$global:tokenbody = @"
{
    "userName": "sysadm@wiseserve.net",
    "password": "fasdfdsatAAAawerfd3412e!!!"
}
"@

# --- Retrieve Yeti Token ---

$global:tokenresponse = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/Users/Login" -Method 'POST' -Headers $tokenheader -Body $tokenbody -ContentType 'application/json'
$global:token = $global:tokenresponse.result.token

# --- Yeti Ticket Header ---

$global:headersYeti = @{
  "X-API-KEY" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
  "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
  "Content-Type" = "application/json"
  "x-token" = $token
  "x-row-limit" = "1000000"
}

# --- Icinga API ---

$data3 = "bW9uaXQ="
$APIUser = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data3))
$data4 = "UmFwaGFlbD0xMDI0"
$APIPass = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data4))
$pair = "$($APIUser):$($APIPass)"
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
$basicAuthValue = "Basic $encodedCreds"

Add-Type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@ -ea SilentlyContinue -wa SilentlyContinue
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- Retrieve Host problems from icinga. Hard state only ---

function GetHostProblems {

  $headers = @{
    Authorization = $basicAuthValue
    "accept" = "application/json" }
  $headers.Add("X-HTTP-Method-Override","GET")

  $body = "{
`n    `"filter`": [`"host.last_hard_state==hoststate&&host.acknowledgement==hostacknowledgement&&host.downtime_depth==hostdowntime`"],
`n    `"filter_vars`": {`"hoststate`": 1, `"hostacknowledgement`": 0, `"hostdowntime`": 0},
`n    `"pretty`": true
`n}"

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


  $response = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/hosts" -Method 'POST' -Headers $headers -Body $body

  $global:hosts = $response | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty name

  # --- Call RunHosts Function ---

  RunHosts
}

# --- Retrieve Service problems from icinga. Hard state only - Warning Services ---

function GetServiceProblemsWarning {

  $headers = @{
    Authorization = $basicAuthValue
    "accept" = "application/json" }
  $headers.Add("X-HTTP-Method-Override","GET")

  $body = "{
`n    `"filter`": [`"service.last_hard_state==servicestate&&service.acknowledgement==serviceacknowledgement&&service.handled==servicehandled&&service.last_reachable==servicereachable&&service.downtime_depth==servicedowntime`"],
`n    `"filter_vars`": {`"servicestate`": 1, `"serviceacknowledgement`": 0, `"servicehandled`": false, `"servicereachable`": true, `"servicedowntime`": 0},
`n    `"pretty`": true
`n}"

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


  $response = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/services" -Method 'POST' -Headers $headers -Body $body

  $global:services = $response | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty __name

  # --- Call RunServices Function ---

  RunServices
}

# --- Retrieve Service problems from icinga. Hard state only -Critical Services ---

function GetServiceProblemsCritical {

  $headers = @{
    Authorization = $basicAuthValue
    "accept" = "application/json" }
  $headers.Add("X-HTTP-Method-Override","GET")

  $body = "{
`n    `"filter`": [`"service.last_hard_state==servicestate&&service.acknowledgement==serviceacknowledgement&&service.handled==servicehandled&&service.last_reachable==servicereachable&&service.downtime_depth==servicedowntime`"],
`n    `"filter_vars`": {`"servicestate`": 2, `"serviceacknowledgement`": 0, `"servicehandled`": false, `"servicereachable`": true, `"servicedowntime`": 0},
`n    `"pretty`": true
`n}"

  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


  $response = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/services" -Method 'POST' -Headers $headers -Body $body

  $global:services = $response | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty __name

  # --- Call RunServices Function ---

  RunServices
}

# --- Retrieve Host comments and book a new ticket or update an existing ticket ---

function RunHosts {

  foreach ($global:h in $global:hosts) {

    $headers = @{
      Authorization = $basicAuthValue
      "accept" = "application/json" }
    $headers.Add("X-HTTP-Method-Override","GET")

    $body3 = "{
`n    `"filter`": `"host.name==hostname&&service.name==servicename`",
`n    `"filter_vars`": {`"hostname`": `"$h`", `"servicename`": `"`"}
`n}"

    $body35 = "{
`n    `"filter`": `"host.__name==hostnames`",
`n    `"filter_vars`": {`"hostnames`": `"$h`"}
`n}"

    $response3 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/comments" -Method 'POST' -Headers $headers -Body $body3
    $output1 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/hosts" -Method 'POST' -Headers $headers -Body $body35

    $global:commenthost = $response3 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty text
    $outputhost1 = $output1 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty last_check_result | Select-Object -ExpandProperty output
    $global:hostdisplayname = $output1 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty display_name
    $global:hh = $global:h -replace " ","%20"

    # --- Escape "\" character from Host description output ---

    $global:outputhost = $outputhost1 -replace '\\','\\\\' -replace '"', '\"' -replace "(\r\n|\r|\n)", '\n'

    # --- Get YetiForce Client ID from Icinga ---

    $global:get_yetiforce_client_id = $output1 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty vars | Select-Object -ExpandProperty yetiforce_client_id -ErrorAction SilentlyContinue

    # --- Check if yetiforce_client_id retrieved from Icinga is Null or not a number ---

    $checkifnumber3 = $get_yetiforce_client_id -match "^\d+$"

    if (($get_yetiforce_client_id -eq $null) -or ($checkifnumber3 -eq $false)) {
      $yetiforce_client_id = "4474"
    }

    else {
      $yetiforce_client_id = $get_yetiforce_client_id
    }

    # --- Check if there is any comment on the host ---

    if (!$global:commenthost) {

      # --- Book a ticket in YetiForce ---

      $body7 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Host is down - $hostdisplayname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T83`",
`n    `"description`": `"<p>$outputhost</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh</a></p>`"
`n}"

      $response7 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body7
      $ticketid1 = $response7 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

      # --- Retrieving Ticket Number after the ticket has been booked in ---

      $getticketnumber1 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid1" -Method 'GET' -Headers $headersYeti
      $ticketnumber1 = $getticketnumber1 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

      # --- Post a comment in Icinga Host with the YetiForce ticket ID ---

      $HeadersPost = @{
        Authorization = $basicAuthValue
        "accept" = "application/json" }

      $body5 = @{
        type = "Host"
        filter = "host.name==hostv"
        filter_vars = @{ hostv = "$h" }
        author = "IcingaAdmin"
        comment = "$ticketid1"
      }

      $json1 = $body5 | ConvertTo-Json
      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
      $response5 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json1

      # --- Acknowledge Icinga Host with the YetiForce Ticket Number ---

      $HeadersPost = @{
        Authorization = $basicAuthValue
        "accept" = "application/json" }

      $body6 = @{
        type = "Host"
        filter = "host.name==hostv"
        filter_vars = @{ hostv = "$h" }
        author = "IcingaAdmin"
        comment = "YetiForce Ticket Booked In: $ticketnumber1"
        expiry = "$expirytime"
      }

      $json2 = $body6 | ConvertTo-Json
      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
      $response6 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json2
    }

    else {

      # --- Retrieving YetiForce Ticket ID based on the Icinga comment (if it exists as a number) ---

      $checkifnumber = $commenthost -match "^\d+$"

      if ($checkifnumber -eq $true) {

        $response8 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commenthost" -Method 'GET' -Headers $headersYeti
        $response8 | ConvertTo-Json

        $verifyticketid = $response8 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id
      }

      # --- Verify if the ticket from Icinga comment exists as a ticket in YetiForce ---

      if (!$verifyticketid) {

        # --- Booking a ticket in YetiForce ---

        $body7 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Host is down - $hostdisplayname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T83`",
`n    `"description`": `"<p>$outputhost</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh</a></p>`"
`n}"

        $response17 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body7
        $ticketid2 = $response17 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

        # --- Retrieving Ticket Number after the ticket has been booked in ---

        $getticketnumber2 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid2" -Method 'GET' -Headers $headersYeti
        $ticketnumber2 = $getticketnumber2 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

        # --- Cleaning up the comments in Icinga Host ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body11 = "{
`n    `"type`": `"Host`",
`n    `"filter`": `"host.name==hostname`",
`n    `"filter_vars`": {`"hostname`": `"$h`"},
`n    `"pretty`": true
`n}"

        $response11 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/actions/remove-comment" -Method 'POST' -Headers $HeadersPost -Body $body11

        # --- Post a comment in Icinga Host with the YetiForce ticket ID ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body5 = @{
          type = "Host"
          filter = "host.name==hostv"
          filter_vars = @{ hostv = "$h" }
          author = "IcingaAdmin"
          comment = "$ticketid2"
        }

        $json1 = $body5 | ConvertTo-Json
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $response5 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json1

        # --- Acknowledge Icinga Host with the YetiForce Ticket Number ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body6 = @{
          type = "Host"
          filter = "host.name==hostv"
          filter_vars = @{ hostv = "$h" }
          author = "IcingaAdmin"
          comment = "YetiForce Ticket Booked In: $ticketnumber2"
          expiry = "$expirytime"
        }

        $json2 = $body6 | ConvertTo-Json
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $response6 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json2
      }

      else {

        # --- Check if the YetiForce ticket is closed ---

        $response11 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commenthost" -Method 'GET' -Headers $headersYeti
        $global:ticketstatus = $response11 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticketstatus

        if ($global:ticketstatus -eq "Closed") {

          # --- Book a ticket in YetiForce ---

          $body12 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Host is down - $hostdisplayname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T83`",
`n    `"description`": `"<p>$outputhost</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/host/show?host=$hh</a></p>`"
`n}"

          $response12 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body12
          $ticketid3 = $response12 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

          # --- Retrieving Ticket Number after the ticket has been booked in ---

          $getticketnumber3 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid3" -Method 'GET' -Headers $headersYeti
          $ticketnumber3 = $getticketnumber3 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

          # --- Cleaning up the comments in Icinga Host ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body18 = "{
`n    `"type`": `"Host`",
`n    `"filter`": `"host.name==hostname`",
`n    `"filter_vars`": {`"hostname`": `"$h`"},
`n    `"pretty`": true
`n}"

          $response18 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/actions/remove-comment" -Method 'POST' -Headers $HeadersPost -Body $body18

          # --- Post a comment in Icinga Host with the YetiForce ticket ID ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body13 = @{
            type = "Host"
            filter = "host.name==hostv"
            filter_vars = @{ hostv = "$h" }
            author = "IcingaAdmin"
            comment = "$ticketid3"
          }

          $json4 = $body13 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response14 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json4

          # --- Acknowledge Icinga Host with the YetiForce Ticket Number ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body15 = @{
            type = "Host"
            filter = "host.name==hostv"
            filter_vars = @{ hostv = "$h" }
            author = "IcingaAdmin"
            comment = "YetiForce Ticket Booked In: $ticketnumber3"
            expiry = "$expirytime"
          }

          $json5 = $body15 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response15 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json5
        }

        else {

          # --- Retrieving Ticket Number from ticket ID ---

          $getticketnumber4 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commenthost" -Method 'GET' -Headers $headersYeti
          $ticketnumber4 = $getticketnumber4 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

          # --- Acknowledge Icinga Host with the YetiForce Ticket Number ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body9 = @{
            type = "Host"
            filter = "host.name==hostv"
            filter_vars = @{ hostv = "$h" }
            author = "IcingaAdmin"
            comment = "YetiForce Ticket Booked In: $ticketnumber4"
            expiry = "$expirytime"
          }

          $json2 = $body9 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response9 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json2

          # --- Post comment in YetiForce Ticket ---

          $body10 = "{
`n    `"related_to`": $commenthost,
`n    `"commentcontent`": `"The problem is still on the board`"
`n}"

          $response10 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti -Body $body10

          # --- Change YetiForce ticket status to System Note Added ---

          $statusbody1 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

          $updatestatus1 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commenthost" -Method 'PUT' -Headers $headersYeti -Body $statusbody1
        }
      }
    }
  }
}

# --- Retrieve Service comments and book a new ticket or update an existing ticket ---

function RunServices {

  foreach ($global:s in $global:services) {

    # --- Check for exclusions ---

    if ($service_exceptions -like "*$s*") {
      continue
    }

    $headers = @{
      Authorization = $basicAuthValue
      "accept" = "application/json" }
    $headers.Add("X-HTTP-Method-Override","GET")

    $body4 = "{
`n    `"filter`": `"service.__name==servicenames`",
`n    `"filter_vars`": {`"servicenames`": `"$s`"}
`n}"

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


    $response4 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/comments" -Method 'POST' -Headers $headers -Body $body4
    $global:output2 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/services" -Method 'POST' -Headers $headers -Body $body4

    $global:commentservice = $response4 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty text
    $outputservice1 = $output2 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty last_check_result | Select-Object -ExpandProperty output
    $global:servicedisplayname = $output2 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty display_name
    $global:getservicehostname = $output2 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty host_name
    $service_name0 = $output2 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty name
    $global:service_name = $service_name0 -replace " ","%20"

    $body88 = "{
`n    `"filter`": `"host.__name==hostnames`",
`n    `"filter_vars`": {`"hostnames`": `"$getservicehostname`"}
`n}"

    $output88 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/hosts" -Method 'POST' -Headers $headers -Body $body88

    $global:servicehostname = $output88 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty display_name

    # --- Escape the "\" character from the Service description output ---

    $global:outputservice = $outputservice1 -replace '\\','\\\\'

    # --- Get YetiForce Client ID from Icinga ---

    $global:h2 = $output2 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty host_name
    $global:hh2 = $global:h2 -replace " ","%20"

    $body40 = "{
`n    `"filter`": `"host.__name==hostnames`",
`n    `"filter_vars`": {`"hostnames`": `"$h2`"}
`n}"

    $global:get_host_name_from_service = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/hosts" -Method 'POST' -Headers $headers -Body $body40

    $global:get_yetiforce_client_id = $get_host_name_from_service | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty vars | Select-Object -ExpandProperty yetiforce_client_id -ErrorAction Ignore

    # --- Check if yetiforce_client_id retrieved from Icinga is Null or not a number ---

    $checkifnumber3 = $get_yetiforce_client_id -match "^\d+$"

    if (($get_yetiforce_client_id -eq $null) -or ($checkifnumber3 -eq $false)) {
      $yetiforce_client_id = "4474"
    }

    else {
      $yetiforce_client_id = $get_yetiforce_client_id
    }

    # --- Check if there is any comment on the service ---

    if (!$global:commentservice) {

      # --- Book a ticket in YetiForce ---

      # --- Replace new lines with then remove all remaining HTML tags except <br> ---

      $outputservice0 = $outputservice -replace '\\','\\\\' -replace "`r`n|`n|`r",'<br> ' -replace '\s{2,}',' ' -replace '"','' -replace "'",'' -replace '[^\x00-\x7F]','' -replace "`t",' '

      $body20 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Service problem - $servicedisplayname on $servicehostname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T86`",
`n    `"description`": `"<p>$outputservice0</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name0</a></p>`"
`n}"

      $response20 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body20
      $ticketid20 = $response20 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

      # --- Retrieving Ticket Number after the ticket has been booked in ---

      $getticketnumber5 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid20" -Method 'GET' -Headers $headersYeti
      $ticketnumber5 = $getticketnumber5 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no


      # --- Post a comment in Icinga Service with the YetiForce ticket ID ---

      $HeadersPost = @{
        Authorization = $basicAuthValue
        "accept" = "application/json" }

      $body21 = @{
        type = "Service"
        filter = "service.__name==servicev"
        filter_vars = @{ servicev = "$s" }
        author = "IcingaAdmin"
        comment = "$ticketid20"
      }

      $json10 = $body21 | ConvertTo-Json
      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
      $response21 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json10

      # --- Acknowledge Icinga Service with the YetiForce Ticket Number ---

      $HeadersPost = @{
        Authorization = $basicAuthValue
        "accept" = "application/json" }

      $body22 = @{
        type = "Service"
        filter = "service.__name==servicev"
        filter_vars = @{ servicev = "$s" }
        author = "IcingaAdmin"
        comment = "YetiForce Ticket Booked In: $ticketnumber5"
        expiry = "$expirytime"
      }

      $json11 = $body22 | ConvertTo-Json
      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
      $response22 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json11
    }

    else {

      # --- Retrieving YetiForce Ticket ID based on the Icinga comment (if it exists as a number) ---

      $checkifnumber2 = $commentservice -match "^\d+$"

      if ($checkifnumber2 -eq $true) {

        $response23 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commentservice" -Method 'GET' -Headers $headersYeti
        $response23 | ConvertTo-Json

        $verifyticketid2 = $response23 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id
      }

      # --- Verify if the ticket from Icinga comment exists as a ticket in YetiForce ---

      if (!$verifyticketid2) {

        # --- Booking a ticket in YetiForce ---

        # --- Replace new lines with then remove all remaining HTML tags except <br> ---

        $outputservice0 = $outputservice -replace '\\','\\\\' -replace "`r`n|`n|`r",'<br> ' -replace '\s{2,}',' ' -replace '"','' -replace "'",'' -replace '[^\x00-\x7F]','' -replace "`t",' '

        $body24 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Service problem - $servicedisplayname on $servicehostname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T86`",
`n    `"description`": `"<p>$outputservice0</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name0</a></p>`"
`n}"

        $response24 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body24
        $ticketid21 = $response24 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

        # --- Retrieving Ticket Number after the ticket has been booked in ---

        $getticketnumber6 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid21" -Method 'GET' -Headers $headersYeti
        $ticketnumber6 = $getticketnumber6 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

        # --- Cleaning up the comments in Icinga Service ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body25 = "{
`n    `"type`": `"Service`",
`n    `"filter`": `"service.__name==servicename`",
`n    `"filter_vars`": {`"servicename`": `"$s`"},
`n    `"pretty`": true
`n}"

        $response25 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/actions/remove-comment" -Method 'POST' -Headers $HeadersPost -Body $body25

        # --- Post a comment in Icinga Service with the YetiForce ticket ID ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body26 = @{
          type = "Service"
          filter = "service.__name==servicev"
          filter_vars = @{ servicev = "$s" }
          author = "IcingaAdmin"
          comment = "$ticketid21"
        }

        $json12 = $body26 | ConvertTo-Json
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $response26 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json12

        # --- Acknowledge Icinga Service with the YetiForce Ticket Number ---

        $HeadersPost = @{
          Authorization = $basicAuthValue
          "accept" = "application/json" }

        $body27 = @{
          type = "Service"
          filter = "service.__name==servicev"
          filter_vars = @{ servicev = "$s" }
          author = "IcingaAdmin"
          comment = "YetiForce Ticket Booked In: $ticketnumber6"
          expiry = "$expirytime"
        }

        $json13 = $body27 | ConvertTo-Json
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $response27 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json13
      }

      else {

        # --- Check if the YetiForce ticket is closed ---

        $response28 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commentservice" -Method 'GET' -Headers $headersYeti
        $global:ticketstatus2 = $response28 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticketstatus

        if ($global:ticketstatus2 -eq "Closed") {

          # --- Book a ticket in YetiForce ---

          # --- Replace new lines with then remove all remaining HTML tags except <br> ---

          $outputservice0 = $outputservice -replace '\\','\\\\' -replace "`r`n|`n|`r",'<br> ' -replace '\s{2,}',' ' -replace '"','' -replace "'",'' -replace '[^\x00-\x7F]','' -replace "`t",' '

          $body29 = "{
`n    `"ticket_title`": `"Icinga Monitoring - Service problem - $servicedisplayname on $servicehostname`",
`n    `"parent_id`": $yetiforce_client_id,
`n    `"assigned_user_id`": 4,
`n    `"contact_id`": 22037,
`n    `"ticketcategories`": `"T10`",
`n    `"ticketstatus`": `"Open`",
`n    `"issue_type`": `"T86`",
`n    `"description`": `"<p>$outputservice0</p>\n<p><a href='https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name' target='_blank'>https://monitoring.wiseserve.net/dashboard#!/monitoring/service/show?host=$hh2&service=$service_name0</a></p>`"
`n}"

          $response29 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record" -Method 'POST' -Headers $headersYeti -Body $body29
          $ticketid22 = $response29 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty id

          # --- Retrieving Ticket Number after the ticket has been booked in ---

          $getticketnumber7 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$ticketid22" -Method 'GET' -Headers $headersYeti
          $ticketnumber7 = $getticketnumber7 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

          # --- Cleaning up the comments in Icinga Service ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body30 = "{
`n    `"type`": `"Service`",
`n    `"filter`": `"service.__name==servicename`",
`n    `"filter_vars`": {`"servicename`": `"$s`"},
`n    `"pretty`": true
`n}"

          $response30 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/actions/remove-comment" -Method 'POST' -Headers $HeadersPost -Body $body30

          # --- Post a comment in Icinga Service with the YetiForce ticket ID ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body31 = @{
            type = "Service"
            filter = "service.__name==servicev"
            filter_vars = @{ servicev = "$s" }
            author = "IcingaAdmin"
            comment = "$ticketid22"
          }

          $json15 = $body31 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response31 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/add-comment" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json15

          # --- Acknowledge Icinga Service with the YetiForce Ticket Number ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body32 = @{
            type = "Service"
            filter = "service.__name==servicev"
            filter_vars = @{ servicev = "$s" }
            author = "IcingaAdmin"
            comment = "YetiForce Ticket Booked In: $ticketnumber7"
            expiry = "$expirytime"
          }

          $json16 = $body32 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response32 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json16
        }

        else {

          # --- Retrieving Ticket Number from ticket ID ---

          $getticketnumber8 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commentservice" -Method 'GET' -Headers $headersYeti
          $ticketnumber8 = $getticketnumber8 | Select-Object -ExpandProperty result | Select-Object -ExpandProperty data | Select-Object -ExpandProperty ticket_no

          # --- Acknowledge Icinga Service with the YetiForce ticket ID ---

          $HeadersPost = @{
            Authorization = $basicAuthValue
            "accept" = "application/json" }

          $body33 = @{
            type = "Service"
            filter = "service.__name==servicev"
            filter_vars = @{ servicev = "$s" }
            author = "IcingaAdmin"
            comment = "YetiForce Ticket Booked In: $ticketnumber8"
            expiry = "$expirytime"
          }

          $json17 = $body33 | ConvertTo-Json
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
          $response33 = Invoke-RestMethod -Uri "https://monitoring.wiseserve.net:5665/v1/actions/acknowledge-problem" -Method 'POST' -ContentType 'application/json' -Headers $HeadersPost -Body $json17

          # --- Post comment in YetiForce Ticket ---

          $body34 = "{
`n    `"related_to`": $commentservice,
`n    `"commentcontent`": `"The problem is still on the board`"
`n}"

          $response34 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti -Body $body34

          # --- Change YetiForce ticket status to System Note Added ---

          $statusbody2 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

          $updatestatus2 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$commentservice" -Method 'PUT' -Headers $headersYeti -Body $statusbody2
        }
      }
    }
  }
}

function CheckIfProblemResolvedItself {

  # --- Retrieve the list of the Icinga tickets booked in but not accepted/assigned with any Status excluding Closed ---

  # --- Yeti Ticket Header ---

  $headersYeti2 = @{
    "X-API-KEY" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
    "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
    "Content-Type" = "application/json"
    "x-token" = $token
    "x-row-limit" = "1000000"
    "x-condition" = '[{ "fieldName": "assigned_user_id", "value": "4", "operator": "e", "group": true },{ "fieldName": "ticketstatus", "value": "Closed", "operator": "n", "group": true }]'
  }

  $response0 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/RecordsList" -Method 'GET' -Headers $headersYeti2
  $opentickets = $response0.result.records
  $headersOnly = ($opentickets | Get-Member -MemberType NoteProperty).Name
  $global:response = [regex]::Matches(($headersOnly | Out-String),'\d+') | ForEach-Object { $_.Value } | Sort-Object -Unique


  # --- Check if the Host or Service recovered in the meantime ---

  # --- Close tickets with any status excluding Closed that recovered and are not accepted/assigned yet ---

  foreach ($global:r in $global:response) {

    $headers = @{
      Authorization = $basicAuthValue
      "accept" = "application/json" }
    $headers.Add("X-HTTP-Method-Override","GET")

    $body3 = "{
`n    `"filter`": `"comment.text==commenttext`",
`n    `"filter_vars`": {`"commenttext`": `"$global:r`"}
`n}"


    $response3 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/comments" -Method 'POST' -Headers $headers -Body $body3

    $gethostname = $response3 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty host_name
    $getservicename = $response3 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty service_name
    if (!$getservicename) {
      $NotAssignedTicket = $gethostname

      $body = "{
`n    `"filter`": [`"host.last_hard_state==hoststate&&host.name==hostname`"],
`n    `"filter_vars`": {`"hoststate`": 0, `"hostname`": `"$NotAssignedTicket`"},
`n    `"pretty`": true
`n}"

      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


      $response4 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/hosts" -Method 'POST' -Headers $headers -Body $body

      $response2 = $response4 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty name -ErrorAction Ignore

      if ($response2 -ne $null) {

        # --- Post comment in YetiForce Ticket ---

        $body10 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Host state recovered`"
`n}"

        $response10 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti2 -Body $body10

        # --- Change YetiForce ticket status to Closed, assign it to Administrator and add resolution too ---

        $statusbody4 = "{
`n    `"solution`": `"The Host state recovered before the ticket to be assigned`",
`n    `"assigned_user_id`": 1
`n}"

        $statusbody8 = "{
`n    `"ticketstatus`": `"Closed`"
`n}"

        $updatestatus12 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti2 -Body $statusbody4
        $updatestatus14 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti2 -Body $statusbody8
      }
    }

    else {
      $NotAssignedTicket = $gethostname + "!" + $getservicename

      $body = "{
`n    `"filter`": [`"service.last_hard_state==servicestate&&service.__name==servicename`"],
`n    `"filter_vars`": {`"servicestate`": 0, `"servicename`": `"$NotAssignedTicket`"},
`n    `"pretty`": true
`n}"

      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


      $response5 = Invoke-RestMethod "https://monitoring.wiseserve.net:5665/v1/objects/services" -Method 'POST' -Headers $headers -Body $body

      $response6 = $response5 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty name -ErrorAction Ignore

      if ($response6 -ne $null) {

        # --- Post comment in YetiForce Ticket ---

        $body11 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Service state recovered`"
`n}"

        $response11 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti2 -Body $body11

        # --- Change YetiForce ticket status to Closed, assign it to Administrator and add resolution too ---

        $statusbody3 = "{
`n    `"solution`": `"The Service state recovered before the ticket to be assigned`",
`n    `"assigned_user_id`": 1
`n}"

        $statusbody5 = "{
`n    `"ticketstatus`": `"Closed`"
`n}"

        $updatestatus11 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti2 -Body $statusbody3
        $updatestatus13 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti2 -Body $statusbody5
      }
    }
  }

}

function UpdateTicketIfProblemResolvedItself {

  # Retrieve the list of the Icinga tickets booked, accepted and not completed or in quality control with category maintenance

  # --- Yeti Ticket Header ---

  $headersYeti3 = @{
    "X-API-KEY" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
    "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
    "Content-Type" = "application/json"
    "x-token" = $token
    "x-row-limit" = "1000000"
    "x-condition" = '[{ "fieldName": "assigned_user_id", "value": "4", "operator": "n", "group": true },{ "fieldName": "ticketstatus", "value": ["Closed","Quality Assurance"], "operator": "n", "group": true },{ "fieldName": "ticketcategories", "value": "T10", "operator": "e", "group": true }]'
  }

  $response50 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/RecordsList" -Method 'GET' -Headers $headersYeti3
  $opentickets2 = $response50.result.records
  $headersOnly2 = ($opentickets2 | Get-Member -MemberType NoteProperty).Name
  $global:response = [regex]::Matches(($headersOnly2 | Out-String),'\d+') | ForEach-Object { $_.Value } | Sort-Object -Unique

  # Check if the Host or Service recovered in the meantime

  foreach ($global:r in $global:response) {

    $headers = @{
      Authorization = $basicAuthValue
      "accept" = "application/json" }
    $headers.Add("X-HTTP-Method-Override","GET")

    $body53 = "{
`n    `"filter`": `"comment.text==commenttext`",
`n    `"filter_vars`": {`"commenttext`": `"$global:r`"}
`n}"


    $response53 = Invoke-RestMethod 'https://monitoring.wiseserve.net:5665/v1/objects/comments' -Method 'POST' -Headers $headers -Body $body53

    $gethostname2 = $response53 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty host_name
    $getservicename2 = $response53 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty attrs | Select-Object -ExpandProperty service_name
    if (!$getservicename2) {
      $StatusRecovered = $gethostname2

      $body59 = "{
`n    `"filter`": [`"host.last_hard_state==hoststate&&host.name==hostname`"],
`n    `"filter_vars`": {`"hoststate`": 0, `"hostname`": `"$StatusRecovered`"},
`n    `"pretty`": true
`n}"

      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


      $response54 = Invoke-RestMethod 'https://monitoring.wiseserve.net:5665/v1/objects/hosts' -Method 'POST' -Headers $headers -Body $body59

      $response52 = $response54 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty name -ErrorAction Ignore

      if ($response52 -ne $null) {

        # Check if the ticket already received a notification about the Host state recovery in the last 24h

        # --- Yeti Comments Header ---

        $headersYeti4 = @{
          "X-API-KEY" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
          "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
          "Content-Type" = "application/json"
          "x-token" = $token
          "x-row-limit" = "1000000"
          "x-condition" = "[{ ""fieldName"": ""commentcontent"", ""value"": ""The Host state recovered. The ticket can now be closed"", ""operator"": ""c"", ""group"": true },{ ""fieldName"": ""related_to"", ""value"": ""$global:r"", ""operator"": ""eid"", ""group"": true }]"
        }


        $checknotification = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/RecordsList" -Method 'GET' -Headers $headersYeti4
        $checknotificationid = $checknotification.result.records
        $headersOnly4 = ($checknotificationid | Get-Member -MemberType NoteProperty).Name | Select-Object -Last 1
        $getnotificationdate = $checknotification | Select-Object -ExpandProperty result | Select-Object -ExpandProperty records | Select-Object -ExpandProperty $headersOnly4 | Select-Object -ExpandProperty modifiedtime -ErrorAction Ignore

        if ($getnotificationdate -eq $null) {

          # --- Post comment in YetiForce Ticket ---

          $body60 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Host state recovered. The ticket can now be closed.`"
`n}"

          $response60 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti4 -Body $body60

          # --- Change YetiForce ticket status to System Note Added ---

          $statusbody53 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

          $updatestatus61 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti4 -Body $statusbody53

        }
        else {

          # --- Extract and convert to date object, then format ---
          # --- Use only the first 16 characters (date and time), and set the culture to en-GB ---
          $culture = [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")
          $parsedDate = [datetime]::ParseExact($getnotificationdate.Substring(0,16),'dd/MM/yyyy HH:mm',$culture)
          $notificationdate = $parsedDate.ToString('dd MMMM yyyy HH:mm:ss',$culture)
          $timespan = New-TimeSpan -Hours 24

          if (((Get-Date) - [datetime]$notificationdate) -lt $timespan) {

            Write-Host "Host - Ticket and user notifications will be skiped. It is less than 24h since the last notification - Ticket ID: $global:r"

          }

          else {

            # --- Post comment in YetiForce Ticket ---

            $body60 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Host state recovered. The ticket can now be closed.`"
`n}"

            $response60 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti4 -Body $body60

            # --- Change YetiForce ticket status to System Note Added ---

            $statusbody53 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

            $updatestatus61 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti4 -Body $statusbody53
          }
        }
      }
    }

    else {
      $StatusRecovered = $gethostname2 + "!" + $getservicename2

      $body61 = "{
`n    `"filter`": [`"service.last_hard_state==servicestate&&service.__name==servicename`"],
`n    `"filter_vars`": {`"servicestate`": 0, `"servicename`": `"$StatusRecovered`"},
`n    `"pretty`": true
`n}"

      [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


      $response55 = Invoke-RestMethod 'https://monitoring.wiseserve.net:5665/v1/objects/services' -Method 'POST' -Headers $headers -Body $body61

      $response56 = $response55 | Select-Object -ExpandProperty results | Select-Object -ExpandProperty name -ErrorAction Ignore

      if ($response56 -ne $null) {


        # Check if the ticket already received a notification about the Service state recovery in the last 24h

        # --- Yeti Comments Header ---

        $headersYeti5 = @{
          "X-API-KEY" = "h23CYbjJPka6zTNPG4Yc5AGN946tCy4p"
          "Authorization" = "Basic YXBpLXByZW1pdW06ZmFzZGZkc2F0QUFBYXdlcmZkMzQxMmUhISE="
          "Content-Type" = "application/json"
          "x-token" = $token
          "x-row-limit" = "1000000"
          "x-condition" = "[{ ""fieldName"": ""commentcontent"", ""value"": ""The Service state recovered. The ticket can now be closed"", ""operator"": ""c"", ""group"": true },{ ""fieldName"": ""related_to"", ""value"": ""$global:r"", ""operator"": ""eid"", ""group"": true }]"
        }

        $checknotification = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/RecordsList" -Method 'GET' -Headers $headersYeti5
        $checknotificationid = $checknotification.result.records
        $headersOnly5 = ($checknotificationid | Get-Member -MemberType NoteProperty).Name | Select-Object -Last 1
        $getnotificationdate = $checknotification | Select-Object -ExpandProperty result | Select-Object -ExpandProperty records | Select-Object -ExpandProperty $headersOnly5 | Select-Object -ExpandProperty modifiedtime -ErrorAction Ignore

        if ($getnotificationdate -eq $null) {

          # --- Post comment in YetiForce Ticket ---

          $body62 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Service state recovered. The ticket can now be closed.`"
`n}"

          $response62 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti5 -Body $body62

          # --- Change YetiForce ticket status to System Note Added ---

          $statusbody54 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

          $updatestatus62 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti5 -Body $statusbody54

        }

        else {

          # --- Extract and convert to date object, then format ---
          # --- Use only the first 16 characters (date and time), and set the culture to en-GB ---
          $culture = [System.Globalization.CultureInfo]::GetCultureInfo("en-GB")
          $parsedDate = [datetime]::ParseExact($getnotificationdate.Substring(0,16),'dd/MM/yyyy HH:mm',$culture)
          $notificationdate = $parsedDate.ToString('dd MMMM yyyy HH:mm:ss',$culture)
          $timespan = New-TimeSpan -Hours 24

          if (((Get-Date) - [datetime]$notificationdate) -lt $timespan) {

            Write-Host "Service - Ticket and user notifications will be skiped. It is less than 24h since the last notification - Ticket ID: $global:r"

          }

          else {

            # --- Post comment in YetiForce Ticket ---

            $body62 = "{
`n    `"related_to`": $global:r,
`n    `"commentcontent`": `"The Service state recovered. The ticket can now be closed.`"
`n}"

            $response62 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/ModComments/Record" -Method 'POST' -Headers $headersYeti5 -Body $body62

            # --- Change YetiForce ticket status to System Note Added ---

            $statusbody54 = "{
`n    `"ticketstatus`": `"System Note Added`"
`n}"

            $updatestatus62 = Invoke-RestMethod "https://force.wiseserve.net/webservice/WebservicePremium/HelpDesk/Record/$global:r" -Method 'PUT' -Headers $headersYeti5 -Body $statusbody54
          }
        }
      }
    }
  }
}

# --- Call GetHostProblems Function ---

GetHostProblems

# --- Sleep 5 seconds ---

Start-Sleep -Seconds 5

# --- Call GetServiceProblemsWarning Function ---

GetServiceProblemsWarning

# --- Sleep 5 seconds ---

Start-Sleep -Seconds 5

# --- Call GetServiceProblemsCritical Function ---

GetServiceProblemsCritical

# --- Sleep 5 seconds ---

Start-Sleep -Seconds 5

# --- Call CheckIfProblemResolvedItself Function ---

CheckIfProblemResolvedItself

# --- Sleep 5 seconds ---

Start-Sleep -Seconds 5

# --- Call UpdateTicketIfProblemResolvedItself Function ---

UpdateTicketIfProblemResolvedItself
