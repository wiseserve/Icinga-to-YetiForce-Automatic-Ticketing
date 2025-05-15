# Icinga-to-YettiForce-Automatic-Ticketing
A Powershell script that is booking Icinga Host or Service problems in Hard State directly into YetiForce.
###
The script is currently running from **CA-Veeam-Cloud - OVH** server. There is a task scheduler there to run every hour from 08:00-17:00 from Monday-Friday.

## How does it work
###
The script is retrieving Host/Service problems from Icinga. Only the ones that are in a Hard State which are not Acknowledged or Scheduled with a Downtime.
###  
After retrieval, will process each individual Host/Service and will book a ticket in YetiForce. After the ticket is booked, will add a comment to the Host/Service with the ticketId and will acknowledge the Host/Service too for 24h.
###
After 24h, if the Host/Service recovered, will be ignored. 
###
If the Host/Service is acknowledged, will be ignored.
###
If the Host/Service is not acknowledged, will check if is any comment. If a comment is preset, will check if is a number or not. If is a number will check if the Ticket is still open. If is still open, will post a comment to the ticket that the problem is still on the board and will change the status to Customer Note Added. If the ticket is closed, will delete all existing comments, will book a new ticket and will add a new comment in Icinga with the new ticketID.
###
If the Host/Service has a comment but is not a ticketId, will delete all the existing comments, will book a ticket and will add a new comment to Icinga with the new ticketId and will acknowledge the host as well.
###
All the Host/Service comments do not expire, but when the problem will come back and the previous ticket was closed, the comments will get deleted and the new comment with the new ticketId will be added.
###
If you want to exclude a service, you can edit the script and add the service name in the format of: Hostname!Servicename. It can accept spaces too. In the script you will see that are already two exclusion entries. You can use that as an example.
###
The script will check if YetiForce_client_id is defined in Icinga Host. If is defined, it will book the ticket under the client. If is not defined, it will book the ticket under Wiseserve.
###
If a ticket was booked in and the problem resolved itself; and the ticket was not yet assigned/accepted, the ticket will get closed(completed).
###
If a ticket or more were merged, the script will check if the Parent ticket was closed and, if was not closed, will add a note about the problem from Child ticket. If the Parent ticket was closed, will book new tickets.
