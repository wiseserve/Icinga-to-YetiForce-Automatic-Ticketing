# Icinga-to-YetiForce-Automatic-Ticketing

A PowerShell script that books Icinga Host or Service problems in a Hard State directly into YetiForce.

The script currently runs from the **Icinga Monitoring** server. A cron job runs it every hour from 08:00 to 17:00, Monday to Friday.

The script is designed to run on **PowerShell 7**.

## How It Works

The script retrieves Host and Service problems from Icinga. Only problems in a Hard State that are not acknowledged and not scheduled with downtime are processed.

After retrieval, each Host or Service is processed individually and a ticket is created in YetiForce. Once the ticket is created, a comment containing the `ticketId` is added to the Host or Service in Icinga, and the Host or Service is acknowledged for 24 hours.

After 24 hours, if the Host or Service has recovered, it is ignored.

If the Host or Service is acknowledged, it is ignored.

If the Host or Service is not acknowledged, the script checks whether a comment exists. If a comment is present, it checks whether the comment is a number. If it is a number, it checks whether the related ticket is still open. If the ticket is still open, a comment is posted to the ticket stating that the problem is still on the board, and the ticket status is changed to `Customer Note Added`. If the ticket is closed, all existing comments are deleted, a new ticket is created, and a new comment containing the new `ticketId` is added in Icinga.

If the Host or Service has a comment that is not a `ticketId`, all existing comments are deleted, a new ticket is created, a new comment containing the new `ticketId` is added in Icinga, and the Host or Service is acknowledged as well.

Host and Service comments do not expire. However, if the problem returns and the previous ticket was already closed, the old comments are deleted and a new comment with the new `ticketId` is added.

If a service needs to be excluded, the script can be edited to add the service name in the format `Hostname!Servicename`. Spaces are supported. The script already contains two exclusion entries that can be used as examples.

The script checks whether `yetiforce_client_id` is defined on the Icinga Host. If it is defined, the ticket is created under that client. If it is not defined, the ticket is created under **Wiseserve**.

If a ticket was created and the problem resolved itself before the ticket was assigned or accepted, the ticket is automatically closed (`Completed`).

If one or more tickets were merged, the script checks whether the parent ticket was closed. If the parent ticket is still open, a note about the problem from the child ticket is added to the parent ticket. If the parent ticket was closed, new tickets are created.
