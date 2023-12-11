# Notifications package

## Overview
The notifications package provides a simple client for sending notifications to a server. It is designed to be used in conjunction with a server that can handle and process notifications.

`service`: A string representing the name of the service. Agent or manager.
`serverUrl`: A string representing the URL of the notification server.
`event`: A string representing the event type of the notification.
`computationId`: A string representing the computation ID associated with the notification. This can be null for idle events.

The notifications are sent to endpoint `<server_url>/notifications/<service_name>` using post method.
