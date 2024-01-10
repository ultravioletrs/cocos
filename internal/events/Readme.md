# Events package

## Overview
The events package provides a simple client for sending events to a server. It is designed to be used in conjunction with a server that can handle and process events.

`service`: A string representing the name of the service. Agent or manager.
`serverUrl`: A string representing the URL of the events server.
`event`: A string representing the event type of the events.
`computationId`: A string representing the computation ID associated with the events. This can be null for idle events.

The notifications are sent to endpoint `<server_url>/notifications/events` using post method.
