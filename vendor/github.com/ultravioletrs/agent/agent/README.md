# Agent

Agent service provides a barebones HTTP API and Service interface implementation for development of a core Mainflux service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable              | Description                                             | Default |
|-----------------------|---------------------------------------------------------|---------|
| MF_AGENT_LOG_LEVEL   | Log level for agent service (debug, info, warn, error) | error   |
| MF_AGENT_HTTP_PORT   | Agent service HTTP port                                | 9021    |
| MF_AGENT_SERVER_CERT | Path to server certificate in pem format                |         |
| MF_AGENT_SERVER_KEY  | Path to server key in pem format                        |         |
| MF_JAEGER_URL         | Jaeger server URL                                       |         |
| MF_AGENT_SECRET      | Agent service secret                                   | secret  |

## Deployment

The service is distributed as a Docker container. The following snippet provides a compose file template that can be used to deploy the service container locally:

```yaml
version: "3"
services:
  agent:
    image: ultravioletrs/agent:[version]
    container_name: [instance name]
    ports:
      - [host machine port]:[configured HTTP port]
    environment:
      MF_AGENT_LOG_LEVEL: [Kit log level]
      MF_AGENT_HTTP_PORT: [Service HTTP port]
      MF_AGENT_SERVER_CERT: [String path to server cert in pem format]
      MF_AGENT_SERVER_KEY: [String path to server key in pem format]
      MF_AGENT_SECRET: [Agent service secret]
      MF_JAEGER_URL: [Jaeger server URL]
```

To start the service outside of the container, execute the following shell script:

```bash
# download the latest version of the service
go get github.com/mainflux/mainflux

cd $GOPATH/src/github.com/mainflux/mainflux

# compile the agent
make agent

# copy binary to bin
make install

# set the environment variables and run the service
MF_AGENT_LOG_LEVEL=[Kit log level] MF_AGENT_HTTP_PORT=[Service HTTP port] MF_AGENT_SERVER_CERT: [String path to server cert in pem format] MF_AGENT_SERVER_KEY: [String path to server key in pem format] MF_JAEGER_URL=[Jaeger server URL] MF_AGENT_SECRET: [Agent service secret] $GOBIN/mainflux-kit
```

## Usage

For more information about service capabilities and its usage, please check out the [API documentation](swagger.yaml).

[doc]: http://mainflux.readthedocs.io
