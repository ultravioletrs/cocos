# Manager

Manager service provides a barebones HTTP API and Service interface implementation for development of a core Mainflux service.

## Configuration

The service is configured using the environment variables from the following table. Note that any unset variables will be replaced with their default values.

| Variable              | Description                                             | Default |
|-----------------------|---------------------------------------------------------|---------|
| CC_MANAGER_LOG_LEVEL   | Log level for manager service (debug, info, warn, error) | error   |
| CC_MANAGER_HTTP_PORT   | Manager service HTTP port                                | 9021    |
| CC_MANAGER_SERVER_CERT | Path to server certificate in pem format                |         |
| CC_MANAGER_SERVER_KEY  | Path to server key in pem format                        |         |
| CC_JAEGER_URL         | Jaeger server URL                                       |         |
| CC_MANAGER_SECRET      | Manager service secret                                   | secret  |

## Deployment

The service is distributed as a Docker container. The following snippet provides a compose file template that can be used to deploy the service container locally:

```yaml
version: "3"
services:
  manager:
    image: mainflux/manager:[version]
    container_name: [instance name]
    ports:
      - [host machine port]:[configured HTTP port]
    environment:
      CC_MANAGER_LOG_LEVEL: [Kit log level]
      CC_MANAGER_HTTP_PORT: [Service HTTP port]
      CC_MANAGER_SERVER_CERT: [String path to server cert in pem format]
      CC_MANAGER_SERVER_KEY: [String path to server key in pem format]
      CC_MANAGER_SECRET: [Manager service secret]
      CC_JAEGER_URL: [Jaeger server URL]
```

To start the service outside of the container, execute the following shell script:

```bash
# download the latest version of the service
go get github.com/mainflux/mainflux

cd $GOPATH/src/github.com/mainflux/mainflux

# compile the manager
make manager

# copy binary to bin
make install

# set the environment variables and run the service
CC_MANAGER_LOG_LEVEL=[Kit log level] CC_MANAGER_HTTP_PORT=[Service HTTP port] CC_MANAGER_SERVER_CERT: [String path to server cert in pem format] CC_MANAGER_SERVER_KEY: [String path to server key in pem format] CC_JAEGER_URL=[Jaeger server URL] CC_MANAGER_SECRET: [Manager service secret] $GOBIN/mainflux-kit
```

## Usage

For more information about service capabilities and its usage, please check out the [API documentation](swagger.yaml).

[doc]: http://mainflux.readthedocs.io
