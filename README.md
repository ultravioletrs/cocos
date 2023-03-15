# Mfxkit - Mainflux Starter Kit

Mfxkit service provides a barebones HTTP API and Service interface implementation for development of a core Mainflux service.

## How-to

Copy `mfxkit` directory to the `mainflux` root directory, e.g. `~/go/src/github.com/mainflux/mainflux/`. Copy `cmd/mfxkit` directory to `mainflux/cmd` directory.

In `mainflux` root directory run

```
CC_MFXKIT_LOG_LEVEL=info go run cmd/mfxkit/main.go
```

You should get a message similar to this one

```
{"level":"info","message":"Mfxkit service started using http on port 9021","ts":"2021-03-03T11:16:27.027381203Z"}
```

In the other terminal window run 

```
curl -i -X POST -H "Content-Type: application/json" localhost:9021/mfxkit -d '{"secret":"secret"}'
```

If everything goes well, you should get

```
HTTP/1.1 200 OK
Content-Type: application/json
Date: Wed, 03 Mar 2021 11:17:10 GMT
Content-Length: 30

{"greeting":"Hello World :)"}
```

To change the secret or the port, prefix the `go run` command with environment variable assignments, e.g.

```
CC_MFXKIT_LOG_LEVEL=info CC_MFXKIT_SECRET=secret2 CC_MFXKIT_HTTP_PORT=9022 go run cmd/mfxkit/main.go
```

To see the change in action, run

```
curl -i -X POST -H "Content-Type: application/json" localhost:9022/mfxkit -d '{"secret":"secret2"}'
```

## cURL
```sh
curl -i -X POST -H "Content-Type: application/json" localhost:9021/mfxkit -d '{"secret":"secret"}'
```

## Virsh

```sh
virsh undefine QEmu-alpine-standard-x86_64
virsh shutdown QEmu-alpine-standard-x86_64
virsh destroy QEmu-alpine-standard-x86_64
rm -rf ~/go/src/github.com/ultravioletrs/cocosvm/cmd/manager/img/boot.img
virsh pool-destroy --pool virtimages
```
