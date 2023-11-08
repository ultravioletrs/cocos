# Broker Docker Profiles

The profiles are:

- `nats.yml` - Nats Nats as a message broker
- `rabbit.yml` - RabbitMQ as a message broker

The following command will run Nats as a message broker:

```bash
COCOS_MESSAGE_BROKER_TYPE=nats make run
```

The following command will run RabbitMQ as a message broker:

```bash
COCOS_MESSAGE_BROKER_TYPE=rabbit make run
```
