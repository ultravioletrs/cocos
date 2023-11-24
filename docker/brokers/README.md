# Brokers Docker Compose

Cocos supports configurable Message broker.

## Message Broker

Cocos-AI supports NATS and RabbitMQ as a message broker.

The following command will run Nats as a message broker:

```bash
MG_MESSAGE_BROKER_TYPE=nats make run
```

The following command will run RabbitMQ as a message broker:

```bash
MG_MESSAGE_BROKER_TYPE=rabbitmq make run
```
