# Brokers Docker Compose

Cocos supports configurable Message broker.

## Message Broker

Magistrala supports NATS and RabbitMQ as a message broker.

## Profiles

This directory contains 2 docker-compose profiles for running Magistrala with different message brokers.

The profiles are:

- `nats` - Nats as a message broker
- `rabbitmq` - RabbitMQ as a message broker

The following command will run Nats as a message broker:

```bash
MG_MESSAGE_BROKER_TYPE=nats make run
```

The following command will run RabbitMQ as a message broker:

```bash
MG_MESSAGE_BROKER_TYPE=rabbitmq make run
```
