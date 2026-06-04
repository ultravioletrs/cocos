# Upstream EDC Deployment

This project packages the Cocos-specific Eclipse EDC extensions so they can be added to an upstream EDC deployment without carrying a long-lived Connector fork.

## Build

Use Java 17+ and run:

```bash
./gradlew build packageUpstreamDropins distZip
```

Artifacts:

- `build/upstream-dropins/libs/*.jar`
- `build/distributions/cocos-edc-extensions-<version>.zip`

## Deployment Model

The produced jars are standard EDC `ServiceExtension` jars.

Expected usage:

1. start from an upstream Eclipse EDC runtime or container image
2. copy the Cocos extension jars into the runtime's library/classpath area
3. provide the required configuration for the Cocos modules
4. start the runtime with the Cocos extensions on the classpath

## Notes

- these jars are not a replacement for the upstream EDC runtime
- they extend an upstream runtime
- upstream runtime dependencies are expected to be provided by the base EDC deployment