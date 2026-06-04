# Cocos EDC Extensions

This directory is the home of the Cocos-owned Eclipse EDC integration.

It exists to keep the Cocos-specific extension code in the `cocos` repository while depending on upstream Eclipse EDC artifacts instead of a long-lived Connector fork.

For the current integration scope, remaining work, and delivery order, see [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md).

Environment note:

- this standalone project follows the upstream Eclipse EDC Gradle baseline
- the copied wrapper currently uses Gradle 9.5
- running Gradle requires a local Java 17+ runtime

Build and packaging:

- the project is pinned to published upstream Eclipse EDC artifacts
- `./gradlew build` builds the extension jars
- `./gradlew packageUpstreamDropins distZip` creates a drop-in bundle under `build/upstream-dropins` and a zip distribution under `build/distributions`
- the generated `libs/` jars are intended to be copied into an upstream EDC deployment image or runtime layout