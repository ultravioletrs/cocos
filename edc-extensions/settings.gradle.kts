rootProject.name = "cocos-edc-extensions"

include(":extensions:cocos:cocos-spi")
include(":extensions:cocos:cocos-cli")
include(":extensions:cocos:cocos-computation-api")
include(":extensions:cocos:cocos-orchestrator")
include(":extensions:cocos:cocos-attestation-credential-service")
include(":extensions:cocos:cocos-data-sink")

project(":extensions:cocos:cocos-spi").projectDir = file("extensions/cocos/cocos-spi")
project(":extensions:cocos:cocos-cli").projectDir = file("extensions/cocos/cocos-cli")
project(":extensions:cocos:cocos-computation-api").projectDir = file("extensions/cocos/cocos-computation-api")
project(":extensions:cocos:cocos-orchestrator").projectDir = file("extensions/cocos/cocos-orchestrator")
project(":extensions:cocos:cocos-attestation-credential-service").projectDir = file("extensions/cocos/cocos-attestation-credential-service")
project(":extensions:cocos:cocos-data-sink").projectDir = file("extensions/cocos/cocos-data-sink")