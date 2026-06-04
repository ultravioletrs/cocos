plugins {
    `java-library`
}

dependencies {
    api(project(":extensions:cocos:cocos-spi"))
    api(libs.edc.web.spi)
    implementation(libs.edc.core.spi)
    implementation(libs.jakarta.rsApi)
    implementation(libs.jackson.databind)
}
