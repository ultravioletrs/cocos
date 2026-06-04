plugins {
    `java-library`
}

dependencies {
    api(project(":extensions:cocos:cocos-spi"))
    implementation(libs.edc.core.spi)
    implementation(libs.edc.http.spi)
    implementation(libs.jackson.databind)
}
