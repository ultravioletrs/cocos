plugins {
    `java-library`
}

dependencies {
    api(project(":extensions:cocos:cocos-spi"))
    api(libs.edc.decentralized.claims.spi)
    implementation(libs.edc.core.spi)
    implementation(libs.edc.http.spi)
    implementation(libs.jackson.databind)
}
