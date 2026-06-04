plugins {
    `java-library`
}

dependencies {
    api(project(":extensions:cocos:cocos-spi"))
    api(libs.edc.data.plane.spi)
    implementation(libs.edc.core.spi)
}
