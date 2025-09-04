plugins {
    application
}

group = "dev.fleap.patchlens"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("com.fasterxml.jackson.core:jackson-databind:2.17.2")
    implementation("com.github.com-github-javabdd:com.github.javabdd:10.0.0")
}

application {
    mainClass = "dev.fleap.patchlens.Main"
}

// Make `gradle run` work with stdin
tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}

tasks.test {
    useJUnitPlatform()
}