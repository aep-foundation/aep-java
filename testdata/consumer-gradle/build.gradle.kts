plugins {
    java
}

val aepVersion = providers.gradleProperty("aepVersion").getOrElse("0.1.1")
val springGeneration = providers.gradleProperty("springGeneration").getOrElse("6")

repositories {
    providers.gradleProperty("aepRepository").orNull?.let {
        maven {
            url = uri(it)
        }
    }
    mavenCentral()
}

dependencies {
    implementation(platform("foundation.aep:aep-bom:$aepVersion"))
    implementation("foundation.aep:aep-agent")
    implementation("foundation.aep:aep-service")
    implementation("foundation.aep:aep-platform")
    implementation("foundation.aep:aep-httpserver")
    implementation("foundation.aep:aep-servlet")
    implementation("foundation.aep:aep-spring-webmvc")

    if (springGeneration == "7") {
        implementation("foundation.aep:aep-json-jackson3")
        implementation("jakarta.servlet:jakarta.servlet-api:6.1.0")
        implementation("org.springframework:spring-webmvc:7.0.9")
    } else {
        implementation("foundation.aep:aep-json-jackson2")
        implementation("jakarta.servlet:jakarta.servlet-api:6.0.0")
        implementation("org.springframework:spring-webmvc:6.2.19")
    }
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

sourceSets {
    main {
        java {
            srcDir("../consumer/src/main/java")
        }
    }
}

tasks.register<JavaExec>("verifyConsumer") {
    classpath = sourceSets.main.get().runtimeClasspath
    mainClass = "foundation.aep.example.Consumer"
}
