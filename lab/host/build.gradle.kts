plugins {
    kotlin("jvm") version "2.0.0"
}

sourceSets {
    main {
        kotlin {
            srcDir("../../rootdetector/src/main/java")
            include("id/jayatech/rootdetector/rules/**")
        }
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
}

val buildNativeRunner by tasks.registering(Exec::class) {
    description = "Builds lab/native/lab_native with the host C++ compiler"
    commandLine("../native/run.sh")
    inputs.files("../native/lab_native.cpp", "../../rootdetector/src/main/cpp/signatures.h")
    outputs.file("../native/build/lab_native")
}

tasks.test {
    dependsOn(buildNativeRunner)
    systemProperty("lab.fixtures", file("../fixtures").absolutePath)
    systemProperty("lab.nativeRunner", file("../native/build/lab_native").absolutePath)
    systemProperty("lab.report", file("../REPORT.md").absolutePath)
    inputs.dir("../fixtures")
    outputs.file("../REPORT.md")
    testLogging {
        events("failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
