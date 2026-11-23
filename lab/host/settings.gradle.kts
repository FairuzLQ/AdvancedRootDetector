// Standalone JVM build — needs no Android SDK. Compiles the library's pure rules
// (rootdetector/src/main/java/.../rules) and runs them against lab/fixtures.
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}
rootProject.name = "rootdetector-lab"
