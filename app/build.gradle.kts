plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// Release signing: the local keystore (../rootdetector-release.jks), or in CI the keystore
// decoded from the RELEASE_KEYSTORE_BASE64 secret (RELEASE_KEYSTORE_PATH + *_PASSWORD/ALIAS env).
// Without any keystore the release build falls back to the debug key so it stays installable.
fun env(name: String): String? = System.getenv(name)?.takeIf { it.isNotEmpty() }
val releaseKeystore = file(env("RELEASE_KEYSTORE_PATH") ?: "../rootdetector-release.jks")

android {
    namespace = "id.jayatech.rootdetector.app"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "id.jayatech.rootdetector.app"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        versionCode = 24
        versionName = "1.6.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        create("release") {
            storeFile = releaseKeystore
            storePassword = env("RELEASE_KEYSTORE_PASSWORD") ?: "rootdetector2024"
            keyAlias = env("RELEASE_KEY_ALIAS") ?: "rootdetector"
            keyPassword = env("RELEASE_KEY_PASSWORD") ?: "rootdetector2024"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.getByName(if (releaseKeystore.exists()) "release" else "debug")
        }
    }

    buildFeatures {
        viewBinding = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":rootdetector"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)

    // Device lab (Firebase Test Lab): scan on real, clean devices — see lab/firebase/
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.junit)
}
