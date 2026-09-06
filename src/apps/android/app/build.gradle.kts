plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.luminet.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.luminet.android"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}")
    }
}

val luminetAar = layout.projectDirectory.file("libs/luminet.aar")
val verifyLuminetAar by tasks.registering {
    doLast {
        require(luminetAar.asFile.isFile) {
            "Missing app/libs/luminet.aar; build the generated mobilebind AAR before the Android app"
        }
    }
}

tasks.named("preBuild") {
    dependsOn(verifyLuminetAar)
}

dependencies {
    implementation(files(luminetAar))
    implementation(platform("androidx.compose:compose-bom:2026.06.00"))
    implementation("androidx.activity:activity-compose:1.12.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    debugImplementation("androidx.compose.ui:ui-tooling")
}
