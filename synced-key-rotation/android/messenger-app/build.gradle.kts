import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// واجهة المحادثة نفسها التي يستعملها الحاسوب (ملف واحد للنسختين)
val copyUi by tasks.registering(Copy::class) {
    from(rootProject.file("../messenger_ui.html"))
    into(layout.buildDirectory.dir("generated/ui-assets"))
}

android {
    namespace = "org.syncedkeys.messenger"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.syncedkeys.messenger"
        minSdk = 26
        targetSdk = 35
        versionCode = 3
        versionName = "0.3"
        // Tor مبني لمعالجات الهواتف فقط (يصغّر التطبيق)
        ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a") }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets["main"].assets.srcDir(layout.buildDirectory.dir("generated/ui-assets"))
    packaging { resources { excludes += setOf("META-INF/versions/**/OSGI-INF/**", "META-INF/*.md") } }
    // اختبارات تحاكي نظام أندرويد على الحاسوب (Robolectric)
    testOptions.unitTests {
        isIncludeAndroidResources = true
        all { it.systemProperty("robolectric.dependency.repo.url", "https://maven-central.storage-download.googleapis.com/maven2") }
    }
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }
tasks.named("preBuild") { dependsOn(copyUi) }

dependencies {
    implementation(project(":core"))
    // Tor الرسمي لأندرويد (Guardian Project / The Tor Project): يعمل داخل التطبيق، بلا تطبيق آخر.
    // سلسلة 0.4.8 (طويلة الدعم): إصدارات 0.4.9 تتطلب compileSdk 37 وأداة بناء أحدث.
    implementation("info.guardianproject:tor-android:0.4.8.22")
    implementation("info.guardianproject:jtorctl:0.4.5.7")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.17")
}
