import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins { id("org.jetbrains.kotlin.jvm") }

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    compileOnly("org.json:json:20240303")          // موجودة أصلًا في أندرويد
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    // اختبارات التوافق تشغّل نسخة بايثون من المجلد الأب
    systemProperty("python.project", rootDir.parentFile.absolutePath)
    testLogging { events("passed", "failed"); showStandardStreams = true }
}
