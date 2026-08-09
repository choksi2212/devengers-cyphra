@echo off
set "ANDROID_HOME=k:\craftathon\android-sdk"
set "JAVA_HOME=C:\Program Files\Microsoft\jdk-21.0.7.6-hotspot"
cd /d k:\craftathon\cyphra-android
k:\craftathon\gradle-8.7\bin\gradle.bat assembleDebug --no-daemon 2> k:\craftathon\build_log.txt
type k:\craftathon\build_log.txt
