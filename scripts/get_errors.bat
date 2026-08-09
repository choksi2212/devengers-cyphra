@echo off
set "ANDROID_HOME=k:\craftathon\android-sdk"
set "JAVA_HOME=C:\Program Files\Microsoft\jdk-21.0.7.6-hotspot"
cd /d k:\craftathon\cyphra-android
k:\craftathon\gradle-8.7\bin\gradle.bat assembleDebug --no-daemon --stacktrace 2>&1 | findstr /i "error" > k:\craftathon\build_errors.txt
k:\craftathon\gradle-8.7\bin\gradle.bat assembleDebug --no-daemon --stacktrace 2>&1 | findstr /i "FAILED" >> k:\craftathon\build_errors.txt
k:\craftathon\gradle-8.7\bin\gradle.bat assembleDebug --no-daemon --stacktrace 2>&1 | findstr /i "Exception" >> k:\craftathon\build_errors.txt
k:\craftathon\gradle-8.7\bin\gradle.bat assembleDebug --no-daemon --stacktrace 2>&1 | findstr /i "Could not" >> k:\craftathon\build_errors.txt
type k:\craftathon\build_errors.txt
