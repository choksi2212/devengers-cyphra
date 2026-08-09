@echo off
set "ANDROID_HOME=k:\craftathon\_build-tools\android-sdk"
set "JAVA_HOME=C:\Program Files\Microsoft\jdk-21.0.7.6-hotspot"
set "GRADLE=k:\craftathon\_build-tools\gradle-8.7\bin\gradle.bat"
set "ADB=k:\craftathon\_build-tools\platform-tools\adb.exe"
set "PROJECT=k:\craftathon\cyphra-android"

echo.
echo ==============================================
echo  CYPHRA ANDROID — BUILD ^& INSTALL
echo ==============================================

echo.
echo [1/4] Building debug APK...
cd /d "%PROJECT%"
call "%GRADLE%" assembleDebug --no-daemon -p "%PROJECT%"
if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED! See errors above.
    pause
    exit /b 1
)

echo.
echo [2/4] Locating APK...
set "APK=%PROJECT%\app\build\outputs\apk\debug\app-debug.apk"
if not exist "%APK%" (
    echo APK not found! Searching...
    dir "%PROJECT%\app\build\outputs\" /s /b 2>nul
    pause
    exit /b 1
)
echo Found: %APK%

echo.
echo [3/4] Installing on phone...
"%ADB%" install -r "%APK%"
if %ERRORLEVEL% neq 0 (
    echo.
    echo INSTALL FAILED — is USB debugging still enabled?
    pause
    exit /b 1
)

echo.
echo [4/4] Launching Cyphra...
"%ADB%" shell am start -n com.cyphra.messenger/.MainActivity

echo.
echo ==============================================
echo  SUCCESS! Cyphra is running on your phone.
echo ==============================================
pause
