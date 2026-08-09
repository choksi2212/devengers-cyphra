@echo off
set SDK_ROOT=k:\craftathon\android-sdk
set SDKMANAGER=%SDK_ROOT%\cmdline-tools\bin\sdkmanager.bat

echo Installing Android SDK components...
call "%SDKMANAGER%" --sdk_root="%SDK_ROOT%" "build-tools;35.0.0" "platforms;android-35" "platform-tools"
echo Done!
