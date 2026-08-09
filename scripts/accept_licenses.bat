@echo off
set SDKMANAGER=k:\craftathon\android-sdk\cmdline-tools\bin\sdkmanager.bat
set SDK_ROOT=k:\craftathon\android-sdk

REM Create licenses folder manually — fastest approach
mkdir "%SDK_ROOT%\licenses" 2>nul

REM Write each license hash directly (these are the standard Android SDK license hashes)
echo 24333f8a63b6825ea9c5514f83c2829b004d1fee > "%SDK_ROOT%\licenses\android-sdk-license"
echo 8933bad161af4178b1185d1a37fbf41ea5269c55 >> "%SDK_ROOT%\licenses\android-sdk-license"
echo d56f5187479451eabf01fb78af6dfcb131a6481e >> "%SDK_ROOT%\licenses\android-sdk-license"
echo 84831b9409646a918e30573bab4c9c91346d8abd >> "%SDK_ROOT%\licenses\android-sdk-license"
echo 504667f4c0de7af1a06de9f4b1727b84351f2910 > "%SDK_ROOT%\licenses\android-sdk-preview-license"
echo 33b6a2b64607f11b759f320ef9dff4ae5c47d97a >> "%SDK_ROOT%\licenses\android-sdk-preview-license"
echo 859f317696f67ef3d7f30a50a5560e7834b43903 > "%SDK_ROOT%\licenses\android-googletv-license"
echo 601085b94cd77f0b54ff86406957099ebe79c4d6 > "%SDK_ROOT%\licenses\google-gdk-license"
echo 33b6a2b64607f11b759f320ef9dff4ae5c47d97a > "%SDK_ROOT%\licenses\intel-android-sysimage-license"
echo e14b5e412b4c0e9f2c9fefb59b0a8f1cc2e61116 > "%SDK_ROOT%\licenses\mips-android-sysimage-license"

echo All licenses written.
