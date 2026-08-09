@echo off
echo ======================================================
echo   CYPHRA ML Inference Service
echo   Port: 5002
echo   Models: LGBM(3) + XGBoost(2) + CatBoost (soft-vote)
echo   Capture: Npcap live packet capture
echo   Run as ADMINISTRATOR for packet capture to work!
echo ======================================================
cd /d "%~dp0"
python main.py
pause
