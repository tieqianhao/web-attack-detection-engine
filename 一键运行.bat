@echo off
REM ============================================
REM 攻击检测平台 - 一键运行（Windows）
REM 双击本文件即可完成：起靶场 -> 打流量 -> 检测 -> 出报告
REM ============================================

cd /d "%~dp0"

set PY=C:\Users\余星乐\.workbuddy\binaries\python\versions\3.13.12\python.exe

echo [1/4] 清空上一轮数据...
if exist access.log del /q access.log
if exist ground_truth.jsonl del /q ground_truth.jsonl
if exist alerts.jsonl del /q alerts.jsonl

echo [2/4] 启动靶场（新窗口，跑完请手动关闭）...
start "靶场-127.0.0.1:8080" %PY% vuln_app.py

echo      等待靶场就绪...
timeout /t 5 /nobreak >nul

echo [3/4] 产生正常 + 攻击混合流量...
%PY% traffic_gen.py --normal 300 --attack 90 --burst --brute

echo [4/4] 运行检测流水线...
%PY% run_pipeline.py

echo.
echo 完成！产出：
echo   检测报告.md      （含真实检出率与误报率）
echo   dashboard.html   （可视化看板，自动打开）
echo   alerts.jsonl     （告警明细）
echo.
start dashboard.html

pause
