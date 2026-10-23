@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================
echo   升级到真 ELK（需要先打开 Docker Desktop）
echo ============================================
echo.
echo   [提示] 若拉镜像很慢，先在 Docker Desktop
echo          Settings - Docker Engine 里加回镜像加速：
echo          "registry-mirrors": ["https://docker.1ms.run",
echo                               "https://docker.m.daocloud.io",
echo                               "https://hub.rat.dev"]
echo          （你原来配的就是这三个，之前被备份成
echo           %%USERPROFILE%%\.docker\daemon.json.bak）
echo.

echo [1/6] 检查 Docker 守护进程...
docker info >nul 2>&1
if errorlevel 1 (
    echo.
    echo   [X] Docker 没有运行。
    echo       请先启动 Docker Desktop，再重新双击本文件。
    echo.
    pause
    exit /b 1
)
echo   [OK] Docker 已就绪
echo.

echo [2/6] 启动 Elasticsearch + Kibana + Filebeat
echo       （首次会拉取镜像，可能需要几分钟）
docker compose up -d
if errorlevel 1 (
    echo   [X] compose 启动失败，请把上面的报错发出来。
    pause
    exit /b 1
)
echo.

echo [3/6] 等待 Elasticsearch 就绪...
set READY=0
for /l %%i in (1,1,60) do (
    curl -s --max-time 3 http://127.0.0.1:9200/_cluster/health >nul 2>&1
    if not errorlevel 1 (
        set READY=1
        goto :esup
    )
    timeout /t 3 >nul
)
:esup
if "%READY%"=="0" (
    echo   [X] 等待超时。用 docker compose logs elasticsearch 看日志。
    pause
    exit /b 1
)
echo   [OK] Elasticsearch 已就绪
echo.

echo [4/6] 导入索引模板与 ILM 策略（面试会问分片数怎么定）
curl -s -X PUT "http://127.0.0.1:9200/_ilm/policy/web-log-policy" -H "Content-Type: application/json" --data-binary @es-ilm-policy.json
echo.
curl -s -X PUT "http://127.0.0.1:9200/_index_template/web-log" -H "Content-Type: application/json" --data-binary @es-index-template.json
echo.
echo   记下来：1 主分片 / 0 副本（单节点设副本会一直 yellow），
echo   日志 30 天后删除，rollover 按 5GB 或 7 天触发。
echo.

echo [5/6] 检查集群状态
curl -s --max-time 10 http://127.0.0.1:9200/_cluster/health?pretty
echo.
echo.

echo [6/6] 产生一批日志供 Filebeat 采集
if not exist access.log (
    python traffic_gen.py --normal 200 --attack 60 --brute
) else (
    echo   已存在 access.log，跳过生成
)
echo.

echo ============================================
echo   完成
echo ============================================
echo   Kibana        http://localhost:5601
echo   Elasticsearch http://localhost:9200
echo.
echo   下一步（Kibana 里做这几件事，面试就能答得出）：
echo     1. Stack Management - Index Management  看 filebeat-* 索引
echo     2. 建 Index Pattern: filebeat-*
echo     3. Discover 里搜 url:*union*  验证日志已进来
echo     4. 建一个 Dashboard: 按 rule_name 聚合告警
echo     5. 记下索引的分片数、ILM 策略名 —— 这是面试官会问的
echo.
echo   检测逻辑不用改：python run_pipeline.py 照常跑
echo.
pause
