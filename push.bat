@echo off
chcp 65001 >nul
set msg=%~1
if "%msg%"=="" set msg=更新：自动推送更新
echo [1/3] 正在暂存文件...
git add .
echo [2/3] 正在提交更改: %msg%
git commit -m "%msg%"
echo [3/3] 正在推送到 GitHub...
git push origin main
echo 完成推送！
