@echo off
chcp 65001 >nul
echo [1/3] 创建虚拟环境...
python -m venv .venv
echo [2/3] 从 wheels 目录离线安装依赖...
.venv\Scripts\python -m pip install --no-index --find-links=wheels -r requirements.txt
echo [3/3] 完成。运行测试: .venv\Scripts\python -m pytest tests -q
pause
