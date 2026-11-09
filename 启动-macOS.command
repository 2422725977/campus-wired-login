#!/bin/bash
# 双击运行：自动打开 Terminal 并登录校园网有线认证
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "未找到 python3，请先安装：xcode-select --install 或 https://www.python.org/downloads/"
  read -r -p "按回车退出..." _
  exit 1
fi
python3 ctbu_wired_login.py "$@"
echo
read -r -p "按回车关闭窗口..." _
