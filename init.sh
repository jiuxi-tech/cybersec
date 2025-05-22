#!/bin/bash

# 创建根目录
mkdir -p cybersec

# 创建 backend 目录及文件
mkdir -p cybersec/backend
touch cybersec/backend/app.py
touch cybersec/backend/requirements.txt
touch cybersec/backend/email_config.json

# 创建 frontend 目录及文件
mkdir -p cybersec/frontend
touch cybersec/frontend/index.html
touch cybersec/frontend/package.json
touch cybersec/frontend/vite.config.js

# 创建 frontend/src 目录及文件
mkdir -p cybersec/frontend/src
touch cybersec/frontend/src/main.js
touch cybersec/frontend/src/App.vue

# 创建 frontend/src/router 目录
mkdir -p cybersec/frontend/src/router

# 创建 frontend/src/components 目录及文件
mkdir -p cybersec/frontend/src/components
touch cybersec/frontend/src/components/AssetManagement.vue
touch cybersec/frontend/src/components/VulnerabilityList.vue
touch cybersec/frontend/src/components/CompareResult.vue
touch cybersec/frontend/src/components/ReportManagement.vue
touch cybersec/frontend/src/components/EmailConfig.vue
touch cybersec/frontend/src/components/NotificationList.vue

echo "目录结构创建完成！"
