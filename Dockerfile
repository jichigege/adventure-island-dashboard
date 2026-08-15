# 冒险岛水世界商店报表看板 —— Koyeb 容器镜像（Flask 鉴权后端 + 内联看板）
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 仅安装运行时依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制全部应用文件（含 dashboard.html、logo80X80.jpg）
COPY . .

# Koyeb 在 Service 设置里填 Port=8000，并通过 PORT 环境变量注入给容器
ENV PORT=8000
EXPOSE 8000

# gunicorn 单 worker 适配免费层 512MB；日志打到 stdout 方便平台查看
CMD ["sh", "-c", "gunicorn -w 1 -b 0.0.0.0:${PORT:-8000} --timeout 120 --access-logfile - --error-logfile - server:app"]
