FROM python:3.12-slim

LABEL maintainer="WuJiaLong067215"
LABEL description="威胁情报平台 - Threat Intelligence Platform"

WORKDIR /app

# 系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 应用代码
COPY . .

# 创建必要目录
RUN mkdir -p memory web

# 环境变量
ENV PYTHONUNBUFFERED=1
ENV MONGO_URI=mongodb://mongodb:27017/
ENV MONGO_DB=threat_intel
ENV HOST=0.0.0.0
ENV PORT=8000

# 暴露端口
EXPOSE 8000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# 启动
CMD ["python", "main.py"]
