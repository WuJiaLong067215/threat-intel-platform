# 🛡️ Threat Intelligence Platform

开源威胁情报平台 — 对标微步在线，打造企业级威胁情报能力

## ✨ 功能特性

- **CVE 情报采集**：自动从 NVD 等源拉取最新漏洞情报，支持分页全量拉取
- **Exploit 检测**：基于 CISA KEV Catalog + NVD 标签，检测漏洞是否已被利用
- **资产匹配**：三层 CPE 匹配策略（精确匹配 / 产品匹配 / 关键词降级）
- **风险评估**：多维风险评分引擎（CVSS + Exploit + 资产 + 时效性）
- **资产扫描**：端口扫描 + HTTP Banner 抓取，自动识别资产
- **情报报告**：自动生成日报，支持企业微信/钉钉/飞书推送
- **Web Dashboard**：暗色主题可视化看板
- **API 服务**：完整的 RESTful API（FastAPI + OpenAPI 文档）
- **定时调度**：APScheduler 后台运行，不阻塞 API

## 🏗️ 架构

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   NVD API   │────▶│  爬虫模块    │────▶│  MongoDB     │
│   CISA KEV  │     │  (crawler)   │     │  (database)  │
└─────────────┘     └──────┬───────┘     └──────┬──────┘
                           │                     │
                    ┌──────▼───────┐     ┌──────▼──────┐
                    │  分析模块    │────▶│  API 服务    │
                    │  (analyzer)  │     │  (FastAPI)   │
                    └──────────────┘     └──────┬──────┘
                                                │
                                         ┌──────▼──────┐
                                         │  Web 前端    │
                                         │  (Vue 3)     │
                                         └─────────────┘
```

## 🚀 快速开始

### 环境要求

- Python 3.10+
- MongoDB 6.0+

### 安装

```bash
git clone https://github.com/WuJiaLong067215/threat-intel-platform.git
cd threat-intel-platform

# 创建虚拟环境
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# 安装依赖
pip install -r requirements.txt

# 配置环境变量
cp .env.example .env
# 编辑 .env 填入 MongoDB 连接和 NVD API Key
```

### 启动

```bash
# API 服务模式（推荐）
python main.py
# 访问 http://localhost:8000

# 单次流水线模式
python main.py --pipeline
```

### Docker 部署（规划中）

```bash
docker-compose up -d
```

## 📡 数据源

| 数据源 | 状态 | 说明 |
|--------|------|------|
| NVD CVE | ✅ 已接入 | 美国国家漏洞数据库 |
| CISA KEV | ✅ 已接入 | 已知被利用漏洞目录 |
| CNVD | 🔄 规划中 | 国家信息安全漏洞共享平台 |
| CNNVD | 🔄 规划中 | 国家信息安全漏洞库 |
| GitHub Advisory | 🔄 规划中 | GitHub 安全公告 |

## 🔌 API 接口

启动后访问 http://localhost:8000/docs 查看完整 API 文档

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | /api/health | 健康检查 |
| GET | /api/dashboard | Dashboard 统计 |
| GET | /api/cves | CVE 列表（支持筛选） |
| GET | /api/cves/{id} | CVE 详情 |
| GET | /api/risk-ranking | 风险排行榜 |
| GET | /api/assets | 资产列表 |
| POST | /api/assets | 添加资产 |
| DELETE | /api/assets/{product} | 删除资产 |
| POST | /api/sync | 同步 CVE 数据 |
| POST | /api/pipeline | 手动触发流水线 |
| GET | /api/brief | 生成情报简报 |

### 认证

在 `.env` 中配置 `API_KEY`，写入操作需要在请求头中携带：

```
X-API-Key: your-api-key
```

## 📋 开发路线图

详见 [ROADMAP.md](./ROADMAP.md)

- **Phase 1**: 核心补强（用户认证 + Docker + 数据源扩展）
- **Phase 2**: 情报深度（IOC 管理 + 利用链分析 + 影响面评估）
- **Phase 3**: 智能分析（AI 摘要 + 知识图谱 + ASM）
- **Phase 4**: 平台化（多租户 + 开放 API + SIEM 集成）
- **Phase 5**: 生态商业化（社区 + 商业情报源 + 合规报告）

## 🛡️ 安全

- API Key 认证中间件
- 资产扫描接口需要认证
- MongoDB 连接池管理
- NVD API 限流处理
- 输入验证（Pydantic 模型）

## 📄 License

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
