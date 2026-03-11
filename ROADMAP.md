# 🛡️ 威胁情报平台 — 微步级演进路线图

> 目标：从当前半成品 → 对标微步在线（ThreatBook）的企业级威胁情报平台

---

## 📋 本次已完成的修复（v4.0）

| # | 问题 | 修复 |
|---|------|------|
| 1 | MongoDB 连接泄漏 | 单例连接池（maxPoolSize=20） |
| 2 | API 无认证 | API Key 中间件（X-API-Key） |
| 3 | 资产匹配太粗糙 | CPE 精确匹配 + 产品匹配 + 关键词降级，三层策略 |
| 4 | NVD 只爬第一页 | `fetch_all_cves` 分页全量拉取（最多500条） |
| 5 | Exploit-DB 误报高 | 改用 CISA KEV Catalog（本地缓存）+ NVD exploit tag |
| 6 | schedule 阻塞主线程 | APScheduler BackgroundScheduler，后台运行不阻塞 |
| 7 | 资产数据双存储 | 统一为 MongoDB，废弃 assets.json |
| 8 | 无日志 | 结构化 logging（文件+控制台） |
| 9 | 前端总数不准 | Dashboard 用 `/api/dashboard` 独立聚合，不受 limit 影响 |
| 10 | 无 Git 管理 | Git init + 初始提交 |

---

## 🗺️ 演进路线图

### Phase 1：核心补强（1-2 周）⬅️ **当前阶段**

**目标**：让平台在生产环境可靠运行

- [ ] **用户认证系统**
  - JWT 登录/注册
  - 角色权限（管理员 / 安全员 / 只读）
  - 操作审计日志

- [ ] **数据源扩展**
  - CNVD（国家信息安全漏洞共享平台）
  - CNNVD
  - GitHub Advisory Database
  - RSS/Atom 订阅（安全厂商博客、CERT 公告）

- [ ] **资产管理系统升级**
  - 支持 CSV/Excel 批量导入
  - 资产分组（部门/环境/业务线）
  - 资产生命周期管理（上线/下线/变更记录）

- [ ] **Docker 化部署**
  - Dockerfile + docker-compose
  - MongoDB 容器化
  - Nginx 反代 + HTTPS

---

### Phase 2：情报深度（2-4 周）

**目标**：超越简单的 CVE 聚合，提供有价值的情报分析

- [ ] **IOC（Indicator of Compromise）管理**
  - IP 黑名单 / 域名黑名单 / Hash 黑名单
  - IOC 关联分析（同一攻击组织、同一漏洞利用链）
  - STIX/TAXII 标准格式支持

- [ ] **威胁情报订阅与推送**
  - 订阅特定产品/厂商/漏洞类型的情报
  - 企业微信/钉钉/飞书/Webhook 实时推送
  - 邮件报告（日报/周报/月报）

- [ ] **漏洞利用链分析**
  - 攻击路径可视化（A漏洞 → B提权 → C接管）
  - PTES/ATT&CK 框架映射
  - 自动生成修复优先级建议

- [ ] **漏洞影响面评估**
  - 基于 Shodan/FOFA 的全网影响面统计
  - 行业对比分析
  - CVE 时间线（披露 → 修复 → 补丁发布）

---

### Phase 3：智能分析（4-8 周）

**目标**：AI 驱动的威胁情报，这是微步的核心竞争力

- [ ] **AI 漏洞摘要**
  - 自动生成中文漏洞摘要
  - 漏洞利用难度评估
  - 修复方案推荐

- [ ] **威胁情报关联图谱**
  - 知识图谱：漏洞 ↔ 产品 ↔ 攻击组织 ↔ IOC
  - 图谱可视化（Neo4j + D3.js / ECharts）
  - 关联推荐："关注 CVE-2024-XXXX 的人也关注..."

- [ ] **攻击面管理（ASM）**
  - 自动发现外部资产（子域名、IP、服务）
  - 暴露面持续监控
  - 未授权资产告警

- [ ] **风险评估引擎升级**
  - 多维评分：业务影响 × 利用难度 × 暴露程度 × 补丁状态
  - 动态风险评分（随时间衰减 + 新情报加权）
  - SLA 合规检查（高危漏洞修复时效）

---

### Phase 4：平台化（8-16 周）

**目标**：从工具变成平台，支持多租户

- [ ] **多租户架构**
  - 租户隔离（数据/配置/用户）
  - 自定义情报源
  - API 配额管理

- [ ] **开放 API & SDK**
  - RESTful API 文档（OpenAPI/Swagger）
  - Python/Go SDK
  - Webhook 回调

- [ ] **SOC/SIEM 集成**
  - Syslog 输出
  - CEF/LEEF 格式
  - Splunk/Elastic SIEM/QRadar 对接

- [ ] **告警与工单系统**
  - 自定义告警规则
  - 工单流转（JIRA/禅道对接）
  - 修复跟踪闭环

---

### Phase 5：生态与商业化（16+ 周）

**目标**：微步级生态

- [ ] **威胁情报社区**
  - 用户贡献情报
  - 众包漏洞验证
  - 行业威胁情报共享联盟

- [ ] **商业情报源接入**
  - 微步 X 威胁情报 API（如果开放）
  - Recorded Future / Mandiant / CrowdStrike
  - 暗网情报监控

- [ ] **合规与报告**
  - 等保 2.0 漏洞管理报告模板
  - ISO 27001 合规检查
  - 自动生成合规报告

---

## 🏗️ 技术架构演进建议

```
当前                    目标架构
────                    ────────

FastAPI + schedule      FastAPI + Celery + Redis
MongoDB                 MongoDB + Redis Cache + Neo4j（图谱）
Vue3 CDN 单文件         Vue3 + Vite + 组件化
无认证                  JWT + RBAC
无日志                  ELK / Loki
手动部署                Docker + K8s
单机                    微服务 / 分布式
```

**推荐技术栈升级路径：**
- **后端**: FastAPI → 保持，加 Celery 做异步任务
- **任务队列**: Redis + Celery（替代 APScheduler）
- **缓存**: Redis（热点数据缓存、限流）
- **图谱**: Neo4j（Phase 3 知识图谱）
- **搜索**: Elasticsearch（全文检索 CVE 描述）
- **前端**: Vue3 + Vite + Pinia + Tailwind（组件化重构）
- **部署**: Docker Compose → K8s

---

## 🎯 下一步行动

**建议立即开始 Phase 1 的用户认证 + Docker 化**，这两个是生产化的前提。完成后平台就可以在内网稳定运行了。

老板，要我接着搞哪个 Phase？
