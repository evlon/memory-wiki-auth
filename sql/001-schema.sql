-- ══════════════════════════════════════════════════════════════════════════════
-- 维度授权存储 —— DDL（v1.0）
-- ══════════════════════════════════════════════════════════════════════════════
--
-- 用途：承载「谁 → 能挂载哪些维度 → 什么权限」的授权规则，
--       供 Hindsight validator 读取并注入检索过滤。
--
-- 设计原则：
--   1. 与 Hindsight 同库（同一 PostgreSQL），但**独立 schema**（wiki_auth），
--      避免与 Hindsight 自己的迁移冲突。
--   2. 授权规则与「身份」解耦 —— 身份来自 HiMarket（consumer_id），
--      本库只存 consumer_id 字符串，不做外键。
--   3. 所有查询都必须能走索引（validator 在每次 recall 前调用，性能敏感）。
--
-- ⚠️ 安全说明：本 schema 的写入权限只给管理台；validator 只读。
-- ══════════════════════════════════════════════════════════════════════════════

CREATE SCHEMA IF NOT EXISTS wiki_auth;

-- ── 维度定义 ──────────────────────────────────────────────────────────────────
-- 一个维度 = 一个业务概念（产品一 / 项目一 / Higress平台 / 运维技术域）
CREATE TABLE IF NOT EXISTS wiki_auth.dim_dimension (
    dim_id            VARCHAR(64)  PRIMARY KEY,           -- product-p1
    dim_type          VARCHAR(32)  NOT NULL,              -- product/project/platform/tech
    name              VARCHAR(128) NOT NULL,              -- 产品一
    description       VARCHAR(512),
    tag_prefix        VARCHAR(64)  NOT NULL,              -- product-p1（检索过滤用）
    bank_id           VARCHAR(128) NOT NULL,              -- team-products
    admin_consumer_id VARCHAR(64),                        -- ⭐ 维度管理员
    status            VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_dim_type   CHECK (dim_type IN ('product','project','platform','tech')),
    CONSTRAINT ck_dim_status CHECK (status IN ('ACTIVE','DISABLED'))
);

CREATE INDEX IF NOT EXISTS idx_dim_bank  ON wiki_auth.dim_dimension (bank_id) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_dim_admin ON wiki_auth.dim_dimension (admin_consumer_id);

-- ── 项目 ↔ 产品 关联（业务核心：项目集成多产品）────────────────────────────────
-- ⚠️ 展开是**单向**的：项目 → 产品。
--    绝不反向（否则产品一的人能看到所有用到它的项目 = 泄漏）
CREATE TABLE IF NOT EXISTS wiki_auth.dim_project_member (
    id             BIGSERIAL    PRIMARY KEY,
    project_dim_id VARCHAR(64)  NOT NULL,                 -- project-prj1
    product_dim_id VARCHAR(64)  NOT NULL,                 -- product-p1
    created_by     VARCHAR(64),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_proj_prod UNIQUE (project_dim_id, product_dim_id)
);

CREATE INDEX IF NOT EXISTS idx_pm_project ON wiki_auth.dim_project_member (project_dim_id);
CREATE INDEX IF NOT EXISTS idx_pm_product ON wiki_auth.dim_project_member (product_dim_id);

-- ── 挂载授权（谁 → 哪个维度 → 什么权限）───────────────────────────────────────
CREATE TABLE IF NOT EXISTS wiki_auth.dim_grant (
    id          BIGSERIAL    PRIMARY KEY,
    consumer_id VARCHAR(64)  NOT NULL,                    -- HiMarket consumer
    dim_id      VARCHAR(64)  NOT NULL,                    -- 维度
    permission  VARCHAR(16)  NOT NULL,                    -- none/read/write
    granted_by  VARCHAR(64),                              -- 哪个管理员批的
    status      VARCHAR(16)  NOT NULL DEFAULT 'APPROVED',
    expires_at  TIMESTAMPTZ,                              -- 可选的过期时间
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_consumer_dim  UNIQUE (consumer_id, dim_id),
    CONSTRAINT ck_permission    CHECK (permission IN ('none','read','write')),
    CONSTRAINT ck_grant_status  CHECK (status IN ('PENDING','APPROVED','REVOKED'))
);

-- validator 的主查询：按 consumer 查有效授权
CREATE INDEX IF NOT EXISTS idx_grant_consumer
    ON wiki_auth.dim_grant (consumer_id) WHERE status = 'APPROVED';

-- ── 凭据 → 身份 映射（由管理台从 HiMarket 同步）────────────────────────────────
-- 为什么需要这张表：
--   validator 必须知道"这个 apikey 是谁"。两个来源：
--     ① 可信代理透传的身份头（HINDSIGHT_API_EXTENSION_PASSTHROUGH_HEADERS）
--     ② apikey → consumer 的映射（本表）
--   用本表而不是直连 HiMarket 的 MySQL，原因：
--     · validator 每次 recall 都要查，必须快（同库 + 索引）
--     · 容器里不需要再装 MySQL 驱动
--     · HiMarket 是权威源，本表是只读副本（由管理台定期同步）
CREATE TABLE IF NOT EXISTS wiki_auth.dim_credential (
    id            BIGSERIAL    PRIMARY KEY,
    api_key       VARCHAR(128) NOT NULL,                  -- apikey-xxx（明文，内部库）
    consumer_id   VARCHAR(64)  NOT NULL,                  -- consumer-xxx
    developer_id  VARCHAR(64),                            -- dev-xxx
    username      VARCHAR(128),                           -- corp-sso_xxx
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',
    synced_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uk_credential_key UNIQUE (api_key),
    CONSTRAINT ck_cred_status CHECK (status IN ('ACTIVE','DISABLED'))
);

CREATE INDEX IF NOT EXISTS idx_cred_consumer ON wiki_auth.dim_credential (consumer_id);

-- ── 审计日志 ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wiki_auth.dim_audit (
    id         BIGSERIAL    PRIMARY KEY,
    actor      VARCHAR(64),                               -- 操作者 consumer_id
    action     VARCHAR(32)  NOT NULL,                     -- grant/revoke/create_dim/...
    target     VARCHAR(128),                              -- 目标（维度 id / consumer id）
    detail     JSONB,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON wiki_auth.dim_audit (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_target  ON wiki_auth.dim_audit (target);

-- ── 便于排查的视图：某人当前能挂载的全部维度（含项目展开）──────────────────────
CREATE OR REPLACE VIEW wiki_auth.v_effective_dim AS
    -- 直接授权
    SELECT g.consumer_id,
           d.dim_id,
           d.tag_prefix,
           d.bank_id,
           g.permission,
           'direct'::text AS via
      FROM wiki_auth.dim_grant g
      JOIN wiki_auth.dim_dimension d ON d.dim_id = g.dim_id
     WHERE g.status = 'APPROVED'
       AND d.status = 'ACTIVE'
       AND (g.expires_at IS NULL OR g.expires_at > now())
    UNION
    -- 项目展开出的产品（权限继承项目的）
    SELECT g.consumer_id,
           pd.dim_id,
           pd.tag_prefix,
           pd.bank_id,
           g.permission,
           ('project-' || pm.project_dim_id)::text AS via
      FROM wiki_auth.dim_grant g
      JOIN wiki_auth.dim_dimension d  ON d.dim_id = g.dim_id AND d.dim_type = 'project'
      JOIN wiki_auth.dim_project_member pm ON pm.project_dim_id = d.dim_id
      JOIN wiki_auth.dim_dimension pd ON pd.dim_id = pm.product_dim_id
     WHERE g.status = 'APPROVED'
       AND d.status = 'ACTIVE'
       AND pd.status = 'ACTIVE'
       AND (g.expires_at IS NULL OR g.expires_at > now());
