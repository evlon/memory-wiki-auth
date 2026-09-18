-- ══════════════════════════════════════════════════════════════════════════════
-- 004-grant-request.sql —— 申请→审批 流转
-- ══════════════════════════════════════════════════════════════════════════════
--
-- ── 为什么需要 ────────────────────────────────────────────────────────────────
--   现状：授权是「管理员单向设置」（PUT /ext/grants），没有「对方申请 →
--        管理员同意」的交互。但跨团队共享的真实诉求是：
--          · 想加入别人的产品/项目 → 提出申请 → 管理员同意后生效
--          · 想引用别人的产品知识（项目 ← 产品）→ 提出申请 → 对方管理员同意
--
--   本表承载这两类申请的状态机：PENDING → APPROVED / REJECTED。
--
-- ── 两类申请 ──────────────────────────────────────────────────────────────────
--   kind = 'join'     申请挂载某个维度（dim_id），期望权限 read/write
--          'reference' 申请项目(project_dim_id)引用产品(product_dim_id)
--
-- ── ⚠️ 安全边界（沿用全库铁律）────────────────────────────────────────────────
--   · 审批者必须是目标维度/项目的管理员（应用层强制，见 admin_auth.py）
--   · 申请者只能申请 read/write（不能申请管理员身份）
--   · 审批通过后由应用层落 dim_grant / dim_project_member 并 invalidate()
--   · fail-closed：状态非法 / 对象不存在 → 拒绝
-- ══════════════════════════════════════════════════════════════════════════════

CREATE SCHEMA IF NOT EXISTS wiki_auth;

CREATE TABLE IF NOT EXISTS wiki_auth.dim_grant_request (
    id            BIGSERIAL    PRIMARY KEY,
    kind          VARCHAR(16)  NOT NULL,                 -- join / reference
    requester_id  VARCHAR(64)  NOT NULL,                 -- 申请者（consumer_id 或 username）
    dim_id        VARCHAR(64),                           -- kind=join：目标维度
    project_dim_id VARCHAR(64),                          -- kind=reference：发起方项目
    product_dim_id VARCHAR(64),                          -- kind=reference：被引用产品
    permission    VARCHAR(16),                           -- kind=join：期望 read/write
    status        VARCHAR(16)  NOT NULL DEFAULT 'PENDING',
    decided_by    VARCHAR(64),                           -- 审批者身份
    decided_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_req_kind   CHECK (kind IN ('join', 'reference')),
    CONSTRAINT ck_req_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    CONSTRAINT ck_req_permission CHECK (
        permission IS NULL OR permission IN ('read', 'write')
    )
);

-- 审批者按「我管理的维度」查待办：join 走 dim_id 的 admin，reference 走 product_dim_id 的 admin
CREATE INDEX IF NOT EXISTS idx_req_status   ON wiki_auth.dim_grant_request (status);
CREATE INDEX IF NOT EXISTS idx_req_requester ON wiki_auth.dim_grant_request (requester_id);
CREATE INDEX IF NOT EXISTS idx_req_dim      ON wiki_auth.dim_grant_request (dim_id);
CREATE INDEX IF NOT EXISTS idx_req_product  ON wiki_auth.dim_grant_request (product_dim_id);
