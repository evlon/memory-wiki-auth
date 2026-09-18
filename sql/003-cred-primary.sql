-- ══════════════════════════════════════════════════════════════════════════════
-- 003-cred-primary.sql —— 修复别名归并的安全缺陷
-- ══════════════════════════════════════════════════════════════════════════════
--
-- ── 发现的缺陷（e596 实测）────────────────────────────────────────────────────
--   002 的别名按 **username** 归组，但一个 username 可能有多个 consumer：
--
--     consumer-a8238936...  corp-sso_niukunliang  is_primary=1     ← 牛昆亮本人
--     consumer-50310ba8...  corp-sso_niukunliang  is_primary=NULL  ← ai-llm 系统账号
--
--   结果：**ai-llm 系统账号继承了牛昆亮的产品写权限** —— 实测泄漏：
--     ai-llm 本应只有 platform-higress(read)，却拿到 product-p1/p2/p3 的 write
--
-- ── 修复思路 ──────────────────────────────────────────────────────────────────
--   只有「绑定到自然人」的 consumer（HiMarket 的 is_primary=1）才参与别名归并；
--   系统账号（is_primary IS NULL）各自独立成组，不与任何人共享授权。
--
--     自然人 niukunliang 的组 = { 'niukunliang', 'consumer-a823...' }
--     ai-llm 的组           = { 'consumer-5031...' }            ← 独立
--
-- ── ⚠️ 安全取向 ───────────────────────────────────────────────────────────────
--   **宁可少归并，不可多归并**：漏归并的后果是"管理台看不到 MCP 的授权"
--   （可用性问题，能发现）；多归并的后果是**越权**（安全问题，难发现）。
-- ══════════════════════════════════════════════════════════════════════════════

-- ── 1. 凭据表加 is_primary 列 ─────────────────────────────────────────────────
ALTER TABLE wiki_auth.dim_credential
    ADD COLUMN IF NOT EXISTS is_primary BOOLEAN;

COMMENT ON COLUMN wiki_auth.dim_credential.is_primary IS
    '是否为该自然人的主 consumer（HiMarket is_primary=1）。'
    'NULL/FALSE = 系统账号（如 ai-llm），不参与身份别名归并。';

-- ── 2. 重建身份分组视图（只归并主 consumer）──────────────────────────────────
DROP VIEW IF EXISTS wiki_auth.v_effective_dim_by_alias;
DROP VIEW IF EXISTS wiki_auth.v_identity_alias;
DROP VIEW IF EXISTS wiki_auth.v_identity_group;

CREATE OR REPLACE VIEW wiki_auth.v_identity_group AS
WITH cred AS (
    SELECT
        consumer_id,
        regexp_replace(username, '^corp-sso_', '') AS uname,
        COALESCE(is_primary, FALSE) AS primary_flag
      FROM wiki_auth.dim_credential
     WHERE status = 'ACTIVE'
       AND consumer_id IS NOT NULL AND consumer_id <> ''
),
-- ① 主 consumer：与归一化 username 归到同一组
g_primary AS (
    SELECT consumer_id AS identity, 'u:' || uname AS group_key
      FROM cred
     WHERE primary_flag AND uname IS NOT NULL AND uname <> ''
),
-- ② 归一化 username 本身
g_uname AS (
    SELECT DISTINCT uname AS identity, 'u:' || uname AS group_key
      FROM cred
     WHERE primary_flag AND uname IS NOT NULL AND uname <> ''
),
-- ③ 非主 consumer（系统账号）：**各自独立成组**
g_system AS (
    SELECT consumer_id AS identity, 'i:' || consumer_id AS group_key
      FROM cred
     WHERE NOT primary_flag
),
-- ④ 其余出现在授权表/管理员字段里的身份：各自独立成组
g_other AS (
    SELECT DISTINCT consumer_id AS identity, 'i:' || consumer_id AS group_key
      FROM wiki_auth.dim_grant
     WHERE consumer_id IS NOT NULL AND consumer_id <> ''
    UNION
    SELECT DISTINCT admin_consumer_id, 'i:' || admin_consumer_id
      FROM wiki_auth.dim_dimension
     WHERE admin_consumer_id IS NOT NULL AND admin_consumer_id <> ''
)
-- ⚠️ 优先级：① ② > ③ > ④（越具体的归并越优先）
SELECT identity, group_key FROM g_uname
UNION
SELECT p.identity, p.group_key FROM g_primary p
 WHERE NOT EXISTS (SELECT 1 FROM g_uname u WHERE u.identity = p.identity)
UNION
SELECT s.identity, s.group_key FROM g_system s
 WHERE NOT EXISTS (SELECT 1 FROM g_uname u WHERE u.identity = s.identity)
   AND NOT EXISTS (SELECT 1 FROM g_primary p WHERE p.identity = s.identity)
UNION
SELECT o.identity, o.group_key FROM g_other o
 WHERE NOT EXISTS (SELECT 1 FROM g_uname   u WHERE u.identity = o.identity)
   AND NOT EXISTS (SELECT 1 FROM g_primary p WHERE p.identity = o.identity)
   AND NOT EXISTS (SELECT 1 FROM g_system  s WHERE s.identity = o.identity);

COMMENT ON VIEW wiki_auth.v_identity_group IS
    '身份 → 分组键。只归并「主 consumer + username」；系统账号（非主 consumer）独立成组。';

CREATE OR REPLACE VIEW wiki_auth.v_identity_alias AS
SELECT a.identity AS alias, a.group_key, b.identity AS sibling
  FROM wiki_auth.v_identity_group a
  JOIN wiki_auth.v_identity_group b ON b.group_key = a.group_key;

COMMENT ON VIEW wiki_auth.v_identity_alias IS
    '别名展开：alias 的同组身份（含自身）在 sibling 列。';

CREATE OR REPLACE VIEW wiki_auth.v_effective_dim_by_alias AS
SELECT
    e.consumer_id,
    e.dim_id,
    e.tag_prefix,
    e.bank_id,
    e.permission,
    e.via,
    al.alias AS queried_as
  FROM wiki_auth.v_effective_dim e
  JOIN wiki_auth.v_identity_alias al ON al.sibling = e.consumer_id;
