-- ══════════════════════════════════════════════════════════════════════════════
-- 002-identity-alias.sql —— 统一身份：让 OIDC 与 apikey 两条路径对上
-- ══════════════════════════════════════════════════════════════════════════════
--
-- ── 为什么需要这个 ────────────────────────────────────────────────────────────
--   同一个人有**两种身份表示**：
--
--     路径              身份字符串                     来源
--     ────────────────  ─────────────────────────────  ──────────────────
--     管理台（OIDC）     zhaolei                        Keycloak username
--     MCP（apikey）      consumer-a8238936cb1147...     HiMarket consumer
--
--   而授权表 dim_grant.consumer_id 只能存一个值
--   → 若按 username 授权，MCP 路径查不到；反之亦然。
--
-- ── 解决思路：分组键（不是归并、也不需要传递闭包）─────────────────────────────
--   给每个身份算一个 **group_key**：
--
--     身份类型                     group_key
--     ───────────────────────────  ─────────────────────────
--     在 dim_credential 里的 consumer   'u:' || 归一化username
--     归一化 username                  'u:' || 归一化username
--     其他（未被登记的授权对象）         'i:' || 身份本身
--
--   于是「我是谁」→「我的 group_key」→「同组的所有身份」，
--   拿这组身份去查 v_effective_dim 即可。
--
--   ⭐ 为什么用归一化 username 做组键：
--      · HiMarket 认为「同一 username 的所有 consumer 属于同一 developer」
--      · 无需决定"谁是主身份"，也无需传递闭包（一步到位）
--
-- ── ⚠️ 安全边界 ───────────────────────────────────────────────────────────────
--   · 分组来源**只有** dim_credential（HiMarket 的 apikey 归属表）
--   · **不做模糊/前缀匹配** —— 除 `corp-sso_` 前缀归一化外，必须精确相等
--   · 本视图只做映射，**不做鉴权**；鉴权仍在应用层（fail-closed）
--   · 未被登记的身份各自独立成组 → 不会意外扩大权限
-- ══════════════════════════════════════════════════════════════════════════════

CREATE SCHEMA IF NOT EXISTS wiki_auth;

-- ── 身份 → 分组键 ─────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW wiki_auth.v_identity_group AS
WITH cred AS (
    SELECT
        consumer_id,
        regexp_replace(username, '^corp-sso_', '') AS uname
      FROM wiki_auth.dim_credential
     WHERE status = 'ACTIVE'
       AND consumer_id IS NOT NULL AND consumer_id <> ''
),
-- ① 凭据表里的 consumer：按归一化 username 归组
g_cred AS (
    SELECT consumer_id AS identity, 'u:' || uname AS group_key
      FROM cred WHERE uname IS NOT NULL AND uname <> ''
),
-- ② 归一化 username 本身也是一个身份别名
g_uname AS (
    SELECT DISTINCT uname AS identity, 'u:' || uname AS group_key
      FROM cred WHERE uname IS NOT NULL AND uname <> ''
),
-- ③ 其余出现在授权表/管理员字段里的身份：各自独立成组
g_other AS (
    SELECT DISTINCT consumer_id AS identity, 'i:' || consumer_id AS group_key
      FROM wiki_auth.dim_grant
     WHERE consumer_id IS NOT NULL AND consumer_id <> ''
    UNION
    SELECT DISTINCT admin_consumer_id, 'i:' || admin_consumer_id
      FROM wiki_auth.dim_dimension
     WHERE admin_consumer_id IS NOT NULL AND admin_consumer_id <> ''
)
-- ⚠️ ① 优先于 ③：同一身份若既在凭据表又在授权表，以凭据表的组为准
SELECT identity, group_key FROM g_uname
UNION
SELECT c.identity, c.group_key FROM g_cred c
 WHERE NOT EXISTS (SELECT 1 FROM g_uname u WHERE u.identity = c.identity)
UNION
SELECT o.identity, o.group_key FROM g_other o
 WHERE NOT EXISTS (SELECT 1 FROM g_uname u WHERE u.identity = o.identity)
   AND NOT EXISTS (SELECT 1 FROM g_cred  c WHERE c.identity = o.identity);

COMMENT ON VIEW wiki_auth.v_identity_group IS
    '身份 → 分组键。同一人的 Keycloak username 与 HiMarket consumer_id 归到同一组。'
    '来源仅 dim_credential（精确匹配）。仅做映射，不做鉴权。';

-- ── 别名展开：给定任一身份，列出同组的所有身份 ────────────────────────────────
CREATE OR REPLACE VIEW wiki_auth.v_identity_alias AS
SELECT
    a.identity      AS alias,
    a.group_key,
    b.identity      AS sibling
  FROM wiki_auth.v_identity_group a
  JOIN wiki_auth.v_identity_group b ON b.group_key = a.group_key;

COMMENT ON VIEW wiki_auth.v_identity_alias IS
    '别名展开：alias 的同组身份（含自身）在 sibling 列。';

-- ── 便捷视图：按任一身份查有效维度（人工排查用）───────────────────────────────
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
