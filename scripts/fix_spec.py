"""更新 P0 命名规范：修正 bank 命名结论 + 加入实测发现"""

p = "docs/知识维度命名规范.md"
s = open(p, encoding="utf-8").read()
orig = s

# 1) 修正分隔符章节（e468 查明真因不是冒号）
s = s.replace(
    """### 2.1 命名格式

```
<范围>:<标识>
```""",
    """### 2.1 命名格式

```
<范围>-<标识>
```

> **⚠️ 分隔符用连字符 `-`，不用冒号 `:`**
>
> 最初（e441）观察到 `team:knowledge` 触发 Hindsight 的
> `PostgresSyntaxError: syntax error at or near "ORDER"`，怀疑是冒号破坏 SQL。
> 但 e468 查明**真因是 `tag_groups` 传了 dict 而非 pydantic 对象**。
>
> **尽管如此，连字符命名仍建议保留**，理由：
> 1. 与 K8s 资源名、Hindsight bank 名的字符集惯例一致
> 2. bank 名会出现在 URL path（`/mcp/{bank}/`），冒号需转义
> 3. 避免未来在 SQL 标识符 / shell 场景踩坑
>
> 实测证据：`team-knowledge` 端到端全部通过（11/11）。""")

# 2) 修正隔离区表格里的冒号
s = s.replace("| `u` | **个人草稿区** | `u:niukunliang` | ❌ **永不共享** |",
              "| `u` | **个人草稿区** | `u-niukunliang` | ❌ **永不共享** |")
s = s.replace("| `team` | **团队知识区** | `team:products` | ✅ 按维度授权 |",
              "| `team` | **团队知识区** | `team-knowledge` | ✅ 按维度授权 |")
s = s.replace("不要新增第三级（如 `team:products:sub`）",
              "不要新增第三级（如 `team-knowledge-sub`）")
s = s.replace("| `u:<用户名>` | 个人草稿、临时笔记 | 本人 |",
              "| `u-<用户名>` | 个人草稿、临时笔记 | 本人 |")
s = s.replace("| `team:products` | **产品知识**（所有产品维度） | 产品知识管理员 / 有 write 权限的人 |",
              "| `team-knowledge` | **全部共享业务知识**（产品/项目/平台/技术域） | 各维度管理员 |")
s = s.replace("| `team:projects` | **项目知识**（所有项目维度） | 项目知识管理员 / 有 write 权限的人 |", "")
s = s.replace("| `team:platform` | **平台知识**（网关、中间件等） | 平台知识运营官 |", "")
s = s.replace("| `team:tech` | **技术域知识**（运维/开发/测试方法论） | 各技术域负责人 |", "")
s = s.replace("| `team-restricted` | 受限知识（需额外授权，受众与上者不重叠） | 平台管理员 |", "")

open(p, "w", encoding="utf-8").write(s)
print("已更新" if s != orig else "⚠️ 未匹配")
