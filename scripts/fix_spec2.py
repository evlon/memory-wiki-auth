"""统一 P0 规范里的 tag 命名分隔符（冒号 → 连字符）"""

import re

p = "docs/知识维度命名规范.md"
s = open(p, encoding="utf-8").read()

# 表格里的 tag 示例
s = s.replace("`product:p1`、`product:himarket`", "`product-p1`、`product-himarket`")
s = s.replace("`project:prj1`、`project:ai-works`", "`project-prj1`、`project-ai-works`")
s = s.replace("`platform:higress`、`platform:k8s`", "`platform-higress`、`platform-k8s`")
s = s.replace("`tech:ops`、`tech:dev`、`tech:qa`", "`tech-ops`、`tech-dev`、`tech-qa`")

# 归属隔离区列（统一为 team-knowledge）
s = s.replace("| `team-products` |", "| `team-knowledge` |")
s = s.replace("| `team-projects` |", "| `team-knowledge` |")
s = s.replace("| `team-platform` |", "| `team-knowledge` |")
s = s.replace("| `team-tech` |", "| `team-knowledge` |")

# tag 示例块
s = s.replace("tags = [platform:higress, tech:ops]", "tags = [platform-higress, tech-ops]")
s = s.replace("tags = [product:p1, tech:dev]", "tags = [product-p1, tech-dev]")

# 反例
s = s.replace('`tags: ["产品一"]`', '`tags: ["产品一"]`')
s = s.replace('`tags: ["Product:P1"]`', '`tags: ["Product-P1"]`')
s = s.replace('`tags: ["product:p1", "product:p1"]`', '`tags: ["product-p1", "product-p1"]`')
s = s.replace('`bank: "team:products:sub"`', '`bank: "team-knowledge-sub"`')
s = s.replace('`tags: ["dept:研发部"]`', '`tags: ["dept-研发部"]`')
s = s.replace('写入 `team:products`', '写入 `team-knowledge`')

# 3.1 命名格式
s = s.replace("""### 3.1 命名格式

```
<类型>:<标识>
```""", """### 3.1 命名格式

```
<类型>-<标识>
```""")

# 维度登记表
s = s.replace("| `product:p1` |", "| `product-p1` |")
s = s.replace("| `product:p2` |", "| `product-p2` |")
s = s.replace("| `project:prj1` |", "| `project-prj1` |")
s = s.replace("| `platform:higress` |", "| `platform-higress` |")
s = s.replace("| `tech:ops` |", "| `tech-ops` |")
s = s.replace("| `team:products` | 张三 |", "| `team-knowledge` | 张三 |")
s = s.replace("| `team:products` | 李四 |", "| `team-knowledge` | 李四 |")
s = s.replace("| `team:projects` | 王五 |", "| `team-knowledge` | 王五 |")
s = s.replace("| `team:platform` | 赵六 |", "| `team-knowledge` | 赵六 |")
s = s.replace("| `team:tech` | 赵六 |", "| `team-knowledge` | 赵六 |")

# SQL 注释
s = s.replace("-- dim:project:prj1", "-- project-prj1")
s = s.replace("-- dim:product:p1", "-- product-p1")

# 共享区前缀说明
s = s.replace("写入共享区（`team:*`）", "写入共享区（`team-*`）")

# 正则与校验代码
s = s.replace(
    r"""BANK_RE   = re.compile(r'^(u|team):[a-z0-9-]{1,40}$')
DIM_RE    = re.compile(r'^(product|project|platform|tech):[a-z0-9-]{1,40}$')""",
    r"""BANK_RE   = re.compile(r'^(u|team)-[a-z0-9-]{1,40}$')
DIM_RE    = re.compile(r'^(product|project|platform|tech)-[a-z0-9-]{1,40}$')""")

# 个人区跳过校验
s = s.replace("if bank_id.startswith('u:'):", "if bank_id.startswith('u-'):")
s = s.replace("对 `u:` 开头的个人区", "对 `u-` 开头的个人区")
s = s.replace("非法维度 tag：{t}（格式 <类型>:<标识>）", "非法维度 tag：{t}（格式 <类型>-<标识>）")

# 项目展开示例
s = s.replace('{tags:["project:prj1"], "match":"any_strict"}', '{tags:["project-prj1"], "match":"any_strict"}')
s = s.replace('{"tags":["project:prj1"]', '{"tags":["project-prj1"]')
s = s.replace('{"tags":["product:p1"]', '{"tags":["product-p1"]')
s = s.replace('{"tags":["product:p2"]', '{"tags":["product-p2"]')
s = s.replace('{"tags":["product:p3"]', '{"tags":["product-p3"]')

open(p, "w", encoding="utf-8").write(s)

# 检查
left = re.findall(r'`(u|team|product|project|platform|tech):[a-z0-9-]+`', s)
print("剩余冒号命名：", left if left else "无")
