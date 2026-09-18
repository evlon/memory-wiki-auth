"""负向验证：注入 bug 后跑测试（在容器内执行，避免 shell 转义）"""

import subprocess
import sys
import shutil
import os

DEST = "/tmp/wiki-auth-test"
V = f"{DEST}/src/wiki_auth/validator.py"
T = f"{DEST}/src/wiki_auth/tenant.py"


def run_tests() -> str:
    r = subprocess.run(
        ["python3", "-m", "pytest", "tests/", "-q", "-p", "no:cacheprovider"],
        cwd=DEST, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": f"{DEST}/src"},
    )
    out = (r.stdout or "") + (r.stderr or "")
    last = [l for l in out.strip().split("\n") if l.strip()]
    return last[-1] if last else "(无输出)"


def inject(path: str, old: str, new: str) -> bool:
    s = open(path, encoding="utf-8").read()
    if old not in s:
        print(f"    ⚠️ 未找到锚点：{old[:60]}")
        return False
    shutil.copy(path, path + ".bak")
    open(path, "w", encoding="utf-8").write(s.replace(old, new))
    return True


def restore(path: str):
    if os.path.exists(path + ".bak"):
        shutil.move(path + ".bak", path)


CASES = [
    ("BUG 1: fail-closed → fail-open（最危险）", V,
     'return self._deny(f"授权校验异常（fail-closed）：{type(e).__name__}")',
     'return ValidationResult.accept()'),
    ("BUG 2: tag_groups 返回 dict（e468 真实 bug）", V,
     'TagGroupLeaf(tags=[a.tag_prefix], match="any_strict")',
     '{"tags": [a.tag_prefix], "match": "any_strict"}'),
    ("BUG 3: 去掉 _strict", V,
     'match="any_strict"', 'match="any"'),
    ("BUG 4: 去掉跨 bank 校验", V,
     'in_bank = [a for a in access if a.bank_id == bank_id]',
     'in_bank = access'),
    ("BUG 5: 去掉 MCP 握手认证", T,
     'raise AuthenticationError(msg)', 'return  # BUG'),
]


def main():
    if not os.path.isdir(DEST):
        print(f"❌ 测试目录不存在：{DEST}")
        return 1

    print("════════ 基线（应全绿）════════")
    print("   ", run_tests())

    caught = 0
    for label, path, old, new in CASES:
        print()
        print(f"════════ {label} ════════")
        if not inject(path, old, new):
            continue
        result = run_tests()
        print("   ", result)
        if "failed" in result or "error" in result.lower():
            caught += 1
            print("    ✅ 测试抓到了这个 bug")
        else:
            print("    ❌ 测试没抓到（测试太弱！）")
        restore(path)

    print()
    print("════════ 恢复后基线（应全绿）════════")
    print("   ", run_tests())

    print()
    print(f"════════ 结论：{caught}/{len(CASES)} 个注入的 bug 被测试抓到 ════════")
    return 0 if caught == len(CASES) else 1


sys.exit(main())
