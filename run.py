#!/usr/bin/env python3
"""一键验证 + 完整报告（原生 Windows / Python 3.12 标准库，无第三方依赖）。

    python run.py              # 跑全部测试，然后输出旗舰/穷举/6万条基准报告
    python run.py --quick      # 测试 + 小规模基准
    python run.py --report     # 跳过单元测试，只出报告
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# 原生 Windows 下 stdout 被重定向到管道时可能是 cp936：统一 UTF-8 且容错，
# 避免打印 ✓ / 制表符等字符时 UnicodeEncodeError。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass


def run_tests() -> bool:
    loader = unittest.TestLoader()
    suite = loader.discover(
        str(ROOT / "tests"),
        pattern="test_*.py",
        top_level_dir=str(ROOT),
    )
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return result.wasSuccessful()


def main() -> int:
    args = set(sys.argv[1:])
    quick = "--quick" in args
    report_only = "--report" in args

    if not report_only:
        print("=" * 70)
        print("运行单元测试套件")
        print("=" * 70)
        if not run_tests():
            print("\n单元测试未全部通过。", file=sys.stderr)
            return 1
        print("\n全部单元测试通过。\n")

    from dutycert.cli import build_report, ARTIFACTS

    bench_n = 600 if quick else 60_000
    lines = build_report(bench_n=bench_n)
    text = "\n".join(lines)
    print(text)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    out = ARTIFACTS / "last_report.txt"
    out.write_text(text, encoding="utf-8")
    print(f"\n报告已写入: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
