"""一键报告：旗舰场景 + 穷举 + 六万条基准。

用法::

    python -m dutycert            # 完整运行（含 60000 条基准）
    python -m dutycert --quick    # 小规模基准，快速自检
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from . import BENCH_RECORDS
from .bench import run_benchmark
from .exhaustive import run_exhaustive
from .scenario import run_flagship

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = REPO_ROOT / "artifacts"


def build_report(*, bench_n: int = BENCH_RECORDS, bench_dir: Path | None = None) -> list[str]:
    lines: list[str] = []
    lines.append("值班资格的原子换岗与证明 —— 标准库模拟（无真实账号）")
    lines.append("=" * 64)

    scenario = run_flagship(ARTIFACTS / "flagship-demo")
    lines.extend(scenario.report_lines())
    lines.append("")

    exhaustive = run_exhaustive(disk=True)
    lines.extend(exhaustive.report_lines())
    lines.append("")

    if bench_dir is None:
        bench_dir = ARTIFACTS / "benchdata"
    bench = run_benchmark(bench_dir, n=bench_n)
    lines.extend(bench.report_lines())
    lines.append("")
    lines.append("全部自检通过。")
    return lines


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass

    parser = argparse.ArgumentParser(description="值班资格原子换岗与证明")
    parser.add_argument("--quick", action="store_true", help="使用小规模基准记录数")
    parser.add_argument("--bench-n", type=int, default=BENCH_RECORDS)
    args = parser.parse_args(argv)

    bench_n = 600 if args.quick else args.bench_n
    try:
        lines = build_report(bench_n=bench_n)
    except Exception:
        print("运行失败：", file=sys.stderr)
        traceback.print_exc()
        return 1

    text = "\n".join(lines)
    print(text)
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    out = ARTIFACTS / "last_report.txt"
    out.write_text(text, encoding="utf-8")
    print(f"\n报告已写入: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
