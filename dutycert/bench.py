"""六万条多区域合成记录：单区域换岗“实际读取范围” vs 全量核验。

存储布局（仅标准库）
--------------------
``benchdata/region-XX.jsonl``：按区域分区、区域内按权限代排序的 JSONL；
``manifest.json``：记录每个 ``(区域, 权限代)`` 在对应文件中的精确字节区间
``[start, end)`` 与条数。另有内存 ``rid -> (region,start,end)`` 键索引。

三种读取口径，全部用 :class:`ReadMeter` 真实统计 ``read()`` 到的字节，而非估算：

1. ``full`` 全量核验：读完所有区域文件的全部 60000 条并逐条验 MAC。
2. ``region_scan`` 单区域换岗（只做区域裁剪）：读完选中区域的所有代。
3. ``epoch_range`` 单区域 + 当前权限代段索引：只读该代的连续字节区间。
4. ``point_read`` 按键索引精确点读换岗证书所需的 5 条证据，并真实跑一次引擎。

记录由固定随机种子确定性生成，数字可复现。
"""

from __future__ import annotations

import json
import random
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import BENCH_RECORDS, signing
from .engine import authorize_credential
from .exhaustive import self_contained_bundle
from .world import make_bundle

BENCH_ISSUER = "bench-issuer"
DETAIL_WORDS = (
    "alert", "ack", "rotation", "oncall", "handoff", "revoke", "approve",
    "delegate", "incident", "escalate", "silence", "verify",
)


@dataclass
class MeteredRead:
    name: str
    records_read: int = 0
    bytes_read: int = 0
    elapsed_s: float = 0.0
    seeks: int = 0
    ranges: list[tuple[str, int, int]] = field(default_factory=list)

    @property
    def span_bytes(self) -> int:
        """所读区间从最小 start 到最大 end 的外包跨度（可能含未读间隙）。"""
        if not self.ranges:
            return 0
        by_file: dict[str, list[tuple[int, int]]] = {}
        for f, s, e in self.ranges:
            by_file.setdefault(f, []).append((s, e))
        total = 0
        for f, ivs in by_file.items():
            total += max(e for _, e in ivs) - min(s for s, _ in ivs)
        return total


def _mac_identity(rec: dict[str, Any]) -> str:
    if rec.get("signer"):
        return rec["signer"]
    kind = rec.get("kind")
    if kind == "approval":
        return rec.get("approver", BENCH_ISSUER)
    if kind == "delegation":
        return rec.get("from_principal", BENCH_ISSUER)
    if kind == "credential":
        return rec.get("issuer", "duty-issuer")
    return BENCH_ISSUER


def verify_synth_mac(rec: dict[str, Any]) -> bool:
    return signing.verify_record_mac(rec, signing.simulate_key(_mac_identity(rec)))


def _synth_record(i: int, n_regions: int, rng: random.Random) -> dict[str, Any]:
    region_idx = i % n_regions if rng.random() < 0.5 else rng.randrange(n_regions)
    region = f"region-{region_idx:02d}"
    cur_epoch = 3 + (region_idx % 4)  # 该区域当前代为 3..6
    epoch = rng.randint(1, cur_epoch)
    lo = rng.randint(0, 40)
    kind = rng.choice(
        [
            "alert", "alert", "alert", "credential", "approval",
            "delegation", "shift_change", "revocation", "audit",
        ]
    )
    rec = {
        "rid": f"S{i:06d}",
        "kind": kind,
        "region": region,
        "epoch": epoch,
        "subject": f"user-{rng.randrange(400):03d}",
        "lo": lo,
        "hi": lo + rng.randint(1, 12),
        "at": rng.randint(0, 60),
        "detail": "-".join(rng.sample(DETAIL_WORDS, 3)),
        "signer": BENCH_ISSUER,
    }
    return signing.sign_record(rec, signing.simulate_key(BENCH_ISSUER))


@dataclass
class BenchReport:
    data_dir: str
    n_records: int
    n_regions: int
    picked_region: str
    picked_epoch: int
    full: MeteredRead
    region_scan: MeteredRead
    epoch_range: MeteredRead
    point_read: MeteredRead
    point_cluster_approved: bool
    region_records: int
    epoch_records: int
    manifest: dict[str, Any]

    def report_lines(self) -> list[str]:
        f, r, e, p = self.full, self.region_scan, self.epoch_range, self.point_read

        def ratio(a: int, b: int) -> str:
            return f"{a / b:6.1f}×" if b else "n/a"

        lines = [
            "== 六万条多区域合成记录：读取范围对比 ==",
            f"  记录总数={self.n_records} 区域数={self.n_regions} "
            f"选中换岗区域={self.picked_region} 当前权限代=gen{self.picked_epoch}",
            f"  落盘目录: {self.data_dir}",
            "  ┌──────────────────────┬──────────┬────────────┬───────────┬──────────┐",
            "  │ 读取口径             │ 记录数   │ 实读字节   │ 用时(ms)  │ 寻址次数 │",
            "  ├──────────────────────┼──────────┼────────────┼───────────┼──────────┤",
            f"  │ 全量核验             │ {f.records_read:>8} │ {f.bytes_read:>10,} │ {f.elapsed_s*1000:>9.1f} │ {f.seeks:>8} │",
            f"  │ 单区域整文件扫描     │ {r.records_read:>8} │ {r.bytes_read:>10,} │ {r.elapsed_s*1000:>9.1f} │ {r.seeks:>8} │",
            f"  │ 单区域+当前代区间    │ {e.records_read:>8} │ {e.bytes_read:>10,} │ {e.elapsed_s*1000:>9.1f} │ {e.seeks:>8} │",
            f"  │ 键索引点读5条证据    │ {p.records_read:>8} │ {p.bytes_read:>10,} │ {p.elapsed_s*1000:>9.2f} │ {p.seeks:>8} │",
            "  └──────────────────────┴──────────┴────────────┴───────────┴──────────┘",
            f"  区域记录数={self.region_records}，当前代记录数={self.epoch_records}",
            f"  记录数放大: 全量/单区域代段 = {ratio(f.records_read, e.records_read)}"
            f"   全量/点读 = {ratio(f.records_read, max(p.records_read,1))}",
            f"  字节放大:   全量/单区域代段 = {ratio(f.bytes_read, e.bytes_read)}"
            f"   全量/点读 = {ratio(f.bytes_read, max(p.bytes_read,1))}",
            f"  代段在区域文件内的连续字节范围: "
            f"{self.manifest['regions'][self.picked_region].get(str(self.picked_epoch))}",
            f"  点读证据真实引擎授权通过: {self.point_cluster_approved}",
        ]
        return lines


def _read_bytes_metered(
    path: Path, start: int, end: int, meter: MeteredRead, *, count_lines: bool = True
) -> list[dict[str, Any]]:
    t0 = time.perf_counter()
    with open(path, "rb") as fh:
        fh.seek(start)
        raw = fh.read(end - start)
    meter.seeks += 1
    meter.bytes_read += len(raw)
    meter.ranges.append((path.name, start, end))
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        rec = json.loads(line.decode("utf-8"))
        out.append(rec)
        if count_lines:
            meter.records_read += 1
    meter.elapsed_s += time.perf_counter() - t0
    return out


def run_benchmark(
    root: str | Path | None = None,
    n: int = BENCH_RECORDS,
    n_regions: int = 12,
    *,
    keep: bool = True,
) -> BenchReport:
    own_tmp = False
    if root is None:
        root = tempfile.mkdtemp(prefix="dutycert_bench_")
        own_tmp = True
    root = Path(root)
    if root.exists() and any(root.iterdir()):
        shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)

    rng = random.Random(16741)
    records = [_synth_record(i, n_regions, rng) for i in range(n)]
    records.sort(key=lambda r: (r["region"], r["epoch"], r["rid"]))

    # 选中一个固定区域做换岗，并在其当前代末尾追加真实可授权的 5 条证据
    picked_idx = 7 % n_regions
    picked_region = f"region-{picked_idx:02d}"
    picked_epoch = 3 + (picked_idx % 4)
    cluster = self_contained_bundle(
        "bench-cluster", picked_epoch, 10, 40, "bench-neo", "new_post",
        region=picked_region,
    )
    records.extend(cluster)

    rid_index: dict[str, tuple[str, int, int]] = {}
    region_epoch_extent: dict[str, dict[str, dict[str, int]]] = {}
    region_file_size: dict[str, int] = {}

    by_region: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        by_region.setdefault(rec["region"], []).append(rec)

    for region, recs in by_region.items():
        recs.sort(key=lambda r: (r["epoch"], r["rid"]))
        path = root / f"{region}.jsonl"
        offset = 0
        ep_start: dict[int, int] = {}
        ep_end: dict[int, int] = {}
        ep_count: dict[int, int] = {}
        with open(path, "wb") as fh:
            for rec in recs:
                ep = int(rec["epoch"])
                if ep not in ep_start:
                    ep_start[ep] = offset
                line = (json.dumps(rec, ensure_ascii=False) + "\n").encode("utf-8")
                fh.write(line)
                start, end = offset, offset + len(line)
                ep_end[ep] = end
                ep_count[ep] = ep_count.get(ep, 0) + 1
                rid_index[rec["rid"]] = (region, start, end)
                offset = end
        region_file_size[region] = offset
        region_epoch_extent[region] = {
            str(ep): {"start": ep_start[ep], "end": ep_end[ep], "count": ep_count[ep]}
            for ep in sorted(ep_start)
        }

    manifest = {
        "n_records": n,
        "n_regions": len(by_region),
        "region_file_size": region_file_size,
        "regions": region_epoch_extent,
    }
    (root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # 1) 全量核验
    full = MeteredRead("full")
    t0 = time.perf_counter()
    bad = 0
    for region in sorted(by_region):
        path = root / f"{region}.jsonl"
        size = region_file_size[region]
        recs = _read_bytes_metered(path, 0, size, full)
        for rec in recs:
            if not verify_synth_mac(rec):
                bad += 1
    full.elapsed_s = time.perf_counter() - t0  # 用包含验签的总时长覆盖读取计时
    if bad:
        raise AssertionError(f"全量核验发现 {bad} 条 MAC 无效记录")
    if full.records_read != n + len(cluster):
        raise AssertionError(
            f"全量记录数 {full.records_read} != {n + len(cluster)}"
        )

    # 2) 单区域整文件
    region_scan = MeteredRead("region_scan")
    path = root / f"{picked_region}.jsonl"
    recs = _read_bytes_metered(
        path, 0, region_file_size[picked_region], region_scan
    )
    region_scan.elapsed_s += _verify_all(recs)
    region_records = len(recs)

    # 3) 单区域 + 当前代连续区间
    ext = region_epoch_extent[picked_region][str(picked_epoch)]
    epoch_range = MeteredRead("epoch_range")
    ep_recs = _read_bytes_metered(
        path, ext["start"], ext["end"], epoch_range
    )
    epoch_range.elapsed_s += _verify_all(ep_recs)
    epoch_records = len(ep_recs)
    if epoch_records != ext["count"]:
        raise AssertionError("代段索引计数与实读行数不符")

    # 4) 键索引点读 cluster 的 5 条证据
    point = MeteredRead("point_read")
    point_recs: list[dict[str, Any]] = []
    t0 = time.perf_counter()
    for rid in [
        "bench-cluster-cred",
        "bench-cluster-apA",
        "bench-cluster-apB",
        "bench-cluster-delA",
        "bench-cluster-delB",
    ]:
        region, s, e = rid_index[rid]
        recs = _read_bytes_metered(root / f"{region}.jsonl", s, e, point)
        point_recs.extend(recs)
    for rec in point_recs:
        if not verify_synth_mac(rec):
            raise AssertionError("点读证据 MAC 无效")
    point.elapsed_s = time.perf_counter() - t0

    bundle = make_bundle()
    pmap = {r["rid"]: r for r in point_recs}
    verdict = authorize_credential(
        pmap["bench-cluster-cred"],
        pmap,
        bundle,
        region=picked_region,
        current_epoch=picked_epoch,
        at=20,
    )
    cluster_ok = bool(verdict.allowed)
    if not cluster_ok:
        raise AssertionError(f"点读证据未通过真实授权: {verdict.short()}")

    if own_tmp and not keep:
        shutil.rmtree(root, ignore_errors=True)

    return BenchReport(
        data_dir=str(root),
        n_records=n,
        n_regions=len(by_region),
        picked_region=picked_region,
        picked_epoch=picked_epoch,
        full=full,
        region_scan=region_scan,
        epoch_range=epoch_range,
        point_read=point,
        point_cluster_approved=cluster_ok,
        region_records=region_records,
        epoch_records=epoch_records,
        manifest=manifest,
    )


def _verify_all(recs: list[dict[str, Any]]) -> float:
    t0 = time.perf_counter()
    for rec in recs:
        if not verify_synth_mac(rec):
            raise AssertionError(f"记录 MAC 无效: {rec.get('rid')}")
    return time.perf_counter() - t0
