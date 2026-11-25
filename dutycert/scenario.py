"""旗舰复现：两个工作线程 + Barrier 还原关键交错。

确定性顺序（用 Barrier 对齐起跑、用 Event 固定提交先后）：

1. 主线程先落一盘 ``genesis(gen1)``。
2. 两个工作线程在同一个 :class:`threading.Barrier` 上对齐。
3. 撤销线程先提交撤销，把 ``cn-east`` 推进到 gen2，并置位
   ``revoke_durable``。
4. 换岗线程等到撤销落盘后，按 **当前 gen2 + 区域** 绑定提交换岗；事务
   整体 fsync 成功，但成功回执在返回客户端途中丢失，客户端只知道“结果
   未知(AMBIGUOUS)”。
5. 撤销线程等换岗落盘后，让 **两条 gen1 旧凭证分别作为两笔迟到事务** 落盘。
6. 主线程“重启”：丢弃内存对象，用 :meth:`DurableStore.reopen` 从磁盘重放，
   靠 ``request_id`` 幂等 resolving 丢回执的换岗，并重试 / 重放，最后从
   落盘记录搜索当前的最短批准证书与两张最短拒绝证书。
"""

from __future__ import annotations

import threading
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .cert import Certificate, shortest_certificate, verify_certificate
from .engine import Verdict
from .store import DurableStore, ReceiptLost, RecoveredState
from .submission import (
    BindingRejected,
    Submission,
    commit_revocation,
    submit_data_plane,
)
from .world import (
    REGION,
    T_EVAL,
    build_cycle_world,
    build_flagship,
    build_shared_control_world,
)


@dataclass
class ScenarioResult:
    data_dir: str
    trace: list[str] = field(default_factory=list)
    client_views: dict[str, str] = field(default_factory=dict)
    recovered_epochs: dict[str, int] = field(default_factory=dict)
    recovered_record_rids: list[str] = field(default_factory=list)
    approval_cert: Certificate | None = None
    denial_certs: dict[str, Certificate] = field(default_factory=dict)
    approval_verdict: Verdict | None = None
    denial_verdicts: dict[str, Verdict] = field(default_factory=dict)
    retry_duplicated: bool | None = None
    retry_last_seq_unchanged: bool | None = None
    stale_submission_code: str | None = None
    attack_certs: dict[str, Certificate] = field(default_factory=dict)
    attack_verdicts: dict[str, Verdict] = field(default_factory=dict)
    passed_checks: list[str] = field(default_factory=list)

    def report_lines(self) -> list[str]:
        lines: list[str] = []
        lines.append("== 双线程 + Barrier 旗舰交错 ==")
        lines.append(f"数据目录(落盘): {self.data_dir}")
        lines.append("-- 确定性时间线 --")
        lines.extend("  " + x for x in self.trace)
        lines.append("-- 客户端视角 --")
        for k, v in self.client_views.items():
            lines.append(f"  {k}: {v}")
        lines.append(
            f"恢复后区域权限代: {self.recovered_epochs}"
        )
        lines.append(
            f"恢复记录 {len(self.recovered_record_rids)} 条: "
            + ", ".join(self.recovered_record_rids)
        )
        if self.retry_duplicated is not None:
            lines.append(
                "丢回执换岗用同一 request_id 重试: "
                f"duplicated={self.retry_duplicated}, "
                f"序列号未增长={self.retry_last_seq_unchanged}"
            )
        if self.stale_submission_code:
            lines.append(
                f"旧 gen1 提交在恢复后重放 -> {self.stale_submission_code}"
            )
        lines.append("-- 当前最短证书（从落盘记录搜索） --")
        if self.approval_cert:
            lines.append("  " + self.approval_cert.brief())
            lines.append("    验证: " + (self.approval_verdict.short() if self.approval_verdict else "?"))
        for rid, cert in self.denial_certs.items():
            lines.append("  " + cert.brief())
            v = self.denial_verdicts.get(rid)
            lines.append("    验证: " + (v.short() if v else "?"))
        lines.append("-- 批准根攻击的最短拒绝证书 --")
        for name, cert in self.attack_certs.items():
            v = self.attack_verdicts[name]
            lines.append(f"  [{name}] " + cert.brief())
            lines.append("    验证: " + v.short())
        lines.append("-- 自检断言 --")
        for c in self.passed_checks:
            lines.append(f"  ✓ {c}")
        return lines


def _attack_cert(aw: Any) -> tuple[Certificate, Verdict]:
    amap = aw.record_map()
    state = RecoveredState(
        records=list(aw.records),
        by_rid=amap,
        region_epochs={aw.region: aw.epoch},
        last_seq=len(aw.records),
    )
    cert = shortest_certificate(
        state, aw.bundle, cred_rid=aw.cred_rid, region=aw.region, at=aw.at
    )
    verdict = verify_certificate(cert, aw.bundle)
    return cert, verdict


def run_flagship(data_dir: str | Path | None = None) -> ScenarioResult:
    world = build_flagship()
    bundle = world.bundle
    if data_dir is None:
        data_dir = tempfile.mkdtemp(prefix="dutycert_flagship_")
    data_dir = str(data_dir)

    # 固定演示目录可能被重复运行：清空，保证从 gen1 干净起跑
    shutil.rmtree(data_dir, ignore_errors=True)

    result = ScenarioResult(data_dir=data_dir)
    trace_lock = threading.Lock()

    def log(msg: str) -> None:
        with trace_lock:
            result.trace.append(msg)

    # 干净目录，避免重复运行读到上次数据
    store = DurableStore(data_dir, bundle.head_key)
    genesis = {
        "rid": "genesis-cn-east",
        "kind": "genesis",
        "region": REGION,
        "epoch": 1,
        "at": 0,
    }
    store.commit_batch([genesis], txid="tx-genesis", request_id="req-genesis")
    log("主线程: 落盘 genesis，cn-east 当前权限代=1")

    barrier = threading.Barrier(2)
    revoke_durable = threading.Event()
    change_committed = threading.Event()

    def worker_revoke() -> None:
        name = "W-revoke"
        barrier.wait()
        log(f"{name}: 越过屏障，提交撤销（必须最先提交）")
        commit_revocation(
            store, world.revocation_batch[0], request_id="req-revoke-1"
        )
        log(f"{name}: 撤销已 fsync 提交，cn-east -> gen2")
        revoke_durable.set()

        # 等换岗事务落盘后，两条旧凭证才“晚到”
        change_committed.wait(timeout=15)
        for i, batch in enumerate(world.late_batches, start=1):
            rid = batch[-1]["rid"]
            store.commit_batch(
                batch, txid=f"tx-late-old-{i}", request_id=f"req-late-old-{i}"
            )
            log(f"{name}: 第 {i} 条旧凭证晚到并落盘 -> {rid}")

    def worker_change() -> None:
        name = "W-change"
        barrier.wait()
        # 关键：不允许抢在撤销前面提交
        revoke_durable.wait(timeout=15)
        current = store.region_epochs[REGION]
        log(f"{name}: 见到撤销已提交，按 region={REGION}, gen={current} 绑定换岗")
        sub = Submission(
            request_id="req-change-oli-neo",
            region=REGION,
            epoch=current,
            records=tuple(world.change_batch),
            kind="shift_change",
        )
        try:
            submit_data_plane(store, sub, lose_receipt=True)
            result.client_views[name] = "ACK_RECEIVED"  # 不应发生
            log(f"{name}: 收到成功回执（与设定不符）")
        except ReceiptLost:
            # 客户端只知道发出后回执没回来 —— 结果未知，不能假设成功或失败
            result.client_views[name] = "AMBIGUOUS(成功回执丢失，未重放前不确定)"
            log(f"{name}: 换岗已提交但成功回执丢失，客户端视角=AMBIGUOUS")
        except Exception as exc:  # pragma: no cover - 防御性
            result.client_views[name] = f"ERROR:{type(exc).__name__}:{exc}"
            log(f"{name}: 异常 {type(exc).__name__}: {exc}")
        finally:
            change_committed.set()

    t_rev = threading.Thread(target=worker_revoke, name="W-revoke")
    t_chg = threading.Thread(target=worker_change, name="W-change")
    t_rev.start()
    t_chg.start()
    t_rev.join(timeout=20)
    t_chg.join(timeout=20)
    if t_rev.is_alive() or t_chg.is_alive():  # pragma: no cover
        raise RuntimeError("旗舰工作线程未在超时内结束，可能死锁")
    log("两个工作线程均已汇合")

    # —— 模拟进程重启：丢弃内存 store，从磁盘重放 ——
    fresh = DurableStore.reopen(data_dir, bundle.head_key, repair=True)
    state = fresh.recover(repair=True)
    result.recovered_epochs = dict(state.region_epochs)
    result.recovered_record_rids = [r["rid"] for r in state.records]

    # 幂等重试丢回执的换岗
    seq_before = fresh.last_seq
    retry_sub = Submission(
        request_id="req-change-oli-neo",
        region=REGION,
        epoch=2,
        records=tuple(world.change_batch),
        kind="shift_change",
    )
    receipt = submit_data_plane(fresh, retry_sub)
    result.retry_duplicated = bool(receipt.duplicated)
    result.retry_last_seq_unchanged = fresh.last_seq == seq_before

    # 旧 gen1 提交重放 -> 必须被权限代栅栏拒绝
    stale_sub = Submission(
        request_id="req-stale-gen1",
        region=REGION,
        epoch=1,
        records=tuple(),
        kind="shift_change",
    )
    try:
        submit_data_plane(fresh, stale_sub)
        result.stale_submission_code = "NOT_REJECTED"  # 不应发生
    except BindingRejected as exc:
        result.stale_submission_code = exc.code

    # —— 从落盘记录构造当前最短证书 ——
    result.approval_cert = shortest_certificate(
        state, bundle, cred_rid=world.new_cred_rid, region=REGION, at=T_EVAL
    )
    result.approval_verdict = verify_certificate(result.approval_cert, bundle)

    for rid in world.old_cred_rids:
        cert = shortest_certificate(
            state, bundle, cred_rid=rid, region=REGION, at=T_EVAL
        )
        result.denial_certs[rid] = cert
        result.denial_verdicts[rid] = verify_certificate(cert, bundle)

    # —— 两个批准根攻击的最短拒绝证书（独立小世界） ——
    for aw in (build_shared_control_world(), build_cycle_world()):
        cert, verdict = _attack_cert(aw)
        result.attack_certs[aw.name] = cert
        result.attack_verdicts[aw.name] = verdict

    # —— 自检（同时供 unittest 复用断言） ——
    checks = result.passed_checks
    assert state.region_epochs.get(REGION) == 2
    checks.append("撤销先提交并把 cn-east 栅栏到 gen2")
    assert result.client_views["W-change"].startswith("AMBIGUOUS")
    checks.append("换岗成功回执丢失，客户端仅知 AMBIGUOUS")
    assert "cred-old-oli" in state.by_rid and "cred-old-sub-sam" in state.by_rid
    checks.append("两条晚到旧凭证均已落盘并可在恢复后读到")
    assert result.retry_duplicated and result.retry_last_seq_unchanged
    checks.append("同一 request_id 恢复重试为幂等命中，不产生第二次换岗")
    assert result.stale_submission_code == "STALE_GENERATION"
    checks.append("旧 gen1 提交被 STALE_GENERATION 拒绝")
    assert result.approval_verdict and result.approval_verdict.allowed
    assert result.approval_cert and result.approval_cert.irredundant
    checks.append("新岗持双人独立根 -> 最短批准证书验证通过且无冗余证据")
    for rid, v in result.denial_verdicts.items():
        assert not v.allowed and v.code == "EPOCH_FENCED", (rid, v.short())
        assert result.denial_certs[rid].irredundant
    checks.append("两条旧凭证均被 EPOCH_FENCED 拒绝，最短拒绝证书无冗余")
    for name, v in result.attack_verdicts.items():
        assert not v.allowed
        assert v.code == "INSUFFICIENT_INDEPENDENT_ROOTS"
    assert result.attack_verdicts["shared-control-root"].detail.startswith(
        "SHARED_CONTROL_ROOT"
    )
    assert result.attack_verdicts["cyclic-proxy"].detail == "CYCLE_PROXY"
    checks.append("共享控制根 / 循环代理均无法凑出两条独立根，拒绝证书成立")

    return result
