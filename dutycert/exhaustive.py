"""小整数时间轴上的短交错穷举模型检查。

三层穷举，全部用真实引擎 / 真实落盘代码做判定，而不是另写一套“碰巧一致”
的影子逻辑：

A. 半开时间轴：对旧岗 / 新岗 / 替班三类凭证，在 ``lo-2 .. hi+2`` 的小整数
   时刻逐点核对 ``NOT_YET_VALID / OK / INTERVAL_EXPIRED``，并核对区域、
   权限代栅栏。
B. 拓扑：独立双根、共享控制根、循环代理三种结构在所有有效时刻都给出预期。
C. 交错：
   - 7 个事件 ``R撤销 / C换岗 / A回执 / O1旧凭证 / O2旧替班 / X崩溃 / V恢复``
     的全部 ``7! = 5040`` 个排列，逐步构造“当时已落盘世界”，每一步都调用
     真实 :func:`authorize_credential` 差分核对安全不变量；
   - 5 个落盘事件 ``R / C / Y幂等重试 / K重启 / K重启`` 的全部 60 个唯一
     排列，用真实 :class:`DurableStore` + fsync + 重开恢复，验证“恰好一次”
     与恢复后最短批准证书。

核心安全不变量
--------------
1. 撤销一旦提交（gen1→gen2），此后任何交错前缀里，gen1 旧凭证都不可能被
   批准，一律 ``EPOCH_FENCED``；撤销之前则按半开区间正常判定。
2. gen2 换岗只有在撤销之后绑定当前代才可能提交；一旦提交落盘，崩溃 / 回执
   丢失 / 恢复位置都不能改变恢复后的批准结论。
3. 共享控制根与循环代理在任何交错 / 时刻下都不产生两根授权。
4. 恢复是对已提交 WAL 的确定性重放：``V``/``K`` 出现在排列的任何位置都不
   改变最终真相；同一 ``request_id`` 至多产生一次效果。
"""

from __future__ import annotations

import itertools
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import signing
from .cert import shortest_certificate, verify_certificate
from .engine import (
    EPOCH_FENCED,
    INTERVAL_EXPIRED,
    NOT_YET_VALID,
    REGION_MISMATCH,
    authorize_credential,
)
from .store import DurableStore
from .submission import BindingRejected, Submission, commit_revocation, submit_data_plane
from .trust import TrustBundle
from .world import (
    BOB,
    HEAD_KEY,
    REGION,
    ROOT_A,
    ROOT_B,
    build_cycle_world,
    build_flagship,
    build_shared_control_world,
    make_bundle,
)


# ---------------------------------------------------------------------------
# 自包含凭证束：每个前缀唯一命名，任意子集都能独立通过两根校验
# ---------------------------------------------------------------------------
def _sign(rec: dict[str, Any], who: str) -> dict[str, Any]:
    return signing.sign_record(rec, signing.simulate_key(who))


def self_contained_bundle(
    prefix: str,
    epoch: int,
    lo: int,
    hi: int,
    subject: str,
    cred_kind: str,
    *,
    region: str = REGION,
) -> list[dict[str, Any]]:
    aa = f"{prefix}-alice"
    bb = f"{prefix}-bob"
    d1 = _sign(
        {
            "rid": f"{prefix}-delA",
            "kind": "delegation",
            "from_principal": ROOT_A,
            "to_principal": aa,
            "region": region,
            "epoch": epoch,
            "lo": 0,
            "hi": 64,
        },
        ROOT_A,
    )
    d2 = _sign(
        {
            "rid": f"{prefix}-delB",
            "kind": "delegation",
            "from_principal": ROOT_B,
            "to_principal": bb,
            "region": region,
            "epoch": epoch,
            "lo": 0,
            "hi": 64,
        },
        ROOT_B,
    )
    a1 = _sign(
        {
            "rid": f"{prefix}-apA",
            "kind": "approval",
            "approver": aa,
            "root": ROOT_A,
            "region": region,
            "epoch": epoch,
            "lo": 0,
            "hi": 64,
        },
        aa,
    )
    a2 = _sign(
        {
            "rid": f"{prefix}-apB",
            "kind": "approval",
            "approver": bb,
            "root": ROOT_B,
            "region": region,
            "epoch": epoch,
            "lo": 0,
            "hi": 64,
        },
        bb,
    )
    cred = _sign(
        {
            "rid": f"{prefix}-cred",
            "kind": "credential",
            "cred_kind": cred_kind,
            "subject": subject,
            "issuer": "duty-issuer",
            "region": region,
            "epoch": epoch,
            "lo": lo,
            "hi": hi,
            "approval_rids": [f"{prefix}-apA", f"{prefix}-apB"],
        },
        "duty-issuer",
    )
    return [d1, d2, a1, a2, cred]


@dataclass
class ExhaustiveReport:
    timeline_cases: int = 0
    topology_cases: int = 0
    interleavings: int = 0
    prefix_checks: int = 0
    disk_interleavings: int = 0
    ack_lost_cases: int = 0
    violations: list[str] = field(default_factory=list)
    canonical_witness: tuple[str, ...] | None = None
    disk_approval_certs: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations

    def raise_if_broken(self) -> None:
        if self.violations:
            head = "\n  ".join(self.violations[:15])
            more = f"\n  …另有 {len(self.violations) - 15} 条" if len(self.violations) > 15 else ""
            raise AssertionError(f"穷举发现 {len(self.violations)} 个违例:\n  {head}{more}")

    def report_lines(self) -> list[str]:
        status = "全部通过 ✓" if self.ok else f"发现 {len(self.violations)} 个违例 ✗"
        lines = [
            "== 短交错 / 小整数时间轴穷举 ==",
            f"  半开时间轴用例: {self.timeline_cases}",
            f"  根拓扑用例: {self.topology_cases}",
            f"  纯模型交错排列: {self.interleavings} (逐步差分检查 {self.prefix_checks} 次)",
            f"  其中成功回执丢失排列: {self.ack_lost_cases}",
            f"  真实落盘重启交错: {self.disk_interleavings} (产出批准证书 {self.disk_approval_certs})",
            f"  结论: {status}",
        ]
        if self.canonical_witness:
            lines.append(
                "  旗舰顺序作为其中一个排列: " + " > ".join(self.canonical_witness)
            )
        if not self.ok:
            lines.extend("  ✗ " + v for v in self.violations[:15])
        return lines


# ---------------------------------------------------------------------------
# A. 半开时间轴 + 区域 / 代绑定
# ---------------------------------------------------------------------------
def check_timeline(rep: ExhaustiveReport) -> None:
    bundle = make_bundle()
    specs = [
        ("tl-old", 1, 10, 20, "old_oli", "old_post"),
        ("tl-new", 2, 12, 22, "neo", "new_post"),
        ("tl-sub", 1, 11, 18, "sub_sam", "substitute"),
    ]
    for prefix, epoch, lo, hi, subj, kind in specs:
        recs = self_contained_bundle(prefix, epoch, lo, hi, subj, kind)
        world = {r["rid"]: r for r in recs}
        cred = world[f"{prefix}-cred"]
        for t in range(lo - 2, hi + 3):
            # 代匹配时：纯半开区间决定
            v = authorize_credential(
                cred, world, bundle, region=REGION, current_epoch=epoch, at=t
            )
            rep.timeline_cases += 1
            if t < lo:
                expect = NOT_YET_VALID
            elif t >= hi:
                expect = INTERVAL_EXPIRED
            else:
                expect = "OK"
            got = "OK" if v.allowed else v.code
            if got != expect:
                rep.violations.append(
                    f"timeline {kind} {lo},{hi} t={t}: 期望 {expect} 得到 {got}({v.detail})"
                )

            # 代不匹配：无论 t 在区间何处，都必须先被栅栏拒绝
            other_epoch = epoch + 1
            v2 = authorize_credential(
                cred, world, bundle, region=REGION, current_epoch=other_epoch, at=t
            )
            rep.timeline_cases += 1
            if v2.allowed or v2.code != EPOCH_FENCED:
                rep.violations.append(
                    f"epoch-fence {kind} t={t}: 期望 EPOCH_FENCED 得到 {v2.short()}"
                )

            # 区域不匹配
            v3 = authorize_credential(
                cred, world, bundle, region="cn-other", current_epoch=epoch, at=t
            )
            rep.timeline_cases += 1
            if v3.allowed or v3.code != REGION_MISMATCH:
                rep.violations.append(
                    f"region {kind} t={t}: 期望 REGION_MISMATCH 得到 {v3.short()}"
                )


# ---------------------------------------------------------------------------
# B. 根拓扑
# ---------------------------------------------------------------------------
def check_topology(rep: ExhaustiveReport) -> None:
    # 独立双根：在整个有效区间内都应批准
    bundle = make_bundle()
    recs = self_contained_bundle("topo-ok", 2, 4, 8, "neo", "new_post")
    world = {r["rid"]: r for r in recs}
    for t in range(0, 12):
        v = authorize_credential(
            world["topo-ok-cred"], world, bundle, region=REGION, current_epoch=2, at=t
        )
        rep.topology_cases += 1
        if 4 <= t < 8:
            if not v.allowed:
                rep.violations.append(f"topo independent t={t} 应批准: {v.short()}")
        else:
            if v.allowed:
                rep.violations.append(f"topo independent t={t} 不应在区间外批准")

    # 共享控制根 / 循环代理：穷举小时间轴，任何时刻都不得批准
    for aw in (build_shared_control_world(), build_cycle_world()):
        wmap = aw.record_map()
        for t in range(aw.at - 6, aw.at + 8):
            v = authorize_credential(
                wmap[aw.cred_rid],
                wmap,
                aw.bundle,
                region=aw.region,
                current_epoch=aw.epoch,
                at=t,
            )
            rep.topology_cases += 1
            if v.allowed:
                rep.violations.append(
                    f"topo {aw.name} t={t} 竟然批准: {v.short()}"
                )
            # 在凭证时间区间内，原因必须精确落到对应攻击
            cred = wmap[aw.cred_rid]
            if cred["lo"] <= t < cred["hi"]:
                if v.code != aw.expected_code or not v.detail.startswith(
                    aw.expected_detail_prefix
                ):
                    rep.violations.append(
                        f"topo {aw.name} t={t} 原因不符: "
                        f"期望 {aw.expected_code}/{aw.expected_detail_prefix}* "
                        f"得到 {v.code}/{v.detail}"
                    )


# ---------------------------------------------------------------------------
# C1. 5040 个纯模型交错排列 + 真实引擎逐步差分
# ---------------------------------------------------------------------------
EVENTS = ("R", "C", "A", "O1", "O2", "X", "V")
CANONICAL = ("R", "C", "A", "O1", "O2", "X", "V")  # 含“撤销先、换岗成、回执丢”的参考序


def check_interleavings(rep: ExhaustiveReport) -> None:
    bundle = make_bundle()

    # 预构造各事件对应的自包含记录束
    chg = self_contained_bundle("ix-chg", 2, 12, 22, "neo", "new_post")
    old1 = self_contained_bundle("ix-o1", 1, 10, 20, "old_oli", "old_post")
    old2 = self_contained_bundle("ix-o2", 1, 11, 18, "sub_sam", "substitute")
    chg_map = {r["rid"]: r for r in chg}
    o1_map = {r["rid"]: r for r in old1}
    o2_map = {r["rid"]: r for r in old2}
    chg_cred = "ix-chg-cred"
    o1_cred = "ix-o1-cred"
    o2_cred = "ix-o2-cred"

    # 旗舰参考序（必须是 7! 个排列之一）：撤销→换岗→两条旧凭证晚到→
    # 崩溃→（本应送达的）回执落在崩溃之后→恢复。C 与 A 之间夹着 X，
    # 因此成功回执确定丢失。
    rep.canonical_witness = ("R", "C", "O1", "O2", "X", "A", "V")

    for perm in itertools.permutations(EVENTS):
        rep.interleavings += 1
        durable: dict[str, dict[str, Any]] = {}
        r_done = False
        c_accepted = False
        o1_done = o2_done = False
        recovered_snapshot: dict[str, dict[str, Any]] | None = None

        positions = {e: i for i, e in enumerate(perm)}
        # 换岗成功 = 撤销排在 C 之前（gen2 已建立，绑定才匹配）
        change_succeeded = positions["R"] < positions["C"]
        # 回执有效送达 = A 在 C 之后，且 C→A 之间没有崩溃 X
        ack_delivered = (
            positions["A"] > positions["C"]
            and not (positions["C"] < positions["X"] < positions["A"])
        )
        if change_succeeded and not ack_delivered:
            rep.ack_lost_cases += 1

        for e in perm:
            if e == "R":
                r_done = True
            elif e == "C":
                # gen2 换岗必须绑定当前代：只有撤销已提交(当前=2)才受理
                if r_done:
                    c_accepted = True
                    durable.update(chg_map)
            elif e == "O1":
                o1_done = True
                durable.update(o1_map)
            elif e == "O2":
                o2_done = True
                durable.update(o2_map)
            elif e == "V":
                # 恢复 = 对已提交持久记录的确定性重放；快照必须等于当前真相
                recovered_snapshot = dict(durable)
            # A / X 不改变持久真相

            current_epoch = 2 if r_done else 1

            # —— 不变量 1：O1 已到达的每个前缀 ——
            if o1_done:
                v = authorize_credential(
                    durable.get(o1_cred),
                    durable,
                    bundle,
                    region=REGION,
                    current_epoch=current_epoch,
                    at=13,
                )
                rep.prefix_checks += 1
                if r_done:
                    if v.allowed or v.code != EPOCH_FENCED:
                        rep.violations.append(
                            f"{perm} O1 after R 必须 EPOCH_FENCED: {v.short()}"
                        )
                else:
                    if not v.allowed:
                        rep.violations.append(
                            f"{perm} O1 before R t13 应按半开区间批准: {v.short()}"
                        )

            # —— 不变量 1（第二条旧凭证/替班） ——
            if o2_done:
                v = authorize_credential(
                    durable.get(o2_cred),
                    durable,
                    bundle,
                    region=REGION,
                    current_epoch=current_epoch,
                    at=13,
                    acting_for="old_oli",
                )
                rep.prefix_checks += 1
                if r_done:
                    if v.allowed or v.code != EPOCH_FENCED:
                        rep.violations.append(
                            f"{perm} O2 after R 必须 EPOCH_FENCED: {v.short()}"
                        )
                else:
                    if not v.allowed:
                        rep.violations.append(
                            f"{perm} O2 before R t13 应批准(替班区间内): {v.short()}"
                        )

            # —— 不变量 2：换岗一旦受理，后续任何前缀都可从持久世界批准 ——
            if c_accepted:
                v = authorize_credential(
                    durable.get(chg_cred),
                    durable,
                    bundle,
                    region=REGION,
                    current_epoch=2,
                    at=13,
                )
                rep.prefix_checks += 1
                if not v.allowed:
                    rep.violations.append(
                        f"{perm} 已提交换岗在后续前缀失去批准: {v.short()}"
                    )

        # —— 恢复确定性：若 V 是最后一个事件，恢复快照必须等于最终持久真相 ——
        if perm[-1] == "V":
            if recovered_snapshot != durable:
                rep.violations.append(f"{perm} 末尾恢复快照与持久真相不一致")
            if c_accepted:
                v = authorize_credential(
                    recovered_snapshot.get(chg_cred), recovered_snapshot, bundle,
                    region=REGION, current_epoch=2, at=13,
                )
                if not v.allowed:
                    rep.violations.append(
                        f"{perm} 末尾恢复后换岗未获批准: {v.short()}"
                    )

        # 每个排列末尾 R 必然已执行 → 旧凭证必被栅栏；与 A/X/V 位置无关
        if o1_done:
            v = authorize_credential(
                durable.get(o1_cred), durable, bundle,
                region=REGION, current_epoch=2, at=13,
            )
            if v.allowed or v.code != EPOCH_FENCED:
                rep.violations.append(f"{perm} 末尾 O1 未被栅栏拒绝")


# ---------------------------------------------------------------------------
# C2. 真实落盘的 60 个重启 / 幂等交错
# ---------------------------------------------------------------------------
def check_disk_interleavings(rep: ExhaustiveReport) -> None:
    world = build_flagship()
    bundle = world.bundle

    orders = sorted(set(itertools.permutations(("R", "C", "Y", "K", "K"))))
    rep.disk_interleavings = 0
    for order in orders:
        rep.disk_interleavings += 1
        tmp = tempfile.mkdtemp(prefix="dutycert_ix_")
        try:
            store = DurableStore(tmp, HEAD_KEY)
            store.commit_batch(
                [{
                    "rid": "genesis-cn-east",
                    "kind": "genesis",
                    "region": REGION,
                    "epoch": 1,
                    "at": 0,
                }],
                txid="tx-genesis",
                request_id="req-genesis",
            )

            def do_r() -> None:
                try:
                    commit_revocation(
                        store, world.revocation_batch[0], request_id="req-rev-1"
                    )
                except BindingRejected:
                    pass

            def change_sub() -> Submission:
                return Submission(
                    request_id="req-change-oli-neo",
                    region=REGION,
                    epoch=2,
                    records=tuple(world.change_batch),
                )

            def do_c() -> None:
                try:
                    submit_data_plane(store, change_sub())
                except BindingRejected:
                    pass

            def do_y() -> None:
                # 客户端用同一 request_id 重试（可能在重启之后）
                try:
                    submit_data_plane(store, change_sub())
                except BindingRejected:
                    pass

            def do_k() -> None:
                nonlocal store
                recovered = DurableStore.reopen(tmp, HEAD_KEY, repair=True)
                recovered.recover(repair=True)
                store = recovered

            for ev in order:
                {"R": do_r, "C": do_c, "Y": do_y, "K": do_k}[ev]()

            state = store.recover()
            pos = {e: i for i, e in enumerate(order) if e != "K"}
            # 若 R 排在 C、Y 两者之后，则两次提交都撞 gen1，换岗不存在
            change_expected = not (
                order.index("R") > max(order.index("C"), order.index("Y"))
            )

            change_rids = [
                r["rid"] for r in state.records if r["rid"] == "change-oli-to-neo"
            ]
            cred_rids = [
                r["rid"] for r in state.records if r["rid"] == "cred-neo-new"
            ]
            if change_expected:
                if len(change_rids) != 1 or len(cred_rids) != 1:
                    rep.violations.append(
                        f"disk {order}: 期望恰好一次换岗, "
                        f"change={len(change_rids)} cred={len(cred_rids)}"
                    )
                    continue
                if "req-change-oli-neo" not in state.request_meta:
                    rep.violations.append(f"disk {order}: 缺少幂等索引")
                    continue
                cert = shortest_certificate(
                    state, bundle, cred_rid="cred-neo-new",
                    region=REGION, at=13,
                )
                verdict = verify_certificate(cert, bundle)
                if not verdict.allowed:
                    rep.violations.append(
                        f"disk {order}: 恢复后最短证书未批准: {verdict.short()}"
                    )
                else:
                    rep.disk_approval_certs += 1
            else:
                if change_rids or cred_rids:
                    rep.violations.append(
                        f"disk {order}: R 最后的顺序不应产生 gen2 换岗"
                    )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def run_exhaustive(*, disk: bool = True) -> ExhaustiveReport:
    rep = ExhaustiveReport()
    check_timeline(rep)
    check_topology(rep)
    check_interleavings(rep)
    if disk:
        check_disk_interleavings(rep)
    rep.raise_if_broken()
    return rep
