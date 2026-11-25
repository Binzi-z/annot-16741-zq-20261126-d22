"""构造确定性的模拟值班世界（无真实账号）。

包含：
- 旗舰世界 ``build_flagship``：旧岗 / 新岗 / 替班三类半开凭证、
  两条真正独立的批准根、撤销与换岗记录、两条晚到的旧权限代凭证。
- 两个攻击小世界：``build_shared_control_world``（两人共享控制根）与
  ``build_cycle_world``（循环代理）。

所有批准 / 代理 / 凭证记录都用 HMAC 做模拟签名，签名密钥由主体 ID 派生，
与 :class:`dutycert.trust.TrustBundle` 的默认取键逻辑一致。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import signing
from .trust import TrustBundle

REGION = "cn-east"
OTHER_REGION = "cn-north"
EPOCH_OLD = 1
EPOCH_NEW = 2
T_EVAL = 13  # 落在新岗 [12,22) 内，也落在两条旧凭证的时间区间内

HEAD_KEY = signing.simulate_key("dutycert-head-anchor-key")
ISSUER = "duty-issuer"

ROOT_A = "root-a"
ROOT_B = "root-b"
ALICE = "alice"
BOB = "bob"


def sign(rec: dict[str, Any], signer: str) -> dict[str, Any]:
    return signing.sign_record(rec, signing.simulate_key(signer))


def make_bundle() -> TrustBundle:
    """两条独立批准根；批准人分属不同控制根。"""
    control = {
        ALICE: "ctrl-a",
        BOB: "ctrl-b",
        # 攻击：两名批准人表面连到不同批准根，却共享同一个身份控制根
        "carol": "ctrl-shared",
        "dave": "ctrl-shared",
        # 循环代理主体
        "pat": "ctrl-cycle",
        "cy-a": "ctrl-cycle",
        "cy-b": "ctrl-cycle",
    }
    return TrustBundle(
        trusted_roots=frozenset({ROOT_A, ROOT_B}),
        control_root_of=control,
        head_key=HEAD_KEY,
        required_roots=2,
    )


def _delegation(
    rid: str,
    grantor: str,
    grantee: str,
    epoch: int,
    *,
    region: str = REGION,
    lo: int = 0,
    hi: int = 64,
) -> dict[str, Any]:
    return sign(
        {
            "rid": rid,
            "kind": "delegation",
            "from_principal": grantor,
            "to_principal": grantee,
            "region": region,
            "epoch": epoch,
            "lo": lo,
            "hi": hi,
        },
        grantor,
    )


def _approval(
    rid: str,
    approver: str,
    root: str,
    epoch: int,
    *,
    region: str = REGION,
    lo: int = 0,
    hi: int = 64,
) -> dict[str, Any]:
    return sign(
        {
            "rid": rid,
            "kind": "approval",
            "approver": approver,
            "root": root,
            "region": region,
            "epoch": epoch,
            "lo": lo,
            "hi": hi,
        },
        approver,
    )


def _credential(
    rid: str,
    cred_kind: str,
    subject: str,
    epoch: int,
    lo: int,
    hi: int,
    approval_rids: list[str],
    *,
    region: str = REGION,
    covers_subject: str | None = None,
) -> dict[str, Any]:
    rec: dict[str, Any] = {
        "rid": rid,
        "kind": "credential",
        "cred_kind": cred_kind,  # old_post | new_post | substitute
        "subject": subject,
        "issuer": ISSUER,
        "region": region,
        "epoch": epoch,
        "lo": lo,
        "hi": hi,
        "approval_rids": approval_rids,
    }
    if covers_subject is not None:
        rec["covers_subject"] = covers_subject
    return sign(rec, ISSUER)


@dataclass
class ScenarioWorld:
    bundle: TrustBundle
    region: str = REGION
    eval_at: int = T_EVAL
    new_cred_rid: str = "cred-neo-new"
    old_cred_rids: tuple[str, str] = ("cred-old-oli", "cred-old-sub-sam")
    revocation_batch: list[dict[str, Any]] = field(default_factory=list)
    change_batch: list[dict[str, Any]] = field(default_factory=list)
    late_batches: list[list[dict[str, Any]]] = field(default_factory=list)

    def all_records(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        out.extend(self.revocation_batch)
        out.extend(self.change_batch)
        for batch in self.late_batches:
            out.extend(batch)
        return out

    def record_map(self) -> dict[str, dict[str, Any]]:
        return {r["rid"]: r for r in self.all_records()}


def build_flagship() -> ScenarioWorld:
    bundle = make_bundle()

    # —— 权限代 1 的两条代理边（旧） ——
    da1 = _delegation("del-a-e1", ROOT_A, ALICE, EPOCH_OLD)
    db1 = _delegation("del-b-e1", ROOT_B, BOB, EPOCH_OLD)

    # —— 权限代 2 的两条代理边（新） ——
    da2 = _delegation("del-a-e2", ROOT_A, ALICE, EPOCH_NEW, lo=10, hi=40)
    db2 = _delegation("del-b-e2", ROOT_B, BOB, EPOCH_NEW, lo=10, hi=40)

    # 撤销记录：先提交，把区域权限代从 1 栅栏到 2
    revocation = {
        "rid": "rev-cn-east-gen2",
        "kind": "revocation",
        "region": REGION,
        "epoch": EPOCH_NEW,
        "at": 11,
        "reason": "rotation: revoke old-post and outstanding substitute",
        "target_rids": ["cred-old-oli", "cred-old-sub-sam"],
    }

    # 新岗持有人 neo 的两条独立批准（gen2）
    ap_neo_a = _approval("ap-neo-a", ALICE, ROOT_A, EPOCH_NEW, lo=10, hi=30)
    ap_neo_b = _approval("ap-neo-b", BOB, ROOT_B, EPOCH_NEW, lo=10, hi=30)
    cred_new = _credential(
        "cred-neo-new",
        "new_post",
        "neo",
        EPOCH_NEW,
        12,
        22,
        ["ap-neo-a", "ap-neo-b"],
    )
    change = {
        "rid": "change-oli-to-neo",
        "kind": "shift_change",
        "region": REGION,
        "epoch": EPOCH_NEW,
        "at": 12,
        "from_subject": "old_oli",
        "to_subject": "neo",
        "new_credential_rid": cred_new["rid"],
        "result": "committed",
    }
    # change 放第一批首条，使幂等元数据指向它
    change_batch = [change, da2, db2, ap_neo_a, ap_neo_b, cred_new]

    # —— 晚到的旧凭证 1：旧岗 old_oli，gen1，时间区间在评估时刻仍有效 ——
    ap_old_a = _approval("ap-old-a", ALICE, ROOT_A, EPOCH_OLD, lo=9, hi=21)
    ap_old_b = _approval("ap-old-b", BOB, ROOT_B, EPOCH_OLD, lo=9, hi=21)
    cred_old_post = _credential(
        "cred-old-oli",
        "old_post",
        "old_oli",
        EPOCH_OLD,
        10,
        20,
        ["ap-old-a", "ap-old-b"],
    )
    late_batch_1 = [da1, db1, ap_old_a, ap_old_b, cred_old_post]

    # —— 晚到的旧凭证 2：替班 sub_sam 替 old_oli，gen1 ——
    ap_sub_a = _approval("ap-sub-a", ALICE, ROOT_A, EPOCH_OLD, lo=10, hi=19)
    ap_sub_b = _approval("ap-sub-b", BOB, ROOT_B, EPOCH_OLD, lo=10, hi=19)
    cred_sub = _credential(
        "cred-old-sub-sam",
        "substitute",
        "sub_sam",
        EPOCH_OLD,
        11,
        18,
        ["ap-sub-a", "ap-sub-b"],
        covers_subject="old_oli",
    )
    late_batch_2 = [ap_sub_a, ap_sub_b, cred_sub]

    return ScenarioWorld(
        bundle=bundle,
        revocation_batch=[revocation],
        change_batch=change_batch,
        late_batches=[late_batch_1, late_batch_2],
    )


@dataclass
class AttackWorld:
    name: str
    bundle: TrustBundle
    records: list[dict[str, Any]]
    cred_rid: str
    expected_code: str
    expected_detail_prefix: str
    region: str = REGION
    epoch: int = EPOCH_NEW
    at: int = T_EVAL

    def record_map(self) -> dict[str, dict[str, Any]]:
        return {r["rid"]: r for r in self.records}


def build_shared_control_world() -> AttackWorld:
    """两名批准人连到不同批准根，但共享控制根 ctrl-shared。"""
    bundle = make_bundle()
    da = _delegation("del-sc-a", ROOT_A, "carol", EPOCH_NEW)
    db = _delegation("del-sc-b", ROOT_B, "dave", EPOCH_NEW)
    apa = _approval("ap-sc-a", "carol", ROOT_A, EPOCH_NEW)
    apb = _approval("ap-sc-b", "dave", ROOT_B, EPOCH_NEW)
    cred = _credential(
        "cred-shared-control",
        "new_post",
        "sc_subject",
        EPOCH_NEW,
        10,
        30,
        ["ap-sc-a", "ap-sc-b"],
    )
    return AttackWorld(
        name="shared-control-root",
        bundle=bundle,
        records=[da, db, apa, apb, cred],
        cred_rid=cred["rid"],
        expected_code="INSUFFICIENT_INDEPENDENT_ROOTS",
        expected_detail_prefix="SHARED_CONTROL_ROOT:ctrl-shared",
    )


def build_cycle_world() -> AttackWorld:
    """pat ← cy-a ← cy-b ← pat 的循环代理，没有任何路径到可信根。"""
    bundle = make_bundle()
    e1 = _delegation("del-cy-1", "cy-a", "pat", EPOCH_NEW)
    e2 = _delegation("del-cy-2", "cy-b", "cy-a", EPOCH_NEW)
    e3 = _delegation("del-cy-3", "pat", "cy-b", EPOCH_NEW)
    ap = _approval("ap-cy-pat", "pat", ROOT_A, EPOCH_NEW)
    cred = _credential(
        "cred-cycle",
        "new_post",
        "cy_subject",
        EPOCH_NEW,
        10,
        30,
        ["ap-cy-pat"],
    )
    return AttackWorld(
        name="cyclic-proxy",
        bundle=bundle,
        records=[e1, e2, e3, ap, cred],
        cred_rid=cred["rid"],
        expected_code="INSUFFICIENT_INDEPENDENT_ROOTS",
        expected_detail_prefix="CYCLE_PROXY",
    )
