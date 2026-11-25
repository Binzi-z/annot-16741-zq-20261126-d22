"""最短批准 / 拒绝证书及其独立验证。

思路
----
- 恢复后的全部落盘记录构成“完整世界”，先在其上跑出权威判定 ``full``。
- 可信头部（各区域当前权限代 + last_seq）用模拟头密钥做 MAC，作为恒定锚点。
- 证据记录从候选池里按基数 ``k=0,1,2,...`` 枚举子集；第一个能被
  :func:`verify_certificate` 验证出与权威判定一致结果的子集，就是
  **基数最短证书**。因为所有更小的子集都已先行枚举且失败，最小性是枚举
  保证的，而不是口头声明。

匹配规则刻意不对称，防止“空证书拒绝一切”：
- 批准证书：子集验证结果必须是 ``allowed=True``；
- 拒绝证书：必须 ``allowed=False`` 且原因码与细节和权威判定**完全一致**
  （例如 ``EPOCH_FENCED`` 或 ``INSUFFICIENT...[SHARED_CONTROL_ROOT:x]``），
  因此缺少关键证据、换一个拒绝理由都不算数。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

from . import signing
from .engine import Verdict, authorize_credential
from .store import RecoveredState
from .trust import TrustBundle

ANCHOR_KIND = "signed_head_anchor"


def make_anchor(state: RecoveredState, bundle: TrustBundle) -> dict[str, Any]:
    payload = {
        "kind": ANCHOR_KIND,
        "last_seq": state.last_seq,
        "region_epochs": dict(sorted(state.region_epochs.items())),
    }
    return {"payload": payload, "mac": signing.head_mac(payload, bundle.head_key)}


@dataclass
class Certificate:
    query: dict[str, Any]
    anchor: dict[str, Any]
    records: list[dict[str, Any]]
    claimed: dict[str, Any]
    witness_count: int
    irredundant: bool = True

    @property
    def total_objects(self) -> int:
        """证据记录数 + 1 个恒定头部锚点。"""
        return self.witness_count + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "anchor": self.anchor,
            "records": self.records,
            "claimed": self.claimed,
            "witness_count": self.witness_count,
            "total_objects": self.total_objects,
            "irredundant": self.irredundant,
        }

    def brief(self) -> str:
        rids = [r.get("rid") for r in self.records]
        sign = "批准" if self.claimed["allowed"] else "拒绝"
        reason = self.claimed["code"]
        if self.claimed.get("detail"):
            reason += f"[{self.claimed['detail']}]"
        return (
            f"最短{sign}证书: 证据 {self.witness_count} 条 {rids}"
            f" (+头部锚点1, 共{self.total_objects}对象) -> {reason}"
        )


def _epoch_from_anchor(anchor: dict[str, Any], region: str) -> int:
    payload = anchor.get("payload", {})
    return int(payload.get("region_epochs", {}).get(region, 0))


def verify_certificate(
    cert: Certificate | dict[str, Any], bundle: TrustBundle
) -> Verdict:
    """仅用证书内嵌的头部锚点 + 证据记录重放判定（独立验证入口）。"""
    if isinstance(cert, dict):
        query = cert["query"]
        anchor = cert["anchor"]
        records_list = cert["records"]
    else:
        query = cert.query
        anchor = cert.anchor
        records_list = cert.records

    payload = anchor.get("payload", {})
    if not signing.verify_head_mac(
        payload, anchor.get("mac"), bundle.head_key
    ) or payload.get("kind") != ANCHOR_KIND:
        return Verdict(False, "BAD_ANCHOR_MAC")

    records = {r["rid"]: r for r in records_list if "rid" in r}
    region = query["region"]
    epoch = _epoch_from_anchor(anchor, region)
    cred = records.get(query["cred_rid"])
    return authorize_credential(
        cred,
        records,
        bundle,
        region=region,
        current_epoch=epoch,
        at=int(query["at"]),
        acting_for=query.get("acting_for"),
    )


def _matches(full: Verdict, sub: Verdict) -> bool:
    if full.allowed:
        return sub.allowed
    return (not sub.allowed) and sub.code == full.code and sub.detail == full.detail


def _candidate_pool(
    cred: dict[str, Any], state: RecoveredState
) -> list[str]:
    pool: set[str] = {cred["rid"]}
    for arid in cred.get("approval_rids", []):
        if arid in state.by_rid:
            pool.add(arid)
    # 图寻路可能用到任意代理边；场景很小，全部纳入候选以保证真正最短
    for rid, rec in state.by_rid.items():
        if rec.get("kind") == "delegation":
            pool.add(rid)
    return sorted(pool)


def _irredundant(
    combo: tuple[str, ...],
    state: RecoveredState,
    bundle: TrustBundle,
    query: dict[str, Any],
    anchor: dict[str, Any],
    full: Verdict,
) -> bool:
    for drop in combo:
        reduced = {
            rid: state.by_rid[rid] for rid in combo if rid != drop
        }
        v = authorize_credential(
            reduced.get(query["cred_rid"]),
            reduced,
            bundle,
            region=query["region"],
            current_epoch=_epoch_from_anchor(anchor, query["region"]),
            at=int(query["at"]),
            acting_for=query.get("acting_for"),
        )
        if _matches(full, v):
            return False  # 删掉 drop 后仍成立 -> 存在冗余
    return True


def shortest_certificate(
    state: RecoveredState,
    bundle: TrustBundle,
    *,
    cred_rid: str,
    region: str,
    at: int,
    acting_for: str | None = None,
) -> Certificate:
    """在恢复状态上搜索给定凭证当前结论的最短证书。"""
    if cred_rid not in state.by_rid:
        raise KeyError(f"落盘记录中没有凭证 {cred_rid}")
    cred = state.by_rid[cred_rid]
    epoch = state.current_epoch(region)
    query = {
        "cred_rid": cred_rid,
        "region": region,
        "at": at,
        "acting_for": acting_for,
    }
    anchor = make_anchor(state, bundle)

    full = authorize_credential(
        cred,
        state.by_rid,
        bundle,
        region=region,
        current_epoch=epoch,
        at=at,
        acting_for=acting_for,
    )

    pool = _candidate_pool(cred, state)
    for k in range(0, len(pool) + 1):
        for combo in combinations(pool, k):
            subset = {rid: state.by_rid[rid] for rid in combo}
            verdict = authorize_credential(
                subset.get(cred_rid),
                subset,
                bundle,
                region=region,
                current_epoch=epoch,
                at=at,
                acting_for=acting_for,
            )
            if not _matches(full, verdict):
                continue
            irredundant = (
                True
                if k == 0
                else _irredundant(
                    combo, state, bundle, query, anchor, full
                )
            )
            cert = Certificate(
                query=query,
                anchor=anchor,
                records=[state.by_rid[rid] for rid in combo],
                claimed={
                    "allowed": full.allowed,
                    "code": full.code,
                    "detail": full.detail,
                    "subject": full.subject,
                    "epoch": epoch,
                },
                witness_count=k,
                irredundant=irredundant,
            )
            # 自检：独立验证器必须得到同一结论
            check = verify_certificate(cert, bundle)
            if not _matches(full, check):
                raise AssertionError(
                    "证书自检失败: "
                    f"full={full.reason_key} verify={check.reason_key}"
                )
            return cert

    # 理论不可达：完整世界本身一定匹配
    raise AssertionError("未能构造证书（完整世界应当可行）")
