"""值班资格授权判定（纯函数核心）。

判定顺序固定，保证证书搜索时“完整世界”和“最小证据子集”能得到同一个
稳定的原因键 ``(code, detail)``：

    记录完整性 → 区域绑定 → 权限代栅栏 → 半开有效期 → 替班范围
              → 两条独立批准根（含共享控制根 / 循环代理诊断）
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from . import signing
from .intervals import Interval
from .trust import (
    TrustBundle,
    diagnose_root_failure,
    evaluate_approval,
    find_independent_pair,
)

# 判定码
OK = "OK"
CREDENTIAL_NOT_FOUND = "CREDENTIAL_NOT_FOUND"
TAMPERED = "TAMPERED"
REGION_MISMATCH = "REGION_MISMATCH"
EPOCH_FENCED = "EPOCH_FENCED"
NOT_YET_VALID = "NOT_YET_VALID"
INTERVAL_EXPIRED = "INTERVAL_EXPIRED"
SUBSTITUTE_SCOPE = "SUBSTITUTE_SCOPE"
INSUFFICIENT_ROOTS = "INSUFFICIENT_INDEPENDENT_ROOTS"


@dataclass
class Verdict:
    allowed: bool
    code: str
    detail: str = ""
    cred_rid: str | None = None
    subject: str | None = None
    region: str | None = None
    epoch: int | None = None
    at: int | None = None
    pair: tuple[Any, Any] | None = None
    supports: list[Any] = field(default_factory=list)

    @property
    def reason_key(self) -> tuple[bool, str, str]:
        return self.allowed, self.code, self.detail

    def short(self) -> str:
        if self.allowed:
            roots = ""
            if self.pair:
                a, b = self.pair
                roots = f" roots=({a.root},{b.root}) ctrl=({a.control_root},{b.control_root})"
            return f"批准 {self.subject} @{self.region}/gen{self.epoch}/t{self.at}{roots}"
        return (
            f"拒绝 {self.subject or self.cred_rid} @{self.region}/gen{self.epoch}/t{self.at}"
            f" -> {self.code}" + (f"[{self.detail}]" if self.detail else "")
        )


def _credential_integrity_ok(cred: dict[str, Any], bundle: TrustBundle) -> bool:
    issuer = cred.get("issuer", "duty-issuer")
    mac = cred.get("mac")
    if mac is None:
        return False
    return signing.verify_record_mac(cred, bundle.key_for(issuer))


def authorize_credential(
    cred: dict[str, Any] | None,
    records: Mapping[str, dict[str, Any]],
    bundle: TrustBundle,
    *,
    region: str,
    current_epoch: int,
    at: int,
    acting_for: str | None = None,
) -> Verdict:
    """对单条凭证做当前资格判定。``current_epoch`` 来自落盘的可信头部。"""
    if cred is None:
        return Verdict(
            False, CREDENTIAL_NOT_FOUND, region=region, epoch=current_epoch, at=at
        )

    rid = cred.get("rid")
    subject = cred.get("subject")
    base = dict(
        cred_rid=rid,
        subject=subject,
        region=region,
        epoch=current_epoch,
        at=at,
    )

    if not _credential_integrity_ok(cred, bundle):
        return Verdict(False, TAMPERED, detail="credential-mac", **base)

    # 1) 区域绑定
    if cred.get("region") != region:
        return Verdict(
            False,
            REGION_MISMATCH,
            detail=f"cred={cred.get('region')} want={region}",
            **base,
        )

    # 2) 权限代栅栏：撤销会推进 current_epoch，旧代凭证立即失效
    if cred.get("epoch") != current_epoch:
        return Verdict(
            False,
            EPOCH_FENCED,
            detail=f"cred_gen={cred.get('epoch')} current_gen={current_epoch}",
            **base,
        )

    # 3) 半开有效期 [lo, hi)
    iv = Interval(cred["lo"], cred["hi"])
    if at < iv.lo:
        return Verdict(False, NOT_YET_VALID, detail=str(iv), **base)
    if at >= iv.hi:
        return Verdict(False, INTERVAL_EXPIRED, detail=str(iv), **base)

    # 4) 替班凭证的覆盖对象范围（若声明，则必须对得上被替的人/岗）
    if cred.get("cred_kind") == "substitute" and cred.get("covers_subject"):
        if acting_for is not None and acting_for != cred["covers_subject"]:
            return Verdict(
                False,
                SUBSTITUTE_SCOPE,
                detail=(
                    f"covers={cred['covers_subject']} acting_for={acting_for}"
                ),
                **base,
            )

    # 5) 两条独立批准根
    supports = []
    cycle_seen_any = False
    for arid in cred.get("approval_rids", []):
        approval = records.get(arid)
        if not approval or approval.get("kind") != "approval":
            continue
        support, failure, cycle_seen = evaluate_approval(
            approval,
            records,
            bundle,
            region=region,
            epoch=current_epoch,
            at=at,
        )
        cycle_seen_any = cycle_seen_any or cycle_seen
        if support is not None:
            supports.append(support)

    pair = find_independent_pair(supports, bundle)
    if pair is not None:
        return Verdict(
            True,
            OK,
            **base,
            pair=pair,
            supports=supports,
        )

    detail = diagnose_root_failure(supports, cycle_seen_any)
    return Verdict(
        False,
        INSUFFICIENT_ROOTS,
        detail=detail,
        **base,
        supports=supports,
    )
