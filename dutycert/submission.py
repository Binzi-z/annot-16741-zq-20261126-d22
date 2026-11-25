"""提交的区域与权限代绑定（乐观栅栏）。

- 数据面提交（换岗、凭证生效请求）必须显式携带 ``region`` 与 ``epoch``，
  且 ``epoch`` 必须等于落盘头部中该区域的当前权限代，否则以
  ``STALE_GENERATION`` 拒绝——撤销一旦把权限代推进，所有旧代提交/凭证都
  被栅栏挡下。
- 载荷中的证据记录也必须与提交同区域、同权限代，防止夹带跨区/跨代材料。
- 撤销是控制面操作：它把区域推进到一个更大的新代（单调），不做“等于当前”
  校验，但禁止回退。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

STALE_GENERATION = "STALE_GENERATION"
REGION_BINDING_MISMATCH = "REGION_BINDING_MISMATCH"
PAYLOAD_BINDING_MISMATCH = "PAYLOAD_BINDING_MISMATCH"
EPOCH_ROLLBACK = "EPOCH_ROLLBACK"


class BindingRejected(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Submission:
    request_id: str
    region: str
    epoch: int
    records: tuple[dict[str, Any], ...]
    kind: str = "shift_change"


def check_data_plane_binding(
    region: str, bound_epoch: int, region_epochs: Mapping[str, int]
) -> int:
    current = int(region_epochs.get(region, 0))
    if bound_epoch != current:
        raise BindingRejected(
            STALE_GENERATION,
            f"region={region} bound_gen={bound_epoch} current_gen={current}",
        )
    return current


def validate_payload_binding(sub: Submission) -> None:
    for rec in sub.records:
        r = rec.get("region")
        e = rec.get("epoch")
        # 有些纯结构记录可能不带区域/代；但凡带了就必须与提交一致
        if r is not None and r != sub.region:
            raise BindingRejected(
                PAYLOAD_BINDING_MISMATCH,
                f"rid={rec.get('rid')} region={r} submission={sub.region}",
            )
        if e is not None and int(e) != sub.epoch and rec.get("kind") != "revocation":
            raise BindingRejected(
                PAYLOAD_BINDING_MISMATCH,
                f"rid={rec.get('rid')} gen={e} submission_gen={sub.epoch}",
            )


def submit_data_plane(store: Any, sub: Submission, *, lose_receipt: bool = False):
    """校验绑定后幂等提交。store 需具备 region_epochs 与 commit_batch。"""
    check_data_plane_binding(sub.region, sub.epoch, store.region_epochs)
    validate_payload_binding(sub)
    return store.commit_batch(
        list(sub.records),
        txid=f"tx-{sub.request_id}",
        request_id=sub.request_id,
        lose_receipt=lose_receipt,
    )


def commit_revocation(store: Any, rec: dict[str, Any], *, request_id: str) -> Any:
    new_epoch = int(rec["epoch"])
    current = int(store.region_epochs.get(rec["region"], 0))
    if new_epoch <= current:
        raise BindingRejected(
            EPOCH_ROLLBACK,
            f"region={rec['region']} new_gen={new_epoch} current={current}",
        )
    return store.commit_batch([rec], txid=f"tx-{request_id}", request_id=request_id)
