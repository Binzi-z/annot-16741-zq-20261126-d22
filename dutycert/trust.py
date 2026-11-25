"""信任束与“两条独立批准根”判定。

两个关键反例在这里被显式封死：

1. ``SHARED_CONTROL_ROOT``：两名批准人也许能连到两个不同的“批准根”，
   但他们在身份控制面同属一个控制根（同一账号/域管控），不算两条独立根。
2. ``CYCLE_PROXY``：代理/委托边构成环（A 代理 B、B 代理 A），沿授权方向
   永远走不到可信根；环不能制造出新的根。寻路只接受无重复节点的简单路径。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from . import signing

# 拒绝细节（稳定字符串，证书搜索需要按它精确匹配）
SHARED_CONTROL_ROOT = "SHARED_CONTROL_ROOT"
CYCLE_PROXY = "CYCLE_PROXY"
SAME_APPROVAL_ROOT = "SAME_APPROVAL_ROOT"
NEED_TWO = "NEED_TWO_INDEPENDENT_ROOTS"


@dataclass(frozen=True)
class TrustBundle:
    """本地模拟信任上下文（相当于真实系统里的根证书库 + 身份管控映射）。"""

    trusted_roots: frozenset[str]
    control_root_of: Mapping[str, str]
    head_key: bytes
    required_roots: int = 2
    # 可选的主体模拟签名密钥；缺省时由主体 ID 确定性派生
    sig_keys: Mapping[str, bytes] = field(default_factory=dict)

    def key_for(self, principal: str) -> bytes:
        return self.sig_keys.get(principal, signing.simulate_key(principal))

    def control_root(self, principal: str) -> str:
        # 未登记主体视为处在独立的“未托管”控制根下；攻击用主体都会显式登记
        return self.control_root_of.get(principal, f"unmanaged::{principal}")


@dataclass(frozen=True)
class Support:
    """一条已经成立的批准支持：某批准人经无环代理链到达某个可信批准根。"""

    approval_rid: str
    approver: str
    root: str
    control_root: str
    path_rids: tuple[str, ...]

    def independence_key(self) -> tuple[str, str, str]:
        return self.root, self.control_root, self.approver


def valid_delegation_edge(
    edge: dict[str, Any],
    bundle: TrustBundle,
    *,
    region: str,
    epoch: int,
    at: int,
) -> bool:
    """校验一条代理边：签名真实、区域/权限代绑定一致、半开区间当时有效。"""
    if edge.get("kind") != "delegation":
        return False
    signer = edge.get("from_principal")
    if not signer or not signing.verify_record_mac(edge, bundle.key_for(signer)):
        return False
    if edge.get("region") != region:
        return False
    if edge.get("epoch") != epoch:
        return False
    lo, hi = edge.get("lo"), edge.get("hi")
    if not isinstance(lo, int) or not isinstance(hi, int) or not (lo <= at < hi):
        return False
    return True


def find_root_paths(
    approver: str,
    delegation_records: list[dict[str, Any]],
    bundle: TrustBundle,
    *,
    region: str,
    epoch: int,
    at: int,
) -> tuple[list[tuple[str, tuple[str, ...]]], bool]:
    """从批准人逆向追溯授权授予者，寻找通往可信根的无环路径。

    返回 ``(paths, cycle_seen)``，其中 paths 的每项是
    ``(root_id, edge_rid 元组)``。只要搜索中撞到“当前路径上已出现的节点”，
    就标记 ``cycle_seen=True`` 且绝不沿该环继续——环不产生授权。
    """
    incoming: dict[str, list[dict[str, Any]]] = {}
    for edge in delegation_records:
        if valid_delegation_edge(
            edge, bundle, region=region, epoch=epoch, at=at
        ):
            incoming.setdefault(edge["to_principal"], []).append(edge)

    paths: list[tuple[str, tuple[str, ...]]] = []
    cycle_seen = False

    def dfs(node: str, node_path: list[str], edge_path: list[str]) -> None:
        nonlocal cycle_seen
        if node in bundle.trusted_roots:
            paths.append((node, tuple(edge_path)))
            return
        for edge in incoming.get(node, ()):  # 谁把权力授予了当前 node
            grantor = edge["from_principal"]
            if grantor in node_path:
                # 代理环：拒绝沿环扩展，只记录“确实见到环”
                cycle_seen = True
                continue
            dfs(grantor, node_path + [grantor], edge_path + [edge["rid"]])

    dfs(approver, [approver], [])
    # 稳定顺序，便于确定性报告
    paths.sort(key=lambda p: (p[0], p[1]))
    return paths, cycle_seen


def evaluate_approval(
    approval: dict[str, Any],
    records: Mapping[str, dict[str, Any]],
    bundle: TrustBundle,
    *,
    region: str,
    epoch: int,
    at: int,
) -> tuple[Support | None, str | None, bool]:
    """评估单条批准记录。

    返回 ``(support, failure_detail, cycle_seen)``。
    """
    approver = approval.get("approver", "?")
    if not signing.verify_record_mac(approval, bundle.key_for(approver)):
        return None, "BAD_SIGNATURE", False
    if approval.get("region") != region:
        return None, "APPROVAL_REGION_MISMATCH", False
    if approval.get("epoch") != epoch:
        return None, "APPROVAL_EPOCH_MISMATCH", False
    alo, ahi = approval.get("lo"), approval.get("hi")
    if not (isinstance(alo, int) and isinstance(ahi, int) and alo <= at < ahi):
        return None, "APPROVAL_TIME_INVALID", False

    delegations = [r for r in records.values() if r.get("kind") == "delegation"]
    paths, cycle_seen = find_root_paths(
        approver,
        delegations,
        bundle,
        region=region,
        epoch=epoch,
        at=at,
    )
    claimed_root = approval.get("root")
    usable = [p for p in paths if claimed_root is None or p[0] == claimed_root]
    if not usable:
        if cycle_seen:
            return None, CYCLE_PROXY, True
        return None, "NO_TRUSTED_ROOT_PATH", cycle_seen

    root, path_rids = usable[0]  # 已排序，取字典序最短/最稳定的一条
    support = Support(
        approval_rid=approval["rid"],
        approver=approver,
        root=root,
        control_root=bundle.control_root(approver),
        path_rids=path_rids,
    )
    return support, None, cycle_seen


def find_independent_pair(
    supports: list[Support], bundle: TrustBundle
) -> tuple[Support, Support] | None:
    """在已成立的支持中寻找两条“人、批准根、控制根”均不同的配对。"""
    for i, a in enumerate(supports):
        for b in supports[i + 1 :]:
            if a.approver == b.approver:
                continue
            if a.root == b.root:
                continue
            if a.control_root == b.control_root:
                continue  # 共享控制根：不算独立
            return a, b
    return None


def diagnose_root_failure(
    supports: list[Support],
    cycle_seen_any: bool,
) -> str:
    """当凑不齐两条独立根时，给出最具体、可构造验证的拒绝细节。"""
    # 1) 已经能连到两个不同批准根，却栽在共享控制根上 —— 题目点名的攻击
    ctrl_groups: dict[str, list[Support]] = {}
    for s in supports:
        ctrl_groups.setdefault(s.control_root, []).append(s)
    for ctrl, group in sorted(ctrl_groups.items()):
        roots = {s.root for s in group}
        approvers = {s.approver for s in group}
        if len(roots) >= 2 and len(approvers) >= 2:
            return f"{SHARED_CONTROL_ROOT}:{ctrl}"

    # 2) 两条支持其实落到同一个批准根
    root_groups: dict[str, list[Support]] = {}
    for s in supports:
        root_groups.setdefault(s.root, []).append(s)
    for root, group in sorted(root_groups.items()):
        if len({s.approver for s in group}) >= 2:
            return f"{SAME_APPROVAL_ROOT}:{root}"

    # 3) 代理环
    if cycle_seen_any:
        return CYCLE_PROXY

    # 4) 笼统的数量不足
    roots = sorted({s.root for s in supports})
    return f"{NEED_TWO}:valid_roots={','.join(roots) or 'none'}"
