"""落盘 WAL、原子头部与崩溃恢复（仅标准库，原生 Windows 可运行）。

持久化设计
----------
- ``wal.jsonl``：追加写。每条记录一个 ``d`` 数据帧，事务末尾写一个 ``c``
  COMMIT 帧；数据帧带 sha256。只有见到校验通过的 COMMIT 帧，事务才算提交。
- ``request_id`` / ``txid`` 放在**帧层**，绝不回写记录体，因此不会破坏
  记录自身的 HMAC 签名。
- 提交时 ``flush + os.fsync``，保证“撤销先提交”和“换岗已提交”确实落盘。
- ``head.json``：用“临时文件 + os.replace”原子更新的可信头部，内含各区域
  当前权限代，并带 HMAC（模拟可信锚点）。
- 回执丢失 / 进程“重启”后，重新扫描 WAL：已提交事务逐条重放，撕坏的尾部
  （半行 JSON、sha 不符、有数据帧无 COMMIT）整体丢弃，并可截断修复。
- ``request_id`` 幂等索引：同一个换岗请求重试绝不会产生第二次效果。
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import signing

WAL_NAME = "wal.jsonl"
HEAD_NAME = "head.json"

# 只有这些权威记录允许推进“当前权限代”，晚到的旧凭证不在其列
_EPOCH_KINDS = frozenset({"genesis", "epoch_bump", "revocation", "shift_change"})


class ReceiptLost(Exception):
    """模拟“服务端已落盘、但成功回执在返回客户端途中丢失”。

    异常里虽然携带服务端回执（便于测试核对落盘事实），但复现场景中的
    客户端线程只把自己标记为 AMBIGUOUS，绝不读取它来判定成功；真相只能
    等恢复后从磁盘与 ``request_id`` 得到。
    """

    def __init__(self, receipt: "Receipt") -> None:
        super().__init__("success receipt lost after durable commit")
        self.server_receipt = receipt


@dataclass(frozen=True)
class Receipt:
    txid: str
    last_seq: int
    rids: tuple[str, ...]
    request_id: str | None
    duplicated: bool = False


@dataclass
class RecoveredState:
    """重放 WAL 后得到的内存真相。"""

    records: list[dict[str, Any]] = field(default_factory=list)
    by_rid: dict[str, dict[str, Any]] = field(default_factory=dict)
    region_epochs: dict[str, int] = field(default_factory=dict)
    request_index: dict[str, dict[str, Any]] = field(default_factory=dict)
    request_meta: dict[str, dict[str, str]] = field(default_factory=dict)
    last_seq: int = 0
    committed_txs: list[str] = field(default_factory=list)
    torn_bytes: int = 0
    wal_path: Path | None = None
    head_payload: dict[str, Any] | None = None
    head_mac: str | None = None

    def current_epoch(self, region: str, default: int = 0) -> int:
        return self.region_epochs.get(region, default)


def _commit_digest(txid: str, rids: list[str]) -> str:
    return signing.frame_digest({"tx": txid, "rids": rids})


def scan_wal(
    wal_path: Path,
) -> tuple[list[dict[str, Any]], int, int, list[str], dict[str, dict[str, str]]]:
    """扫描 WAL。

    返回 ``(accepted_data_frames, last_seq, committed_end_offset,
    committed_txids, request_meta)``。任何撕坏 / 未提交的尾部都不会进入结果。
    每个 accepted data frame 是原始 ``d`` 帧（含 ``rec/tx/req``）。
    """
    request_meta: dict[str, dict[str, str]] = {}
    if not wal_path.exists():
        return [], 0, 0, [], request_meta

    data = wal_path.read_bytes()
    accepted_frames: list[dict[str, Any]] = []
    committed_txs: list[str] = []
    last_seq = 0
    committed_end = 0

    offset = 0
    pending: list[dict[str, Any]] = []
    pending_tx: str | None = None
    pending_rids: list[str] = []

    while offset < len(data):
        nl = data.find(b"\n", offset)
        if nl == -1:
            break  # 没有结尾换行：写到一半的帧
        line = data[offset:nl]
        line_end = nl + 1
        try:
            frame = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            break  # 半行 / 坏 JSON，尾部从这里起全部不可信

        ftype = frame.get("t")
        if ftype == "d":
            rec = frame.get("rec")
            if not isinstance(rec, dict) or frame.get("sha") != signing.frame_digest(rec):
                break  # 内容与 sha 不符（撕裂或篡改）
            if pending_tx is None:
                pending_tx = frame.get("tx")
            pending.append(frame)
            pending_rids.append(frame.get("rid"))
            last_seq = max(last_seq, int(frame.get("seq", 0)))
            offset = line_end
            continue

        if ftype == "c":
            rids = frame.get("rids") or []
            txid = frame.get("tx")
            ok = (
                txid == pending_tx
                and int(frame.get("n", -1)) == len(pending)
                and list(rids) == pending_rids
                and frame.get("sha") == _commit_digest(txid, list(rids))
            )
            if not ok:
                break  # COMMIT 帧自身校验失败：整笔不可信
            for fr in pending:
                accepted_frames.append(fr)
                req = fr.get("req")
                if req and req not in request_meta:
                    request_meta[req] = {
                        "txid": fr.get("tx"),
                        "rid": fr.get("rid"),
                    }
            committed_txs.append(txid)
            committed_end = line_end
            pending, pending_rids, pending_tx = [], [], None
            offset = line_end
            continue

        # 未知帧类型：保守停止
        break

    return accepted_frames, last_seq, committed_end, committed_txs, request_meta


class DurableStore:
    """带锁的追加型持久化存储；多线程可共享同一实例提交。"""

    def __init__(self, directory: str | os.PathLike[str], head_key: bytes) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.wal_path = self.dir / WAL_NAME
        self.head_path = self.dir / HEAD_NAME
        self.head_key = head_key
        self._lock = threading.RLock()
        self.records: list[dict[str, Any]] = []
        self.by_rid: dict[str, dict[str, Any]] = {}
        self.region_epochs: dict[str, int] = {}
        self.request_index: dict[str, dict[str, Any]] = {}
        self.request_meta: dict[str, dict[str, str]] = {}
        self.committed_txs: list[str] = []
        self.last_seq = 0
        self._reload_from_disk(repair=False)

    # ---------- 恢复 / 重放 ----------
    def _absorb_record(self, rec: dict[str, Any]) -> None:
        rid = rec.get("rid")
        if rid is not None and rid not in self.by_rid:
            self.by_rid[rid] = rec
            self.records.append(rec)
        if rec.get("kind") in _EPOCH_KINDS and rec.get("region") and "epoch" in rec:
            region = rec["region"]
            epoch = int(rec["epoch"])
            self.region_epochs[region] = max(
                epoch, self.region_epochs.get(region, 0)
            )

    def _reload_from_disk(self, repair: bool) -> RecoveredState:
        frames, last_seq, committed_end, txs, req_meta = scan_wal(self.wal_path)
        self.records = []
        self.by_rid = {}
        self.region_epochs = {}
        self.request_index = {}
        self.request_meta = dict(req_meta)
        for fr in frames:
            rec = fr["rec"]
            self._absorb_record(rec)
            req = fr.get("req")
            if req and req not in self.request_index:
                self.request_index[req] = rec
        self.last_seq = last_seq
        self.committed_txs = txs

        torn_bytes = 0
        if self.wal_path.exists():
            size = self.wal_path.stat().st_size
            torn_bytes = size - committed_end
            if repair and torn_bytes > 0:
                with open(self.wal_path, "r+b") as f:
                    f.truncate(committed_end)
                    f.flush()
                    os.fsync(f.fileno())

        payload = self._head_payload()
        self._write_head_atomic(payload)
        return self.recovered_state(torn_bytes=torn_bytes)

    @classmethod
    def reopen(
        cls, directory: str | os.PathLike[str], head_key: bytes, *, repair: bool = True
    ) -> "DurableStore":
        """模拟进程重启：重新扫描磁盘，并截断修复撕坏的尾部。"""
        store = cls.__new__(cls)
        store.dir = Path(directory)
        store.wal_path = store.dir / WAL_NAME
        store.head_path = store.dir / HEAD_NAME
        store.head_key = head_key
        store._lock = threading.RLock()
        store.records = []
        store.by_rid = {}
        store.region_epochs = {}
        store.request_index = {}
        store.request_meta = {}
        store.committed_txs = []
        store.last_seq = 0
        store._reload_from_disk(repair=repair)
        return store

    def recover(self, *, repair: bool = False) -> RecoveredState:
        return self._reload_from_disk(repair=repair)

    def recovered_state(self, *, torn_bytes: int = 0) -> RecoveredState:
        payload = self._head_payload()
        return RecoveredState(
            records=list(self.records),
            by_rid=dict(self.by_rid),
            region_epochs=dict(self.region_epochs),
            request_index=dict(self.request_index),
            request_meta=dict(self.request_meta),
            last_seq=self.last_seq,
            committed_txs=list(self.committed_txs),
            torn_bytes=torn_bytes,
            wal_path=self.wal_path,
            head_payload=payload,
            head_mac=signing.head_mac(payload, self.head_key),
        )

    # ---------- 头部 ----------
    def _head_payload(self) -> dict[str, Any]:
        return {
            "last_seq": self.last_seq,
            "region_epochs": dict(sorted(self.region_epochs.items())),
            "committed_txs": list(self.committed_txs),
        }

    def _write_head_atomic(self, payload: dict[str, Any]) -> None:
        envelope = {
            "payload": payload,
            "mac": signing.head_mac(payload, self.head_key),
        }
        tmp = self.head_path.with_name(HEAD_NAME + ".tmp")
        data = json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.head_path)  # Windows 上也能原子替换已存在文件

    def read_verified_head(self) -> dict[str, Any] | None:
        """读取并校验落盘 head.json 的 MAC。"""
        if not self.head_path.exists():
            return None
        envelope = json.loads(self.head_path.read_text(encoding="utf-8"))
        payload = envelope.get("payload", {})
        if not signing.verify_head_mac(
            payload, envelope.get("mac"), self.head_key
        ):
            raise ValueError("head.json MAC 校验失败")
        return payload

    # ---------- 提交 ----------
    def commit_batch(
        self,
        records: list[dict[str, Any]],
        *,
        txid: str | None = None,
        request_id: str | None = None,
        lose_receipt: bool = False,
    ) -> Receipt:
        """原子提交一批记录。

        整批数据帧 + 一个 COMMIT 帧一次 fsync；随后原子更新 head。
        若提供已提交过的 ``request_id``，直接返回原回执且不追加任何内容。
        ``lose_receipt=True`` 会在全部落盘后抛出 :class:`ReceiptLost`。
        """
        with self._lock:
            if request_id and request_id in self.request_meta:
                meta = self.request_meta[request_id]
                return Receipt(
                    txid=meta["txid"],
                    last_seq=self.last_seq,
                    rids=(meta["rid"],),
                    request_id=request_id,
                    duplicated=True,
                )

            txid = txid or f"tx-{self.last_seq + 1}"
            rids = [r["rid"] for r in records]
            chunks: list[bytes] = []
            for rec in records:
                self.last_seq += 1
                frame = {
                    "t": "d",
                    "tx": txid,
                    "seq": self.last_seq,
                    "rid": rec["rid"],
                    "req": request_id,
                    "rec": rec,
                    "sha": signing.frame_digest(rec),
                }
                chunks.append(
                    (json.dumps(frame, ensure_ascii=False) + "\n").encode("utf-8")
                )
            commit_frame = {
                "t": "c",
                "tx": txid,
                "n": len(records),
                "rids": rids,
                "sha": _commit_digest(txid, rids),
            }
            chunks.append(
                (json.dumps(commit_frame, ensure_ascii=False) + "\n").encode("utf-8")
            )

            with open(self.wal_path, "ab") as f:
                for chunk in chunks:
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())

            for rec in records:
                self._absorb_record(rec)
            if request_id:
                self.request_meta[request_id] = {
                    "txid": txid,
                    "rid": records[0]["rid"],
                }
                self.request_index.setdefault(request_id, records[0])
            self.committed_txs.append(txid)
            self._write_head_atomic(self._head_payload())

            receipt = Receipt(
                txid=txid,
                last_seq=self.last_seq,
                rids=tuple(rids),
                request_id=request_id,
                duplicated=False,
            )
            if lose_receipt:
                raise ReceiptLost(receipt)
            return receipt

    def append_torn_tail(self, blob: bytes = b'{"t":"d","seq":999,"rec": {') -> None:
        """测试辅助：在 WAL 末尾追加一段没有 COMMIT 的撕裂字节。"""
        with self._lock:
            with open(self.wal_path, "ab") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())

    def append_garbage_line(self) -> None:
        with self._lock:
            with open(self.wal_path, "ab") as f:
                f.write(b"\n{this is not valid json\n")
                f.flush()
                os.fsync(f.fileno())
