"""模拟签名 / MAC（标准库 hmac + sha256）。

题目明确“无真实账号”，因此这里不使用任何真实密钥体系或操作系统账号，
只用 HMAC-SHA256 模拟“批准人签名”和“可信锚点头部 MAC”。所有模拟密钥
都由主体 ID 确定性派生，便于测试与重放；它提供篡改可检出性，但不是
生产级密钥管理。
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

# 仅用于模拟的域分隔前缀，避免不同用途的 MAC 被复用
_SIG_DOMAIN = b"dutycert-sig-v1:"
_HEAD_DOMAIN = b"dutycert-head-v1:"
_FRAME_DOMAIN = b"dutycert-frame-v1:"


def canonical_bytes(obj: Any) -> bytes:
    """规范化 JSON 字节：键排序、无空白、UTF-8、不转义非 ASCII。"""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def simulate_key(principal: str) -> bytes:
    """从主体 ID 确定性派生模拟密钥（绝非真实凭据）。"""
    return hashlib.sha256(b"dutycert-sim-key-v1:" + principal.encode("utf-8")).digest()


def sign_value(payload: Any, key: bytes, domain: bytes = _SIG_DOMAIN) -> str:
    return hmac.new(key, domain + canonical_bytes(payload), hashlib.sha256).hexdigest()


def verify_value(
    payload: Any, mac_hex: str | None, key: bytes, domain: bytes = _SIG_DOMAIN
) -> bool:
    if not mac_hex:
        return False
    expected = sign_value(payload, key, domain)
    return hmac.compare_digest(expected, mac_hex)


def body_without_mac(record: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in record.items() if k != "mac"}


def sign_record(record: dict[str, Any], signer_key: bytes) -> dict[str, Any]:
    """返回带 ``mac`` 字段的记录副本（MAC 覆盖除 mac 外的全部字段）。"""
    out = dict(record)
    out["mac"] = sign_value(body_without_mac(out), signer_key)
    return out


def verify_record_mac(record: dict[str, Any], signer_key: bytes) -> bool:
    return verify_value(
        body_without_mac(record), record.get("mac"), signer_key, _SIG_DOMAIN
    )


def head_mac(payload: Any, head_key: bytes) -> str:
    return sign_value(payload, head_key, _HEAD_DOMAIN)


def verify_head_mac(payload: Any, mac_hex: str | None, head_key: bytes) -> bool:
    return verify_value(payload, mac_hex, head_key, _HEAD_DOMAIN)


def frame_digest(payload: Any) -> str:
    """WAL 帧 / 记录内容的非密钥 sha256，用于撕尾与损坏检测。"""
    return hashlib.sha256(_FRAME_DOMAIN + canonical_bytes(payload)).hexdigest()
