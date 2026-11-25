"""半开有效区间。

旧岗凭证、新岗凭证、替班凭证以及代理授权都使用统一的半开整数区间
``[lo, hi)``：在 ``t == hi`` 时立即失效，在 ``t == lo`` 时开始生效。
半开区间保证换岗时刻不会出现“新旧同时有效”或“边界两不管”的歧义。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, order=True)
class Interval:
    """不可变半开区间 ``[lo, hi)``，时间轴为离散小整数。"""

    lo: int
    hi: int

    def __post_init__(self) -> None:
        if not isinstance(self.lo, int) or not isinstance(self.hi, int):
            raise TypeError("区间端点必须是整数")
        if self.lo > self.hi:
            raise ValueError(f"非法区间 [{self.lo}, {self.hi})：lo > hi")

    def contains(self, t: int) -> bool:
        """半开判定：``lo <= t < hi``。"""
        return self.lo <= t < self.hi

    @property
    def empty(self) -> bool:
        return self.lo == self.hi

    def overlaps(self, other: "Interval") -> bool:
        """两个半开区间是否存在公共整数时刻（端点相接不算重叠）。"""
        return max(self.lo, other.lo) < min(self.hi, other.hi)

    def as_tuple(self) -> tuple[int, int]:
        return self.lo, self.hi

    def __str__(self) -> str:  # 便于中文报告
        return f"[{self.lo},{self.hi})"


def contains_any(intervals: Iterable[Interval], t: int) -> bool:
    return any(iv.contains(t) for iv in intervals)


def boundary_probe(iv: Interval) -> list[tuple[int, bool]]:
    """返回覆盖半开边界的一组探测时刻及期望有效性。

    用于穷举：``lo-1`` 无效、``lo`` 有效、``hi-1`` 有效、``hi`` 无效。
    空区间单独处理。
    """
    if iv.empty:
        return [(iv.lo - 1, False), (iv.lo, False), (iv.lo + 1, False)]
    return [
        (iv.lo - 1, False),
        (iv.lo, True),
        (iv.hi - 1, True),
        (iv.hi, False),
        (iv.hi + 1, False),
    ]
