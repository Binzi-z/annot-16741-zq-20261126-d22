"""dutycert —— 值班资格的原子换岗与最短证明（仅用 Python 3.12 标准库）。

模块划分
--------
- intervals  : 半开有效区间 [lo, hi) 与小整数时间轴
- trust      : 模拟信任束、控制根、代理图（无环）、两条独立批准根判定
- engine     : 区域 + 权限代绑定的授权判定（纯函数核心）
- signing    : HMAC-SHA256 模拟签名 / 锚点 MAC（无真实账号）
- store      : 落盘 WAL、COMMIT 标记、fsync、原子 head、崩溃恢复、幂等
- cert       : 从落盘记录搜索并验证“最短批准/拒绝证书”
- scenario   : 两个工作线程 + Barrier 的旗舰复现场景
- exhaustive : 小整数时间轴上的短交错穷举模型检查
- bench      : 60000 条多区域合成记录的实际读取范围 vs 全量核验
- cli        : 一键入口
"""

__version__ = "1.0.0"

# 旗舰基准固定规模：六万条多区域合成记录
BENCH_RECORDS = 60_000
