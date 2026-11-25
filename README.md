# 值班资格的原子换岗与证明（dutycert）

内部告警处理的**纯标准库模拟**：原生 Windows + Python 3.12，无真实账号、无第三方依赖。
题面见 [`task/PROMPT.txt`](task/PROMPT.txt)。

一条命令完成单元测试 + 旗舰复现 + 短交错穷举 + 六万条读取范围基准：

```bat
python run.py
```

或只出报告（跳过测试）：

```bat
python run.py --report
python -m dutycert            :: 等价的完整报告
python -m dutycert --quick    :: 小规模基准的快速自检
```

只跑测试：

```bat
python -m unittest discover -s tests -v
```

---

## 1. 题面要求 → 实现位置对照

| 题面要求 | 实现 |
| --- | --- |
| 旧岗 / 新岗 / 替班凭证采用半开有效区间 | `dutycert/intervals.py` 的 `Interval[lo,hi)`；三类凭证见 `world.py`，边界测试 `TestIntervals` / `test_half_open_expiry_at_hi` |
| 两条独立的批准根 | `trust.py::find_independent_pair`，要求人、批准根、**控制根**三者都不同 |
| 不得因两名人员共享控制根而授权 | `trust.py::diagnose_root_failure` → `SHARED_CONTROL_ROOT:<根>`；攻击世界 `build_shared_control_world` |
| 不得因循环代理而授权 | `trust.py::find_root_paths` 只走无重复节点的简单路径，撞环标记 `CYCLE_PROXY` 且绝不沿环扩展；`build_cycle_world` |
| 提交必须绑定区域和权限代 | `submission.py`（`STALE_GENERATION` / `REGION_BINDING_MISMATCH` / `EPOCH_ROLLBACK`），引擎 `engine.py` 同样强制 region+epoch |
| 两个工作线程与屏障 | `scenario.py::run_flagship`，`threading.Barrier(2)` + 两个 `Event` 固定提交先后 |
| 撤销先提交 | 撤销线程越屏障后先 `commit_revocation`，换岗线程等 `revoke_durable` 后才提交 |
| 换岗提交成功回执丢失 | `store.py::ReceiptLost`：事务已 fsync、head 已原子更新后才抛；客户端只记 `AMBIGUOUS`，不读异常里的服务端回执 |
| 两条旧凭证晚到 | 换岗落盘后，撤销线程把两笔 gen1 旧凭证（旧岗 + 替班）分别作为独立事务追加落盘 |
| 恢复后从落盘记录给当前批准/拒绝的最短证书 | `store.py::DurableStore.reopen/scan_wal` + `cert.py::shortest_certificate` |
| 小整数时间轴穷举所有短交错 | `exhaustive.py`：`7!=5040` 个事件排列逐步用**真实引擎**差分，外加 60 个真实落盘重启排列 |
| 六万条多区域合成记录，比较单区域换岗实际读取范围与全量核验 | `bench.py`：确定性 60000 条 ×12 区域，字节级计量 4 种读取口径 |

---

## 2. 授权模型

判定顺序固定，使“完整世界”和“最小证据子集”能得到同一个稳定原因键：

```
凭证 HMAC 完整性
  → 区域绑定 region
  → 权限代栅栏 epoch == head.region_epochs[region]
  → 半开有效期 lo <= t < hi
  → 替班覆盖对象 scope
  → 两条独立批准根
```

- **半开区间**：`[lo, hi)`。`t=lo` 生效、`t=hi-1` 仍有效、`t=hi` 立即失效。
  换岗双方区间在交接点相接（`[10,20)` 与 `[12,22)` 仅为示意，边界测试专门验证
  `hi` 失效与“端点相接不重叠”），杜绝边界双重资格 / 两不管。
- **代理图无环寻根**：边 `grantor → grantee` 表示“授予代理”。从批准人逆向找授予者，
  只有到达 `TrustedBundle.trusted_roots` 中可信根的**简单路径**才算支持；
  路径上再次遇到当前链中的节点即判定代理环。
- **独立性**：两条支持必须同时满足 `approver / root / control_root` 互不相同。
  因此“连到 `root-a`、`root-b` 但两人同属 `ctrl-shared`”仍被拒绝。
- 所有记录用 HMAC-SHA256 做**模拟签名**（`signing.py`，密钥由主体 ID 确定性派生），
  明确不是真实账号 / 真实密钥体系。

---

## 3. 落盘、崩溃恢复与幂等

`DurableStore`（`store.py`）：

- `wal.jsonl` 追加写：每条记录一个 `d` 数据帧（带 sha256），每笔事务末尾一个 `c`
  COMMIT 帧（带整批 rid 列表与摘要）。`flush + os.fsync` 后事务才算落盘。
- `request_id/txid` 放在**帧层**，不回写记录体，因此不会破坏记录自身 HMAC。
- `head.json` 用“临时文件 + `os.replace`”原子更新，保存各区域当前权限代，带 HMAC 锚点 MAC。
- 恢复 `scan_wal`：只重放“数据帧齐全 + COMMIT 校验通过”的事务；半行 JSON、sha 不符、
  有数据帧无 COMMIT 的尾部整体视为撕裂并可截断修复。
- `request_id` 幂等索引：丢回执后用同一 `request_id` 重试只返回 `duplicated=True`
  和原 txid，**序列号不增长、绝不产生第二次换岗**。

---

## 4. 最短证书

`cert.py`。可信头部（各区域当前 gen + last_seq，HMAC）是恒定锚点；证据记录从候选池按
基数 `k=0,1,2,…` 枚举子集，第一个能被独立验证器 `verify_certificate` 验证出与权威判定
一致的子集即**基数最短**，并通过“删任意一条都不再成立”的无冗余检查。

匹配刻意不对称，防止“空证书拒绝一切”：

- 批准证书：子集必须真的 `allowed=True`（旗舰为 5 条证据：凭证 + 两批准 + 两代理边）。
- 拒绝证书：必须 `allowed=False` 且 `code/detail` 与权威判定**完全一致**。
  - 晚到旧凭证：**1 条证据**（旧凭证本身）+ 头部锚点即可证明 `EPOCH_FENCED`；
  - 共享控制根 / 循环代理：各需 **5 条证据**（凭证 + 两批准/一批准 + 对应拓扑边），
    环的三条边缺一不可，这正是“最短”的可验证含义。

证书可被第三方仅凭“头部锚点 + 内嵌证据”重放验证；篡改锚点 → `BAD_ANCHOR_MAC`，
篡改证据 → 签名失效 / 两根破裂。

---

## 5. 双线程 + Barrier 旗舰时间线

`scenario.py`（`run_flagship`）：

1. 主线程落 `genesis(gen1)`。
2. `W-revoke`、`W-change` 在 `threading.Barrier(2)` 对齐。
3. `W-revoke` 先提交撤销，`cn-east: gen1→gen2`，置 `revoke_durable`。
4. `W-change` 等到撤销落盘，按 `region=cn-east, epoch=2` 绑定提交换岗；事务 fsync 成功，
   但 `lose_receipt=True` 在落盘后抛 `ReceiptLost`，客户端仅记录 `AMBIGUOUS`。
5. `W-revoke` 等 `change_committed` 后，把两条 gen1 旧凭证（旧岗 `cred-old-oli`、
   替班 `cred-old-sub-sam`）作为两笔独立迟到事务落盘。
6. 主线程丢弃内存对象，`DurableStore.reopen` 从磁盘重放，随后：
   - 同 `request_id` 重试 → 幂等命中、序列号不变；
   - 重放 gen1 旧提交 → `STALE_GENERATION`；
   - 产出 1 张最短批准证书 + 2 张最短 `EPOCH_FENCED` 拒绝证书；
   - 另对共享控制根、循环代理各产出一张最短拒绝证书。

---

## 6. 穷举模型检查（`exhaustive.py`）

- **时间轴**：旧岗 / 新岗 / 替班在 `lo-2 … hi+2` 逐点核对“未生效 / 有效 / 已过期”，
  并交叉权限代栅栏与区域绑定。
- **拓扑**：独立双根在有效区间必批准；共享控制根、循环代理在所有小整数时刻必拒绝且原因精确。
- **5040 个交错**：事件 `R撤销 / C换岗 / A回执 / O1旧岗 / O2替班 / X崩溃 / V恢复`
  的全部 `7!` 排列，逐步构造“当时已落盘世界”，每一步调用真实 `authorize_credential` 差分：
  - 撤销一旦提交，之后任何前缀里 gen1 旧凭证一律 `EPOCH_FENCED`；撤销之前按半开区间有效；
  - gen2 换岗只有在撤销之后绑定当前代才提交；一旦落盘，崩溃 / 丢回执 / 恢复位置不改结论；
  - 末尾恢复快照必须等于持久真相。
- **60 个真实落盘交错**：`R / C / Y幂等重试 / K重启 / K重启` 的全部 `5!/2!=60` 个唯一排列，
  用真实 `DurableStore`（fsync + 重开）验证“同一 request_id 恰好一次效果”，
  且凡换岗存在，恢复后最短证书必批准。

---

## 7. 六万条多区域读取范围基准（`bench.py`）

固定种子 `16741` 确定性生成 **60000 条 ×12 区域**记录，区域内按权限代排序，写
`region-XX.jsonl` 与 `manifest.json`（记录每个 `(区域,代)` 的精确字节区间），并维护
`rid→(region,start,end)` 键索引。所有读取字节由 `ReadMeter` 实际统计 `read()` 得到。

四种口径：全量核验 60000 条并逐条验 MAC；单区域整文件；单区域+当前代连续区间；
按键索引精确点读换岗证书所需 5 条证据并真实跑一次引擎授权。

### 本机实测（Python 3.12.1 / Windows，固定种子可复现）

穷举：半开时间轴 **126** 例、根拓扑 **40** 例、纯模型交错 **7!=5040** 个排列
（逐步真实引擎差分 **47040** 次，其中成功回执丢失排列 **1890** 个）、真实落盘重启交错
**60** 个（其中 **40** 个换岗存在且恢复证书批准，与 `R/C/Y` 末位计数精确吻合）。

基准（选中 `region-07` 当前 `gen6`；完整表由 `python run.py` 写入
`artifacts/last_report.txt`，机器可读数字在 `artifacts/bench60k_numbers.json`）：

| 读取口径 | 记录数 | 实读字节 | 用时(ms) | 寻址 |
| --- | ---: | ---: | ---: | ---: |
| 全量核验（12 个区域文件） | 60005 | 15,781,619 | ≈870 | 12 |
| 单区域整文件扫描 | 5075 | 1,334,329 | ≈55–65 | 1 |
| 单区域 + 当前代连续区间 `[1114746,1334329)` | 835 | 219,583 | ≈8–9 | 1 |
| 键索引点读 5 条证据 | 5 | 1,271 | ≈2–3 | 5 |

- 记录数 / 字节放大：全量 vs 单区域当前代段 = **71.9×**；全量 vs 5 条点读 ≈ **12000× / 12417×**。
- 点读的 5 条证据经真实 `authorize_credential` 验证为**批准**，证明该极小读取范围足以支撑结论。
- 用时为单次参考值，随机器波动；记录数、字节范围与放大倍数是确定性的。

> `artifacts/` 已在 `.gitignore` 中；上述文件在一次测试或 `python run.py` 后生成。

---

## 8. 目录结构

```
dutycert/
  intervals.py    半开区间
  signing.py      HMAC/sha256 模拟签名与摘要
  trust.py        信任束、代理图无环寻路、两根独立性与攻击诊断
  engine.py       纯函数授权判定（区域/代/区间/scope/两根）
  submission.py   提交的区域+权限代绑定栅栏
  store.py        WAL/COMMIT/fsync/原子 head/撕尾恢复/request_id 幂等
  cert.py         最短证书搜索、无冗余检查、独立验证器
  world.py        确定性模拟世界与两个攻击拓扑
  scenario.py     两线程 + Barrier 旗舰复现
  exhaustive.py   时间轴/拓扑/5040 交错/60 落盘交错穷举
  bench.py        60000 条多区域读取范围基准
  cli.py          python -m dutycert 报告入口
tests/test_dutycert.py  27 个 unittest（含真实 60k 基准与报告组装）
run.py            测试 + 完整报告一键入口
```

## 9. 设计边界（诚实声明）

- HMAC“签名”和头 MAC 都是**本地模拟**，密钥可从主体 ID 推导，用于表达验证流程与篡改可检出，
  不提供真实身份认证；题面明确“无真实账号”。
- “最短”是在给定恢复世界的候选证据池内、按记录条数的**穷举基数最优**；旗舰/攻击世界很小，
  因此是真正的全局最短，而非贪心近似。
- 基准中的授权内容为合成负载；基准衡量的是**读取范围 / 放大倍数**与核验代价，
  点读的 5 条证据额外做了真实授权以证明该范围足以支撑结论。
