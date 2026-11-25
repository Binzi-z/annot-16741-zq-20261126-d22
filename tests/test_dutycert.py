"""覆盖半开区间、两根独立性、区域/代绑定、落盘恢复、最短证书、
双线程旗舰场景、穷举交错与规模基准的标准库 unittest。

运行：``python -m unittest discover -s tests -v``
"""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from dutycert.bench import run_benchmark
from dutycert.cert import shortest_certificate, verify_certificate
from dutycert.engine import (
    EPOCH_FENCED,
    INTERVAL_EXPIRED,
    OK,
    REGION_MISMATCH,
    authorize_credential,
)
from dutycert.exhaustive import run_exhaustive
from dutycert.intervals import Interval
from dutycert.scenario import run_flagship
from dutycert.store import DurableStore, RecoveredState
from dutycert.submission import (
    BindingRejected,
    Submission,
    commit_revocation,
    submit_data_plane,
)
from dutycert.world import (
    REGION,
    T_EVAL,
    build_cycle_world,
    build_flagship,
    build_shared_control_world,
)


class TestIntervals(unittest.TestCase):
    def test_half_open_boundaries(self):
        iv = Interval(10, 13)
        self.assertFalse(iv.contains(9))
        self.assertTrue(iv.contains(10))   # lo 含
        self.assertTrue(iv.contains(12))   # hi-1 含
        self.assertFalse(iv.contains(13))  # hi 不含：半开关键
        self.assertFalse(iv.contains(14))

    def test_touching_intervals_do_not_overlap(self):
        a = Interval(10, 13)
        b = Interval(13, 16)  # 端点相接，不算重叠 -> 换岗边界无双重资格
        self.assertFalse(a.overlaps(b))
        self.assertTrue(a.overlaps(Interval(12, 14)))

    def test_invalid_interval(self):
        with self.assertRaises(ValueError):
            Interval(5, 2)


class TestAuthorizationCore(unittest.TestCase):
    def setUp(self):
        self.world = build_flagship()
        self.bundle = self.world.bundle
        self.records = self.world.record_map()

    def test_new_post_approved_with_two_independent_roots(self):
        v = authorize_credential(
            self.records["cred-neo-new"], self.records, self.bundle,
            region=REGION, current_epoch=2, at=T_EVAL,
        )
        self.assertTrue(v.allowed, v.short())
        self.assertEqual(v.code, OK)
        self.assertIsNotNone(v.pair)
        a, b = v.pair
        self.assertNotEqual(a.root, b.root)
        self.assertNotEqual(a.control_root, b.control_root)

    def test_old_credentials_fenced_after_revocation(self):
        for rid in self.world.old_cred_rids:
            v = authorize_credential(
                self.records[rid], self.records, self.bundle,
                region=REGION, current_epoch=2, at=T_EVAL,
            )
            self.assertFalse(v.allowed)
            self.assertEqual(v.code, EPOCH_FENCED, v.short())

    def test_old_credentials_were_valid_before_revocation(self):
        # 撤销前 current_epoch=1：两条旧凭证在 t=13 都应有效（含替班）
        for rid in self.world.old_cred_rids:
            v = authorize_credential(
                self.records[rid], self.records, self.bundle,
                region=REGION, current_epoch=1, at=T_EVAL,
                acting_for="old_oli",
            )
            self.assertTrue(v.allowed, v.short())

    def test_half_open_expiry_at_hi(self):
        # 旧岗 [10,20)：t=19 仍有效，t=20 立即过期（即便 gen 匹配）
        ok = authorize_credential(
            self.records["cred-old-oli"], self.records, self.bundle,
            region=REGION, current_epoch=1, at=19,
        )
        expired = authorize_credential(
            self.records["cred-old-oli"], self.records, self.bundle,
            region=REGION, current_epoch=1, at=20,
        )
        self.assertTrue(ok.allowed, ok.short())
        self.assertFalse(expired.allowed)
        self.assertEqual(expired.code, INTERVAL_EXPIRED)

    def test_region_binding_enforced(self):
        v = authorize_credential(
            self.records["cred-neo-new"], self.records, self.bundle,
            region="cn-other", current_epoch=2, at=T_EVAL,
        )
        self.assertEqual(v.code, REGION_MISMATCH)

    def test_substitute_scope(self):
        # 替班凭证声明 covers old_oli；替错人必须拒绝
        wrong = authorize_credential(
            self.records["cred-old-sub-sam"], self.records, self.bundle,
            region=REGION, current_epoch=1, at=13, acting_for="someone-else",
        )
        self.assertEqual(wrong.code, "SUBSTITUTE_SCOPE")

    def test_shared_control_root_denied(self):
        aw = build_shared_control_world()
        m = aw.record_map()
        v = authorize_credential(
            m[aw.cred_rid], m, aw.bundle,
            region=aw.region, current_epoch=aw.epoch, at=aw.at,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.code, aw.expected_code)
        self.assertTrue(v.detail.startswith("SHARED_CONTROL_ROOT:ctrl-shared"), v.detail)

    def test_cyclic_proxy_denied(self):
        aw = build_cycle_world()
        m = aw.record_map()
        v = authorize_credential(
            m[aw.cred_rid], m, aw.bundle,
            region=aw.region, current_epoch=aw.epoch, at=aw.at,
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.detail, "CYCLE_PROXY", v.short())


class TestSubmissionBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="dutycert_sub_")
        self.world = build_flagship()
        self.store = DurableStore(self.tmp, self.world.bundle.head_key)
        self.store.commit_batch([{
            "rid": "genesis", "kind": "genesis",
            "region": REGION, "epoch": 1, "at": 0,
        }])
        commit_revocation(
            self.store, self.world.revocation_batch[0], request_id="req-rev"
        )

    def test_stale_generation_submission_rejected(self):
        stale = Submission("x", REGION, 1, tuple())
        with self.assertRaises(BindingRejected) as ctx:
            submit_data_plane(self.store, stale)
        self.assertEqual(ctx.exception.code, "STALE_GENERATION")

    def test_region_payload_mismatch_rejected(self):
        bad = Submission(
            "x", REGION, 2,
            ({"rid": "z", "region": "cn-north", "epoch": 2},),
        )
        with self.assertRaises(BindingRejected) as ctx:
            submit_data_plane(self.store, bad)
        self.assertEqual(ctx.exception.code, "PAYLOAD_BINDING_MISMATCH")

    def test_epoch_rollback_rejected(self):
        rec = {"rid": "rev-bad", "kind": "revocation",
               "region": REGION, "epoch": 1}
        with self.assertRaises(BindingRejected) as ctx:
            commit_revocation(self.store, rec, request_id="req-bad")
        self.assertEqual(ctx.exception.code, "EPOCH_ROLLBACK")


class TestStoreRecovery(unittest.TestCase):
    def test_commit_reopen_and_idempotent_retry(self):
        world = build_flagship()
        with tempfile.TemporaryDirectory(prefix="dutycert_store_") as tmp:
            store = DurableStore(tmp, world.bundle.head_key)
            r1 = store.commit_batch(
                world.revocation_batch, txid="t1", request_id="req-1"
            )
            self.assertFalse(r1.duplicated)
            last = store.last_seq

            again = store.commit_batch(
                world.revocation_batch, txid="t1b", request_id="req-1"
            )
            self.assertTrue(again.duplicated)
            self.assertEqual(store.last_seq, last)

            reopened = DurableStore.reopen(tmp, world.bundle.head_key)
            state = reopened.recover()
            self.assertEqual(state.region_epochs[REGION], 2)
            self.assertIn("req-1", state.request_meta)
            self.assertTrue(Path(tmp, "head.json").exists())
            self.assertIsNotNone(reopened.read_verified_head())

    def test_torn_tail_is_discarded_and_repaired(self):
        world = build_flagship()
        with tempfile.TemporaryDirectory(prefix="dutycert_torn_") as tmp:
            store = DurableStore(tmp, world.bundle.head_key)
            store.commit_batch(world.revocation_batch, txid="t1")
            valid_size = Path(tmp, "wal.jsonl").stat().st_size

            store.append_torn_tail(b'{"t":"d","seq":999,"rec": {')
            torn = store.recover(repair=False)
            self.assertGreater(torn.torn_bytes, 0)
            self.assertEqual(torn.region_epochs[REGION], 2)
            self.assertTrue(all(r["rid"] != "fake" for r in torn.records))

            repaired = store.recover(repair=True)
            self.assertGreater(repaired.torn_bytes, 0)
            self.assertEqual(Path(tmp, "wal.jsonl").stat().st_size, valid_size)

            after = store.recover(repair=True)
            self.assertEqual(after.torn_bytes, 0)

    def test_garbage_line_does_not_crash_recovery(self):
        world = build_flagship()
        with tempfile.TemporaryDirectory(prefix="dutycert_garbage_") as tmp:
            store = DurableStore(tmp, world.bundle.head_key)
            store.commit_batch(world.revocation_batch, txid="t1")
            store.append_garbage_line()
            state = store.recover(repair=True)
            self.assertEqual(state.region_epochs[REGION], 2)
            self.assertGreaterEqual(len(state.records), 1)


class TestShortestCertificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_flagship()  # 内部已含完整断言
        cls.bundle = build_flagship().bundle

    def test_approval_cert_is_minimal_and_valid(self):
        cert = self.result.approval_cert
        self.assertIsNotNone(cert)
        self.assertTrue(cert.irredundant)
        verdict = verify_certificate(cert, self.bundle)
        self.assertTrue(verdict.allowed, verdict.short())
        # 凭证 + 两条批准 + 两条代理边 = 5 条证据，缺一不可
        self.assertEqual(cert.witness_count, 5)

    def test_epoch_denial_cert_is_one_record_minimal(self):
        for rid, cert in self.result.denial_certs.items():
            self.assertTrue(cert.irredundant)
            self.assertEqual(cert.witness_count, 1, cert.brief())
            v = verify_certificate(cert, self.bundle)
            self.assertEqual(v.code, EPOCH_FENCED)

    def test_shared_and_cycle_denial_certs_minimal(self):
        shared = self.result.attack_certs["shared-control-root"]
        cycle = self.result.attack_certs["cyclic-proxy"]
        self.assertEqual(shared.witness_count, 5)
        self.assertTrue(shared.irredundant)
        self.assertEqual(cycle.witness_count, 5)  # 环的三条边缺一不可
        self.assertTrue(cycle.irredundant)
        self.assertFalse(self.result.attack_verdicts["cyclic-proxy"].allowed)

    def test_tampered_anchor_rejected(self):
        cert_dict = copy.deepcopy(self.result.approval_cert.to_dict())
        cert_dict["anchor"]["payload"]["region_epochs"][REGION] = 99
        v = verify_certificate(cert_dict, self.bundle)
        self.assertEqual(v.code, "BAD_ANCHOR_MAC")

    def test_tampered_evidence_rejected(self):
        cert_dict = copy.deepcopy(self.result.approval_cert.to_dict())
        # 篡改其中一条批准的有效期 -> MAC 失效 -> 无法维持两根
        cert_dict["records"][1]["hi"] = 999
        v = verify_certificate(cert_dict, self.bundle)
        self.assertFalse(v.allowed)


class TestFlagshipThreads(unittest.TestCase):
    def test_flagship_all_checks(self):
        result = run_flagship()
        self.assertGreaterEqual(len(result.passed_checks), 7)
        self.assertTrue(
            result.client_views["W-change"].startswith("AMBIGUOUS")
        )
        self.assertTrue(result.retry_duplicated)
        self.assertTrue(result.retry_last_seq_unchanged)
        self.assertEqual(result.stale_submission_code, "STALE_GENERATION")
        self.assertEqual(result.recovered_epochs[REGION], 2)


class TestExhaustive(unittest.TestCase):
    def test_all_short_interleavings(self):
        rep = run_exhaustive(disk=True)
        rep.raise_if_broken()
        self.assertEqual(rep.interleavings, 5040)   # 7!
        self.assertEqual(rep.disk_interleavings, 60)  # 5!/2!
        self.assertGreater(rep.ack_lost_cases, 0)
        self.assertGreater(rep.prefix_checks, 0)
        self.assertGreater(rep.disk_approval_certs, 0)


class TestBenchmark(unittest.TestCase):
    def test_scaled_benchmark_read_ranges(self):
        with tempfile.TemporaryDirectory(prefix="dutycert_bench_") as tmp:
            rep = run_benchmark(tmp, n=1200, n_regions=12)
            self.assertEqual(rep.full.records_read, 1205)  # +5 cluster
            self.assertLess(rep.epoch_range.records_read, rep.full.records_read)
            self.assertLess(rep.epoch_range.bytes_read, rep.full.bytes_read)
            self.assertEqual(rep.point_read.records_read, 5)
            self.assertTrue(rep.point_cluster_approved)
            # 单区域代段至少比全量少一个数量级（12 区域 × 若干代）
            self.assertGreater(
                rep.full.records_read / rep.epoch_range.records_read, 8.0
            )


class TestFullScaleSixtyK(unittest.TestCase):
    """真正跑一次题面要求的 60000 条，并把实测读取范围写入 artifacts/。"""

    def test_full_60k_comparison_and_dump(self):
        from dutycert.cli import ARTIFACTS

        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        rep = run_benchmark(ARTIFACTS / "benchdata", n=60_000, n_regions=12)

        self.assertEqual(rep.n_records, 60_000)
        self.assertEqual(rep.full.records_read, 60_005)
        self.assertEqual(rep.n_regions, 12)
        self.assertEqual(rep.point_read.records_read, 5)
        self.assertTrue(rep.point_cluster_approved)
        # 单区域当前代段、点读都必须显著小于全量核验
        self.assertLess(rep.epoch_range.records_read, rep.full.records_read / 20)
        self.assertLess(rep.point_read.bytes_read, rep.full.bytes_read / 1000)

        (ARTIFACTS / "bench60k_report.txt").write_text(
            "\n".join(rep.report_lines()), encoding="utf-8"
        )
        # 供报告/文档引用的机器可读实测数字
        import json

        numbers = {
            "records": rep.full.records_read,
            "full_bytes": rep.full.bytes_read,
            "full_ms": round(rep.full.elapsed_s * 1000, 1),
            "region_records": rep.region_scan.records_read,
            "region_bytes": rep.region_scan.bytes_read,
            "epoch": rep.picked_epoch,
            "epoch_records": rep.epoch_range.records_read,
            "epoch_bytes": rep.epoch_range.bytes_read,
            "epoch_extent": rep.manifest["regions"][rep.picked_region][
                str(rep.picked_epoch)
            ],
            "point_records": rep.point_read.records_read,
            "point_bytes": rep.point_read.bytes_read,
            "record_ratio": round(
                rep.full.records_read / rep.epoch_range.records_read, 1
            ),
            "byte_ratio": round(rep.full.bytes_read / rep.epoch_range.bytes_read, 1),
        }
        (ARTIFACTS / "bench60k_numbers.json").write_text(
            json.dumps(numbers, ensure_ascii=False, indent=2), encoding="utf-8"
        )


class TestReportAssembly(unittest.TestCase):
    """走一遍 CLI 的完整报告拼装，确保所有 report_lines() 不抛异常，
    并生成与 `python run.py` 同内容的 artifacts/last_report.txt。"""

    def test_build_full_report_and_dump(self):
        from dutycert.cli import ARTIFACTS, build_report

        lines = build_report(bench_n=60_000)
        text = "\n".join(lines)
        for heading in ("旗舰", "穷举", "读取范围", "全部自检通过"):
            self.assertIn(heading, text)
        self.assertIn("5040", text)
        self.assertIn("60000", text)
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        (ARTIFACTS / "last_report.txt").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    unittest.main(verbosity=2)
