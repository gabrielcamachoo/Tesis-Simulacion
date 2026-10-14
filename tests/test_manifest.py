#!/usr/bin/env python3
"""Tests del manifest por corrida (run_experiment.write_manifest)."""

import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluate import EvaluationResult  # noqa: E402
from run_experiment import (  # noqa: E402
    LAB_ONLY_WARNING, ProcessSampler, git_info, sha256_file, write_manifest)


def _fake_run_dir(tmp_path):
    run = tmp_path / "runs" / "20260101_000000"
    (run / "alerts").mkdir(parents=True)
    (run / "settings_lab.yaml").write_text("lab: true\n", encoding="utf-8")
    (run / "seed.txt").write_text("seed_base=42\n", encoding="utf-8")
    (run / "ground_truth.jsonl").write_text(
        '{"injection_id":"INJ-1"}\n', encoding="utf-8")
    (run / "alerts" / "alerts.jsonl").write_text(
        '{"alert_id":"A-1","rule_id":"R-ID-001"}\n', encoding="utf-8")
    (run / "evaluation.json").write_text("{}", encoding="utf-8")
    return run


def _fake_args():
    return Namespace(seed_base=42,
                     phase_seeds={"benign1": 42, "anomalies": 1000045,
                                  "benign2": 2000045},
                     benign_count=6, interval=6.0, anomaly_count=3,
                     exclude="A14", window=5.0)


def test_sha256_file_stable(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"abc")
    h1 = sha256_file(p)
    assert h1 == sha256_file(p)
    assert len(h1) == 64


def test_git_info_keys():
    info = git_info()
    assert "commit" in info and "dirty" in info


def test_write_manifest_fields(tmp_path):
    run = _fake_run_dir(tmp_path)
    res = EvaluationResult(tp=5, fp=0, tn=3, fn=0, recall=1.0,
                           precision=1.0, f1_score=1.0, fpr=0.0)
    path = write_manifest(run, _fake_args(), "local",
                          "2026-01-01T00:00:00+00:00",
                          "2026-01-01T00:05:00+00:00",
                          res, {"note": "sin psutil"})
    assert path.exists()
    m = json.loads(path.read_text(encoding="utf-8"))

    assert m["identificador_experimento"] == "20260101_000000"
    assert m["configuracion"]["mode"] == "local"
    assert m["configuracion"]["exclude"] == "A14"
    assert m["semilla"]["seed_base"] == 42
    assert m["semilla"]["phase_seeds"]["anomalies"] == 1000045
    assert "A14" in m["escenarios_excluidos"]
    assert "A01" in m["escenarios_ejecutados"]
    assert "A14" not in m["escenarios_ejecutados"]
    assert "settings_lab.yaml" in m["hashes_entradas"]
    assert "ground_truth.jsonl" in m["hashes_salidas"]
    assert "alerts/alerts.jsonl" in m["hashes_salidas"]
    assert m["resultado"]["tp"] == 5
    assert m["resultado"]["recall"] == 1.0
    assert m["advertencia"] == LAB_ONLY_WARNING
    assert "commit" in m["commit_git"]
    assert m["runtime"]["python"]


def test_write_manifest_null_result(tmp_path):
    run = _fake_run_dir(tmp_path)
    path = write_manifest(run, _fake_args(), "docker",
                          "2026-01-01T00:00:00+00:00",
                          "2026-01-01T00:05:00+00:00",
                          None, {})
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m["resultado"] is None
    assert m["runtime"]["contenedor"]


def test_process_sampler_without_psutil_graceful():
    s = ProcessSampler()
    s._psutil = None
    out = s.stop()
    assert "note" in out
