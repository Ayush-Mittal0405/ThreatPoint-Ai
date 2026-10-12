"""
Unit tests for the Dataset Builder (Fine-Tuning Data Extraction & Formatter).
"""
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from ml.datasets.dataset_builder import DatasetBuilder, SEED_SAMPLES


class TestDatasetBuilder:
    def test_format_chatml(self):
        builder = DatasetBuilder(format_type="chatml")
        sample = {
            "system": "You are AegisX Triage Agent.",
            "user": '{"alert_id": "ALT-123"}',
            "assistant": '{"severity": "high"}',
        }
        res = builder.format_sample(sample)
        assert "messages" in res
        assert len(res["messages"]) == 3
        assert res["messages"][0]["role"] == "system"
        assert res["messages"][1]["role"] == "user"
        assert res["messages"][2]["role"] == "assistant"

    def test_format_alpaca(self):
        builder = DatasetBuilder(format_type="alpaca")
        sample = {
            "system": "You are AegisX Triage Agent.",
            "user": '{"alert_id": "ALT-123"}',
            "assistant": '{"severity": "high"}',
        }
        res = builder.format_sample(sample)
        assert "instruction" in res
        assert "input" in res
        assert "output" in res
        assert res["instruction"] == sample["system"]
        assert res["input"] == sample["user"]

    def test_generate_seed_data(self):
        builder = DatasetBuilder()
        data = builder.generate_seed_data(multiplier=2)
        assert len(data) == len(SEED_SAMPLES) * 2

    def test_save_splits(self):
        with TemporaryDirectory() as tmp_dir:
            builder = DatasetBuilder(output_dir=tmp_dir, format_type="chatml")
            data = builder.generate_seed_data(multiplier=5)
            splits = builder.save_splits(data, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)

            assert splits["train"] > 0
            assert splits["val"] > 0
            assert splits["test"] > 0
            assert splits["train"] + splits["val"] + splits["test"] == len(data)

            assert (Path(tmp_dir) / "train.jsonl").exists()
            assert (Path(tmp_dir) / "val.jsonl").exists()
            assert (Path(tmp_dir) / "test.jsonl").exists()
            assert (Path(tmp_dir) / "dataset_info.json").exists()

            # Verify JSONL lines are valid JSON
            with open(Path(tmp_dir) / "train.jsonl", "r", encoding="utf-8") as f:
                for line in f:
                    obj = json.loads(line)
                    assert "messages" in obj
