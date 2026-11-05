import tempfile
from pathlib import Path

import pandas as pd

from detector.train import load_extra, train_sms

HAM = ["see you at lunch tomorrow {}", "please send the notes for class {}", "call me when free {}"]
SCAM = ["URGENT verify your KYC now http://bit.ly/a{} account blocked", "You won a prize claim reward {} free"]


def _df():
    rows = [(1, SCAM[i % 2].format(i)) for i in range(120)] + \
           [(0, HAM[i % 3].format(i)) for i in range(240)]
    return pd.DataFrame(rows, columns=["y", "text"])


def test_extra_goes_to_train_only():
    base_model, base_meta, _ = train_sms(_df(), "toy")
    extra = pd.DataFrame({"y": [0, 0, 1], "text": ["your otp is 123456 do not share it",
                                                   "payment received thank you",
                                                   "pay fee at http://x.top/a now"]})
    model, meta, _ = train_sms(_df(), "toy", extra=extra)
    s, b = meta["split_sizes"], base_meta["split_sizes"]
    assert s["train_extra"] == 3 and s["train"] == b["train"] + 3
    assert s["validation"] == b["validation"] and s["test"] == b["test"]
    assert "transactional" in meta["dataset"]


def test_extra_never_repeats_eval_or_uci_texts():
    with tempfile.TemporaryDirectory() as t:
        t = Path(t)
        (t / "eval").mkdir()
        (t / "eval" / "x.csv").write_text("label,text\n0,Hello there  friend\n1,win a prize\n",
                                          encoding="utf-8")
        (t / "extra.csv").write_text("label,text\n0,hello THERE friend\n0,a brand new message\n",
                                     encoding="utf-8")
        ex = load_extra(t / "extra.csv", t / "eval")
        assert list(ex["text"]) == ["a brand new message"]
    dup = pd.DataFrame({"y": [0], "text": [HAM[0].format(0)]})  # already in the UCI-like data
    _, meta, _ = train_sms(_df(), "toy", extra=dup)
    assert meta["split_sizes"]["train_extra"] == 0


def test_missing_extra_file_is_fine():
    assert load_extra(Path("nope.csv"), Path("nope_dir")) is None