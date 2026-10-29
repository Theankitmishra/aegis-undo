"""Trainable & Adversarially Fine-Tunable Semantic Guardrail Classifier with Cryptographic Weight Verification."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.pipeline import FeatureUnion, Pipeline

from aegis.ml.dataset import (
    AdversarialSample,
    build_base_corpus,
    build_redteam_holdout_set,
)

LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})
BASE64_CANDIDATE_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
SPACED_CHARS_RE = re.compile(r"(?:\b[a-zA-Z]\s+){4,}[a-zA-Z]\b")


def normalize_adversarial_text(text: str) -> str:
    """
    Pre-classifier de-obfuscation layer:
      1. Strips invisible zero-width Unicode chars
      2. Collapses spaced-out smuggling (`i g n o r e` -> `ignore`)
      3. Decodes inline Base64 payloads and appends decoded plaintext for semantic scoring
      4. Appends leetspeak-normalized view (`1gn0r3` -> `ignore`)
    """
    cleaned = re.sub(r"[\u200b\u200c\u200d\u2060\ufeff]", "", text)

    def _collapse_spaced(match: re.Match[str]) -> str:
        return re.sub(r"\s+", "", match.group(0))

    collapsed = SPACED_CHARS_RE.sub(_collapse_spaced, cleaned)

    decoded_blobs: List[str] = []
    for b64_tok in BASE64_CANDIDATE_RE.findall(collapsed):
        try:
            raw = base64.b64decode(b64_tok, validate=True).decode("utf-8", errors="ignore")
            if raw and sum(c.isprintable() for c in raw) / len(raw) > 0.85:
                decoded_blobs.append(raw)
        except Exception:
            continue

    leet_norm = collapsed.lower().translate(LEET_MAP)
    parts = [collapsed, leet_norm] + decoded_blobs
    return " || ".join(parts)


@dataclass
class FineTuneMetrics:
    stage: str
    samples_count: int
    accuracy: float
    precision: float
    recall: float
    f1: float


class AdversarialGuardrailClassifier:
    """
    Local low-latency semantic classifier combining Word N-grams + Character Subword N-grams
    with de-obfuscation and iterative hard-negative adversarial fine-tuning.
    Persists a SHA-256 weight integrity manifest so poisoned model files are rejected on load.
    """

    def __init__(self, threshold: float = 0.52) -> None:
        self.threshold = threshold
        self.pipeline: Optional[Pipeline] = None
        self.corpus: List[AdversarialSample] = []
        self.training_rounds: int = 0

    def _build_pipeline(self) -> Pipeline:
        features = FeatureUnion(
            transformer_list=[
                (
                    "word_ngrams",
                    TfidfVectorizer(
                        ngram_range=(1, 3),
                        min_df=1,
                        sublinear_tf=True,
                        lowercase=True,
                    ),
                ),
                (
                    "char_ngrams",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        min_df=1,
                        sublinear_tf=True,
                        lowercase=True,
                    ),
                ),
            ]
        )
        clf = LogisticRegression(C=6.0, class_weight="balanced", max_iter=1000, random_state=42)
        return Pipeline([("features", features), ("clf", clf)])

    def train_base(self, custom_samples: Optional[List[AdversarialSample]] = None) -> FineTuneMetrics:
        self.corpus = list(custom_samples) if custom_samples is not None else build_base_corpus()
        texts = [normalize_adversarial_text(s.text) for s in self.corpus]
        labels = [s.label for s in self.corpus]

        self.pipeline = self._build_pipeline()
        self.pipeline.fit(texts, labels)
        self.training_rounds = 1

        holdout, _ = build_redteam_holdout_set()
        return self.evaluate(holdout, stage="base_pretrained")

    def fine_tune(
        self,
        adversarial_feedback: List[AdversarialSample],
        oversample_factor: int = 3,
        eval_set: Optional[List[AdversarialSample]] = None,
    ) -> Dict[str, Any]:
        """
        Fine-tune the semantic guardrail on newly discovered company-specific attack vectors
        and hard false-positives, returning Before vs. After evaluation metrics.
        """
        if self.pipeline is None:
            self.train_base()

        target_eval = eval_set if eval_set is not None else build_redteam_holdout_set()[0]
        before_metrics = self.evaluate(target_eval, stage="before_finetune")

        for item in adversarial_feedback:
            for _ in range(max(1, oversample_factor)):
                self.corpus.append(item)

        texts = [normalize_adversarial_text(s.text) for s in self.corpus]
        labels = [s.label for s in self.corpus]

        self.pipeline = self._build_pipeline()
        self.pipeline.fit(texts, labels)
        self.training_rounds += 1

        after_metrics = self.evaluate(target_eval, stage=f"finetuned_round_{self.training_rounds}")
        return {
            "training_rounds": self.training_rounds,
            "total_training_samples": len(self.corpus),
            "before": before_metrics.__dict__,
            "after": after_metrics.__dict__,
        }

    def predict_attack_probability(self, payload_text: str) -> float:
        if self.pipeline is None:
            self.train_base()
        assert self.pipeline is not None
        norm = normalize_adversarial_text(payload_text)
        prob = float(self.pipeline.predict_proba([norm])[0][1])
        return round(prob, 4)

    def inspect(self, payload_text: str) -> Dict[str, Any]:
        prob = self.predict_attack_probability(payload_text)
        return {
            "is_malicious": prob >= self.threshold,
            "attack_probability": prob,
            "threshold": self.threshold,
            "training_rounds": self.training_rounds,
        }

    def evaluate(self, samples: List[AdversarialSample], stage: str = "eval") -> FineTuneMetrics:
        if self.pipeline is None:
            self.train_base()
        y_true = [s.label for s in samples]
        y_pred = [1 if self.predict_attack_probability(s.text) >= self.threshold else 0 for s in samples]
        return FineTuneMetrics(
            stage=stage,
            samples_count=len(samples),
            accuracy=round(float(accuracy_score(y_true, y_pred)), 4),
            precision=round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            recall=round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            f1=round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        )

    def save_verified_checkpoint(self, model_dir: str | Path) -> Dict[str, str]:
        """Save model weights alongside a SHA-256 integrity manifest to prevent supply-chain weight tampering."""
        if self.pipeline is None:
            self.train_base()
        out_dir = Path(model_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        weights_path = out_dir / "aegis_guardrail_v2.joblib"
        manifest_path = out_dir / "aegis_guardrail_v2.manifest.json"

        joblib.dump(
            {
                "pipeline": self.pipeline,
                "threshold": self.threshold,
                "training_rounds": self.training_rounds,
                "corpus_size": len(self.corpus),
            },
            weights_path,
        )
        sha256_hex = hashlib.sha256(weights_path.read_bytes()).hexdigest()
        manifest = {
            "model_file": weights_path.name,
            "sha256": sha256_hex,
            "training_rounds": self.training_rounds,
            "corpus_size": len(self.corpus),
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return {"weights_path": str(weights_path), "sha256": sha256_hex}

    def load_verified_checkpoint(self, model_dir: str | Path) -> None:
        """Verify SHA-256 digest BEFORE deserializing weights so tampered `.joblib` files are rejected."""
        in_dir = Path(model_dir)
        weights_path = in_dir / "aegis_guardrail_v2.joblib"
        manifest_path = in_dir / "aegis_guardrail_v2.manifest.json"

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        actual_sha = hashlib.sha256(weights_path.read_bytes()).hexdigest()
        if actual_sha != manifest.get("sha256"):
            raise RuntimeError(
                "CRITICAL MODEL SUPPLY-CHAIN ALERT: Guardrail checkpoint SHA-256 mismatch! "
                "Refusing to deserialize potentially poisoned model weights."
            )

        bundle = joblib.load(weights_path)
        self.pipeline = bundle["pipeline"]
        self.threshold = float(bundle["threshold"])
        self.training_rounds = int(bundle["training_rounds"])
