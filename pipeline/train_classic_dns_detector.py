#!/usr/bin/env python3
"""Train one classic DNS tunneling detector from PCAP-extracted UDP/TCP features."""

from __future__ import annotations

import argparse
import json
import multiprocessing
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


TARGET = "label"
RANDOM_STATE = 42
DECISION_THRESHOLD = 0.70
DROP_COLUMNS = {
    TARGET,
    "source_file",
    "top_level",
    "split_hint",
    "transport",
    "src_ip",
    "dst_ip",
    "timestamp",
    "query_name",
}


def load_dataset(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    df = pd.read_csv(path)
    if TARGET not in df.columns:
        raise ValueError(f"Dataset must contain '{TARGET}'")
    if df.empty:
        raise ValueError("Dataset is empty")
    df = df.drop_duplicates()
    df[TARGET] = pd.to_numeric(df[TARGET], errors="coerce")
    df = df.dropna(subset=[TARGET])
    df[TARGET] = df[TARGET].astype(int)
    if set(df[TARGET].unique()) - {0, 1}:
        raise ValueError("Labels must be binary: 0=benign, 1=dns_tunnel")
    return add_derived_features(df)


def safe_divide(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    return numerator / denominator.replace(0, np.nan)


_OPTIONAL_COLUMNS = [
    "tcp_payload_size", "dns_length_field", "segment_count",
    "retransmission_ratio", "message_count", "max_message_size",
    "avg_message_size", "rcode",
]


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    numeric_candidates = [column for column in df.columns if column not in DROP_COLUMNS]
    for column in numeric_candidates:
        df[column] = pd.to_numeric(df[column], errors="coerce")

    for column in _OPTIONAL_COLUMNS:
        if column not in df.columns:
            df[column] = 0

    df["response_to_query_ratio_len"] = safe_divide(df["response_length"], df["query_length"])
    df["payload_to_query_ratio"] = safe_divide(df["payload_size"], df["query_length"])
    df["payload_to_response_ratio"] = safe_divide(df["payload_size"], df["response_length"])
    df["entropy_per_query_char"] = safe_divide(df["query_entropy"], df["query_length"])
    df["label_entropy_per_max_label"] = safe_divide(df["label_entropy"], df["max_label_length"])
    df["chars_per_label"] = safe_divide(df["unique_chars"], df["max_label_length"])
    df["query_rate_per_iat"] = safe_divide(df["query_rate"], df["inter_arrival_time"])
    df["high_entropy_long_query"] = df["query_entropy"] * df["query_length"]
    df["digit_hex_mix"] = df["digit_ratio"] * df["hex_ratio"]
    df["txt_or_null_record"] = ((df["has_txt_record"].fillna(0) > 0) | (df["has_null_record"].fillna(0) > 0)).astype(int)
    df["tcp_payload_to_dns_payload_ratio"] = safe_divide(df["tcp_payload_size"], df["payload_size"])
    df["dns_length_to_tcp_payload_ratio"] = safe_divide(df["dns_length_field"], df["tcp_payload_size"])
    df["segments_per_message"] = safe_divide(df["segment_count"], df["message_count"])
    df["payload_per_segment"] = safe_divide(df["tcp_payload_size"], df["segment_count"])
    df["message_size_spread"] = df["max_message_size"] - df["avg_message_size"]
    df["retransmission_payload_pressure"] = df["retransmission_ratio"] * df["payload_size"]
    df["nxdomain_flag"] = (df["rcode"].fillna(0) == 3).astype(int)
    df = df.replace([np.inf, -np.inf], np.nan)
    return df


def feature_columns(df: pd.DataFrame) -> list[str]:
    cols = [
        column
        for column in df.columns
        if column not in DROP_COLUMNS and pd.api.types.is_numeric_dtype(df[column])
    ]
    # Drop columns that are entirely NaN (derived features with division-by-zero)
    return [c for c in cols if df[c].notna().any()]


def split_data(df: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    X = df[features]
    y = df[TARGET]
    groups = df["source_file"] if "source_file" in df.columns else None
    if groups is not None and groups.nunique() >= 4:
        splitter = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=RANDOM_STATE)
        train_index, test_index = next(splitter.split(X, y, groups))
        return X.iloc[train_index], X.iloc[test_index], y.iloc[train_index], y.iloc[test_index]
    return train_test_split(X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE)


def build_models(features: list[str]) -> dict[str, Pipeline]:
    scaled_preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                Pipeline(steps=[("imputer", SimpleImputer(strategy="median")), ("scaler", StandardScaler())]),
                features,
            )
        ],
        remainder="drop",
    )
    tree_preprocessor = ColumnTransformer(
        transformers=[("numeric", Pipeline(steps=[("imputer", SimpleImputer(strategy="median"))]), features)],
        remainder="drop",
    )
    return {
        "logistic_regression": Pipeline(
            steps=[
                ("preprocess", scaled_preprocessor),
                ("model", LogisticRegression(class_weight="balanced", max_iter=2000, random_state=RANDOM_STATE)),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                ("preprocess", tree_preprocessor),
                (
                    "model",
                    RandomForestClassifier(
                        n_estimators=350,
                        class_weight="balanced",
                        min_samples_leaf=2,
                        n_jobs=-1,
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
        "xgboost": Pipeline(
            steps=[
                ("preprocess", tree_preprocessor),
                (
                    "model",
                    XGBClassifier(
                        n_estimators=350,
                        max_depth=4,
                        learning_rate=0.05,
                        subsample=0.9,
                        colsample_bytree=0.9,
                        objective="binary:logistic",
                        eval_metric="logloss",
                        n_jobs=-1,
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
    }


def evaluate(model: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> tuple[dict[str, Any], list[list[int]]]:
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, proba) if len(set(y_test)) > 1 else 0.0,
        "avg_precision": average_precision_score(y_test, proba) if len(set(y_test)) > 1 else 0.0,
        "classification_report": classification_report(y_test, pred, output_dict=True, zero_division=0),
    }
    return metrics, confusion_matrix(y_test, pred).tolist()


def evaluate_at_threshold(proba: np.ndarray, y_test: pd.Series, threshold: float) -> dict[str, Any]:
    pred = (proba >= threshold).astype(int)
    matrix = confusion_matrix(y_test, pred, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    return {
        "threshold": float(threshold),
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1": f1_score(y_test, pred, zero_division=0),
        "false_positive_rate": fp / max(fp + tn, 1),
        "false_negative_rate": fn / max(fn + tp, 1),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def build_threshold_analysis(model: Pipeline, X_test: pd.DataFrame, y_test: pd.Series) -> pd.DataFrame:
    proba = model.predict_proba(X_test)[:, 1]
    thresholds = np.round(np.arange(0.05, 1.0, 0.05), 2)
    rows = [evaluate_at_threshold(proba, y_test, float(threshold)) for threshold in thresholds]
    return pd.DataFrame(rows)


def save_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _get_output_features(model: Pipeline, input_features: list[str]) -> list[str]:
    preprocess = model.named_steps.get("preprocess")
    if hasattr(preprocess, "get_feature_names_out"):
        try:
            return preprocess.get_feature_names_out().tolist()
        except Exception:
            pass
    return input_features


def save_importance(models: dict[str, Pipeline], features: list[str], output_dir: Path) -> None:
    rf = models["random_forest"]
    rf_features = _get_output_features(rf, features)
    pd.DataFrame({"feature": rf_features, "importance": rf.named_steps["model"].feature_importances_}).sort_values(
        "importance", ascending=False
    ).to_csv(output_dir / "random_forest_feature_importance.csv", index=False)

    xgb = models["xgboost"]
    xgb_features = _get_output_features(xgb, features)
    pd.DataFrame({"feature": xgb_features, "importance": xgb.named_steps["model"].feature_importances_}).sort_values(
        "importance", ascending=False
    ).to_csv(output_dir / "xgboost_feature_importance.csv", index=False)

    lr = models["logistic_regression"]
    lr_features = _get_output_features(lr, features)
    pd.DataFrame({"feature": lr_features, "coefficient": lr.named_steps["model"].coef_[0]}).assign(
        abs_coefficient=lambda frame: frame["coefficient"].abs()
    ).sort_values("abs_coefficient", ascending=False).to_csv(
        output_dir / "logistic_regression_coefficients.csv", index=False
    )


def train(dataset: Path, output_dir: Path) -> pd.DataFrame:
    output_dir.mkdir(parents=True, exist_ok=True)
    df = load_dataset(dataset)
    features = feature_columns(df)
    X_train, X_test, y_train, y_test = split_data(df, features)

    models = build_models(features)
    metrics_rows = []
    full_metrics = {}
    matrices = {}
    for name, model in models.items():
        model.fit(X_train, y_train)
        metrics, matrix = evaluate(model, X_test, y_test)
        joblib.dump(model, output_dir / f"{name}.pkl")
        metrics_rows.append(
            {
                "model": name,
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1": metrics["f1"],
                "roc_auc": metrics["roc_auc"],
                "avg_precision": metrics["avg_precision"],
            }
        )
        full_metrics[name] = metrics
        matrices[name] = matrix

    metrics_df = pd.DataFrame(metrics_rows).sort_values(by=["f1", "recall", "roc_auc"], ascending=False)
    best_model_name = str(metrics_df.iloc[0]["model"])
    joblib.dump(models[best_model_name], output_dir / "best_model.pkl")
    threshold_df = build_threshold_analysis(models[best_model_name], X_test, y_test)
    threshold_df.to_csv(output_dir / "threshold_analysis.csv", index=False)
    selected_threshold = threshold_df.loc[(threshold_df["threshold"] - DECISION_THRESHOLD).abs().idxmin()]
    selected_threshold_metrics = {
        key: (int(value) if key in {"tn", "fp", "fn", "tp"} else float(value))
        for key, value in selected_threshold.to_dict().items()
    }
    metrics_df.to_csv(output_dir / "model_metrics.csv", index=False)
    metrics_df.to_csv(output_dir / "model_comparison.csv", index=False)
    pd.Series(features, name="feature").to_csv(output_dir / "feature_names.csv", index=False)
    save_importance(models, features, output_dir)
    save_json(output_dir / "classification_reports.json", full_metrics)
    save_json(output_dir / "confusion_matrices.json", matrices)
    save_json(
        output_dir / "model_metadata.json",
        {
            "dataset": str(dataset),
            "target": TARGET,
            "best_model": best_model_name,
            "random_state": RANDOM_STATE,
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
            "feature_count": len(features),
            "label_mapping": {"0": "benign", "1": "dns_tunnel"},
            "transport_model": "combined_udp_tcp_classic_dns",
            "decision_threshold": DECISION_THRESHOLD,
            "threshold_metrics": selected_threshold_metrics,
            "tui_transport_routing": {
                "UDP53": "artifacts/classic_dns",
                "TCP53": "artifacts/classic_dns",
                "DOH": "artifacts/doh",
            },
        },
    )
    save_json(
        output_dir / "data_profile.json",
        {
            "rows": int(len(df)),
            "columns": int(len(df.columns)),
            "label_counts": df[TARGET].value_counts().sort_index().to_dict(),
            "transport_counts": df["transport"].value_counts().to_dict() if "transport" in df else {},
            "top_level_counts": df["top_level"].value_counts().to_dict() if "top_level" in df else {},
        },
    )
    print(f"Saved classic DNS detector artifacts to {output_dir}")
    print(metrics_df.to_string(index=False))
    print(f"Best model: {best_model_name}")
    return metrics_df


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("datasets/classic_dns_from_pcaps.csv"), help="Path to extracted PCAP features CSV")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/classic_dns"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    train(args.dataset, args.output_dir)


if __name__ == "__main__":
    multiprocessing.set_start_method("fork")
    main()
