import json
import os
import re
import time

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import confusion_matrix, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split

from .models import MODEL_KEYS, MODEL_NAMES, AnomalySystem, RandomForestDetector, combine
from .traffic import NUM_COLS, generate_dataset

LABEL_NAMES = ["label", "class", "attack", "attack_cat", "attack_type", "attack_label", "category", "type",
               "target", "y", "subcategory", "detailed-label", "detailed_label", "binary_label", "is_attack", "malicious"]
ID_LIKE = re.compile(r"^(unnamed: ?0|id|index|no\.?|row|ts|timestamp|time|stime|ltime|date|datetime|frame\.time.*|flow_id|flow id)$", re.IGNORECASE)
NORMAL_WORDS = re.compile(r"^(benign|benigntraffic|normal|legitimate|0|0\.0)$", re.IGNORECASE)
COLORS = {"if": "#2a78d6", "ae": "#eb6834", "rf": "#1baf7a", "vote": "#3b4350"}
CAPTIONS = {
    "roc": "منحنيات ROC: كلما اقترب المنحنى من الزاوية العليا اليسرى كان النموذج أفضل.",
    "confusion": "مصفوفات الالتباس: الخلايا القطرية صحيحة، والأخرى إنذارات كاذبة أو هجمات فائتة.",
    "scores": "توزيع درجات الشذوذ: الرمادي طبيعي والأحمر هجوم، والخط المتقطع هو العتبة.",
    "ae_loss": "خطأ إعادة البناء أثناء تدريب Autoencoder على بيانات التدريب والتحقق.",
    "importance": "أهم الخصائص في قرارات Random Forest.",
    "per_attack": "نسبة كشف كل نوع هجوم لكل نموذج.",
    "zero_day": "تجربة الهجوم المجهول: نخفي نوعاً واحداً عن Random Forest أثناء التدريب.",
}


def read_csv_sample(path, max_rows=100_000, seed=42):
    with open(path, "rb") as handle:
        lines = [handle.readline() for _ in range(2001)][1:]
    row_bytes = sum(len(line) for line in lines) / max(1, sum(1 for line in lines if line))
    fraction = min(1.0, max_rows / max(1.0, os.path.getsize(path) / row_bytes))
    rng = np.random.default_rng(seed)
    with pd.read_csv(path, chunksize=100_000, low_memory=False) as chunks:
        sample = pd.concat(chunk.sample(frac=fraction, random_state=rng) for chunk in chunks)
    return sample.head(max_rows).reset_index(drop=True)


def guess_label(df):
    candidates = [c for c in df.columns if 2 <= df[c].nunique() <= 200]
    for name in LABEL_NAMES:
        for column in candidates:
            if str(column).strip().lower() == name:
                return column
    text = [c for c in candidates if not pd.api.types.is_numeric_dtype(df[c])]
    if text:
        return text[-1]
    return candidates[-1] if candidates else None


def guess_normal(values):
    counts = values.dropna().astype(str).str.strip().value_counts()
    for value in counts.index:
        if NORMAL_WORDS.match(value):
            return value
    for value in counts.index:
        if "benign" in value.lower() or "normal" in value.lower():
            return value
    return counts.index[0]


def prepare_dataset(df, label_col, normal_value):
    if label_col not in df.columns:
        raise ValueError(f"العمود «{label_col}» غير موجود في الملف.")
    dropped = [c for c in df.columns if c != label_col and (str(c).strip().lower() in LABEL_NAMES or ID_LIKE.match(str(c).strip()))]
    data = df.drop(columns=dropped).replace([np.inf, -np.inf], np.nan)
    data = data.loc[:, (data.isna().mean() < 0.5) | (data.columns == label_col)]
    data = data.dropna().drop_duplicates()
    labels = data[label_col].astype(str).str.strip().to_numpy()
    if (labels == str(normal_value)).sum() < 50 or (labels != str(normal_value)).sum() < 20:
        raise ValueError("يجب أن يحتوي الملف على 50 سجلاً طبيعياً و20 سجل هجوم على الأقل بعد التنظيف.")
    return data.drop(columns=[label_col]).reset_index(drop=True), labels, dropped


def metrics(y_true, alarm, score):
    tn, fp, fn, tp = confusion_matrix(y_true, alarm, labels=[0, 1]).ravel()
    return {
        "accuracy": (tp + tn) / len(y_true),
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "f1": 2 * tp / (2 * tp + fp + fn) if tp else 0.0,
        "auc": roc_auc_score(y_true, score),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "cm": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def run_experiment(features, labels, normal_label, reports_root, folder, trees=200, zero_day_max=4, seed=42, log=print):
    labels = np.asarray(labels).astype(str)
    normal_label = str(normal_label)
    y = (labels != normal_label).astype(int)
    rows = np.arange(len(labels))
    train_rows, test_rows = train_test_split(rows, test_size=0.3, stratify=y, random_state=seed)
    f_train, f_test = features.iloc[train_rows], features.iloc[test_rows]
    l_train, l_test, y_test = labels[train_rows], labels[test_rows], y[test_rows]

    log(f"[{folder}] training Isolation Forest, Autoencoder and Random Forest on {len(train_rows):,} rows ...")
    system = AnomalySystem(normal_label, trees=trees, seed=seed).fit(f_train, l_train)

    X_test = system.pipeline.transform(f_test)
    scores, micros = {}, {}
    for key in MODEL_KEYS:
        started = time.perf_counter()
        scores[key] = system.raw_score(key, X_test)
        micros[key] = (time.perf_counter() - started) * 1e6 / len(X_test)
    risks = np.column_stack([system.risk(key, scores[key]) for key in MODEL_KEYS])
    risks_by_key = dict(zip(MODEL_KEYS, risks.T))
    risks_by_key["vote"] = combine(risks, "majority")
    alarms = {key: (risk >= 50).astype(int) for key, risk in risks_by_key.items()}

    table = []
    for key in MODEL_KEYS + ["vote"]:
        row = metrics(y_test, alarms[key], risks_by_key[key])
        row.update(key=key, name=MODEL_NAMES[key], train_s=system.train_seconds.get(key), micros=micros.get(key))
        table.append(row)

    attack_types = [t for t in pd.Series(l_test).value_counts().index if t != normal_label]
    per_attack = []
    for attack in attack_types:
        mask = l_test == attack
        per_attack.append({"type": attack, "count": int(mask.sum()), **{k: float(alarms[k][mask].mean()) for k in alarms}})

    log(f"[{folder}] zero-day test: hiding one attack type at a time from Random Forest ...")
    X_train = system.pipeline.transform(f_train)
    zero_day = []
    for attack in attack_types[:zero_day_max]:
        keep = l_train != attack
        forest = RandomForestDetector(trees=max(30, trees // 2), seed=seed).fit(X_train[keep], l_train[keep], normal_label)
        mask = l_test == attack
        zero_day.append({"type": attack, "rf": float((forest.score(X_test[mask]) >= 0.5).mean()),
                         "if": float(alarms["if"][mask].mean()), "ae": float(alarms["ae"][mask].mean())})

    importance = pd.Series(system.forest.model.feature_importances_, index=system.pipeline.columns)
    report = {
        "folder": folder,
        "stamp": int(time.time()),
        "rows": len(labels),
        "features": len(system.pipeline.columns),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        "attack_share": float(y.mean()),
        "normal_label": normal_label,
        "classes": pd.Series(labels).value_counts().to_dict(),
        "table": table,
        "per_attack": per_attack,
        "zero_day": zero_day,
        "importance": importance.sort_values(ascending=False).head(12).to_dict(),
        "ae_epochs": len(system.autoencoder.history["val"]),
        "ae_best_epoch": system.autoencoder.best_epoch,
    }
    log(f"[{folder}] drawing figures ...")
    report["figures"] = draw_figures(report, system, y_test, risks_by_key, scores, os.path.join(reports_root, folder))
    return system, report


def draw_figures(report, system, y_test, risks_by_key, scores, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    files = []

    def save(fig, name, wide=False):
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, name + ".png"), dpi=160)
        plt.close(fig)
        files.append({"name": name, "file": name + ".png", "caption": CAPTIONS[name], "wide": wide})

    fig, ax = plt.subplots(figsize=(5.6, 4.0))
    for row in report["table"]:
        fpr, tpr, _ = roc_curve(y_test, risks_by_key[row["key"]])
        name = "Majority vote" if row["key"] == "vote" else row["name"]
        ax.plot(fpr, tpr, color=COLORS[row["key"]], lw=2, label=f"{name} (AUC {row['auc']:.3f})")
    ax.plot([0, 1], [0, 1], color="#999999", ls="--", lw=1)
    ax.set(xlabel="False positive rate", ylabel="True positive rate (recall)", title="ROC curves")
    ax.legend(loc="lower right", fontsize=8)
    save(fig, "roc")

    history = system.autoencoder.history
    epochs = range(1, len(history["val"]) + 1)
    fig, ax = plt.subplots(figsize=(5.6, 4.0))
    ax.plot(epochs, history["train"], color="#3b4350", lw=2, label="train")
    ax.plot(epochs, history["val"], color="#eb6834", lw=2, label="validation")
    ax.axvline(system.autoencoder.best_epoch, color="#999999", ls=":", label="best epoch")
    ax.set(xlabel="epoch", ylabel="reconstruction MSE", yscale="log", title="Autoencoder training")
    ax.legend(fontsize=8)
    save(fig, "ae_loss")

    fig, axes = plt.subplots(1, 3, figsize=(11, 3.4))
    for ax, row in zip(axes, report["table"]):
        cm = np.array(row["cm"])
        ax.imshow(cm, cmap="Blues")
        for (i, j), value in np.ndenumerate(cm):
            ax.text(j, i, f"{value:,}", ha="center", va="center", color="white" if value > cm.max() / 2 else "black")
        ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"],
               xlabel="Predicted", ylabel="Actual", title=row["name"])
    save(fig, "confusion", wide=True)

    fig, axes = plt.subplots(1, 2, figsize=(11, 3.6))
    for ax, key in zip(axes, ["if", "ae"]):
        values = scores[key]
        bins = np.logspace(np.log10(max(values.min(), 1e-6)), np.log10(values.max()), 60) if key == "ae" else 60
        for flag, color, label in [(0, "#6b7480", "Normal"), (1, "#d03b3b", "Attack")]:
            part = values[y_test == flag]
            ax.hist(part, bins=bins, alpha=0.6, color=color, label=label, weights=np.ones(len(part)) / len(part))
        ax.axvline(system.calibrators[key].threshold, color="black", ls="--", lw=1.2, label="threshold")
        ax.set(title=f"{MODEL_NAMES[key]} anomaly score (test set)", ylabel="share of records", xscale="log" if key == "ae" else "linear")
        ax.legend(fontsize=8)
    save(fig, "scores", wide=True)

    charts = [("per_attack", report["per_attack"][:8], MODEL_KEYS + ["vote"], "Detection rate per attack type"),
              ("zero_day", report["zero_day"], ["rf", "if", "ae"], "Zero-day test: attack never seen by Random Forest")]
    for name, rows, keys, chart_title in charts:
        if not rows:
            continue
        fig, ax = plt.subplots(figsize=(5.6, 4.0))
        width = 0.8 / len(keys)
        for k, key in enumerate(keys):
            label = "Majority vote" if key == "vote" else MODEL_NAMES[key]
            ax.bar(np.arange(len(rows)) + k * width, [r[key] for r in rows], width, color=COLORS[key], label=label)
        ax.set_xticks(np.arange(len(rows)) + width * (len(keys) - 1) / 2, [r["type"] for r in rows], fontsize=8, rotation=15)
        ax.set(ylim=(0, 1.25), ylabel="detection rate", title=chart_title)
        ax.legend(fontsize=7, ncol=2, loc="upper center")
        save(fig, name)

    importance = pd.Series(report["importance"]).sort_values()
    fig, ax = plt.subplots(figsize=(11, 3.8))
    ax.barh(importance.index, importance.values, color=COLORS["rf"])
    ax.set(title="Random Forest feature importance", xlabel="mean decrease in impurity")
    save(fig, "importance", wide=True)
    return files


def report_json(report):
    return json.dumps(report, ensure_ascii=False, default=lambda value: value.item() if hasattr(value, "item") else str(value))


def load_or_run_lab(cache_path, reports_root, log=print):
    try:
        cached = joblib.load(cache_path)
        figures_ok = all(os.path.exists(os.path.join(reports_root, "lab", f["file"])) for f in cached["report"]["figures"])
        if cached["sklearn"] == sklearn.__version__ and figures_ok:
            log("Raqib: loaded the trained models from " + cache_path)
            return cached["system"], cached["report"], cached["baseline"]
    except Exception:
        pass
    log("Raqib: first start, training the models (about 20 seconds) ...")
    data = generate_dataset()
    system, report = run_experiment(data.drop(columns="label"), data["label"], "Normal", reports_root, "lab", log=log)
    baseline = data[data["label"] == "Normal"].groupby("device_type")[NUM_COLS].median()
    joblib.dump({"sklearn": sklearn.__version__, "system": system, "report": report, "baseline": baseline}, cache_path)
    return system, report, baseline


if __name__ == "__main__":
    data = generate_dataset()
    _, result = run_experiment(data.drop(columns="label"), data["label"], "Normal", os.path.join("static", "reports"), "lab")
    print(pd.DataFrame(result["table"]).set_index("name")[["accuracy", "precision", "recall", "f1", "auc", "fpr"]].round(4))
    print(pd.DataFrame(result["zero_day"]).set_index("type").round(3))
