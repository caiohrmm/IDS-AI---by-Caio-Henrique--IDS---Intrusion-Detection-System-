import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
from sklearn.pipeline import Pipeline as SkPipeline
from sklearn.preprocessing import FunctionTransformer
from xgboost import XGBClassifier


# -----------------------------
# Utility functions
# -----------------------------

def find_cicflowmeter_command() -> Optional[List[str]]:
    """Return a command list to invoke CICFlowMeter, or None if not found.

    Tries a few common forms that work on Windows/Linux:
    - cicflowmeter
    - cfm
    - python -m cicflowmeter
    """
    candidates = [
        ["cicflowmeter"],
        ["cfm"],
        ["python", "-m", "cicflowmeter"],
        ["python3", "-m", "cicflowmeter"],
    ]
    for cmd in candidates:
        try:
            subprocess.run(cmd + ["-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            return cmd
        except Exception:
            continue
    return None


def ensure_cicflowmeter_csv(input_path: Path, output_dir: Path, cic_cmd: Optional[List[str]]) -> Path:
    """Ensure a flows CSV exists for the given pcap/pcapng/pcap_ISCX file using CICFlowMeter.

    If a CSV exists already next to the file or in output_dir, it is reused.
    Otherwise, runs CICFlowMeter and writes a CSV in output_dir.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Choose an output CSV path
    csv_name = f"{input_path.stem}_flows.csv"
    out_csv = output_dir / csv_name

    # Reuse if already present
    if out_csv.exists():
        return out_csv

    if cic_cmd is None:
        raise RuntimeError(
            "CICFlowMeter não encontrado no PATH. Instale com 'pip install cicflowmeter' ou adicione ao PATH."
        )

    # Run CICFlowMeter
    # CLI usage: cicflowmeter -f input.pcap -c output.csv
    cmd = cic_cmd + ["-f", str(input_path), "-c", str(out_csv)]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"Falha ao executar CICFlowMeter para {input_path.name}.\n"
            f"Comando: {' '.join(cmd)}\nSaída:\n{completed.stdout}\nErro:\n{completed.stderr}"
        )
    if not out_csv.exists():
        raise RuntimeError(f"CSV esperado não foi gerado: {out_csv}")
    return out_csv


def extract_label_from_filename(path: Path) -> str:
    """Extract label from filename.

    - If contains 'BENIGN' (case-insensitive) -> 'BENIGN'
    - Else try to infer common attack names from filename tokens.
    - Fallback: 'ATTACK'
    """
    name = path.stem.lower()
    if "benign" in name:
        return "BENIGN"

    # Normalize separators to spaces and split tokens
    tokens = re.split(r"[^a-z0-9]+", name)
    token_set = set(tokens)

    # Common attack label mapping (lowercase token -> canonical label)
    mapping = [
        ("ddos", "DDoS"),
        ("dos", "DoS"),
        ("portscan", "PortScan"),
        ("infiltration", "Infiltration"),
        ("infilteration", "Infiltration"),  # frequent misspelling in filenames
        ("webattacks", "WebAttacks"),
        ("web", "WebAttacks"),
        ("botnet", "Botnet"),
        ("bruteforce", "BruteForce"),
        ("ssh", "SSH"),
        ("ftp", "FTP"),
        ("sqlinjection", "SQLInjection"),
        ("sql", "SQLInjection"),
        ("heartbleed", "Heartbleed"),
        ("xss", "XSS"),
        ("injection", "Injection"),
        ("worm", "Worm"),
        ("malware", "Malware"),
        ("ransomware", "Ransomware"),
        ("scan", "PortScan"),
    ]
    for key, label in mapping:
        if key in token_set:
            return label

    return "ATTACK"


def list_input_files(base_dir: Path) -> List[Path]:
    """List pcap-like inputs and ready CSVs.

    Includes files with extensions: .pcap, .pcapng, .pcap_ISCX
    Also includes already-extracted CSVs that look like flows from ISCX dataset (e.g., *pcap_ISCX.csv).
    """
    patterns = ["*.pcap", "*.pcapng", "*.pcap_ISCX", "*.pcap_ISCX.csv"]
    found: List[Path] = []
    for pat in patterns:
        found.extend(base_dir.glob(pat))
    # Deduplicate
    uniq = []
    seen = set()
    for p in found:
        if p.resolve() not in seen:
            uniq.append(p)
            seen.add(p.resolve())
    return uniq


def read_flows_csv(csv_path: Path) -> pd.DataFrame:
    """Read a flows CSV robustly with pandas."""
    # low_memory=False to avoid mixed type warnings; engine='c' for speed
    df = pd.read_csv(csv_path, low_memory=False)
    return df


def clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Standardize column names by stripping spaces around names."""
    df = df.copy()
    df.columns = [c.strip() for c in df.columns]
    return df


def drop_irrelevant_columns(df: pd.DataFrame) -> Tuple[pd.DataFrame, List[str]]:
    """Drop columns like IPs, ports, IDs, timestamps.

    Returns the modified DataFrame and the list of actually dropped columns.
    """
    drop_candidates = [
        "Flow ID",
        "Src IP",
        "Dst IP",
        "Source IP",
        "Destination IP",
        "Src Port",
        "Dst Port",
        "Source Port",
        "Destination Port",
        "Timestamp",
        "SimillarHTTP",
        "SimiliarHTTP",
        "Flow Byts/s (raw)",  # occasionally seen
    ]
    existing_drops = [c for c in drop_candidates if c in df.columns]
    return df.drop(columns=existing_drops, errors="ignore"), existing_drops


def _replace_inf_with_nan(X):
    """Replace +/-inf with NaN on DataFrame or ndarray, preserving type when possible."""
    if isinstance(X, pd.DataFrame):
        return X.replace([np.inf, -np.inf], np.nan)
    X = np.asarray(X)
    X = X.copy()
    X[np.isinf(X)] = np.nan
    return X


def build_pipeline(X: pd.DataFrame) -> Tuple[ImbPipeline, List[str], List[str]]:
    """Build the preprocessing + SMOTE + XGBoost pipeline.

    Returns (pipeline, categorical_columns, numeric_columns)
    """
    # Identify categorical and numeric columns
    categorical_columns = [c for c in X.columns if X[c].dtype == "object"]
    numeric_columns = [c for c in X.columns if c not in categorical_columns]

    # Replace inf with nan globally; imputers will handle
    X = X.replace([np.inf, -np.inf], np.nan)

    # Preprocessors
    try:
        ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        # For older scikit-learn versions
        ohe = OneHotEncoder(handle_unknown="ignore", sparse=False)

    categorical_transformer = SkPipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", ohe),
        ]
    )
    numeric_transformer = SkPipeline(
        steps=[
            ("inf_to_nan", FunctionTransformer(_replace_inf_with_nan, validate=False)),
            ("imputer", SimpleImputer(strategy="median")),
        ]
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", categorical_transformer, categorical_columns),
            ("num", numeric_transformer, numeric_columns),
        ],
        remainder="drop",
    )

    # Classifier
    clf = XGBClassifier(
        n_estimators=300,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.8,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        objective="binary:logistic",
        eval_metric="logloss",
        n_jobs=os.cpu_count() or 4,
        tree_method="hist",
        random_state=42,
    )

    # Full pipeline with SMOTE applied only during fit
    pipeline = ImbPipeline(
        steps=[
            ("sanitize", FunctionTransformer(_replace_inf_with_nan, validate=False)),
            ("preprocess", preprocessor),
            ("smote", SMOTE(random_state=42)),
            ("clf", clf),
        ]
    )

    return pipeline, categorical_columns, numeric_columns


# -----------------------------
# Main training logic
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Treinar modelo de detecção de intrusão (BENIGN vs MALICIOUS)")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=str(Path.cwd()),
        help="Diretório contendo arquivos .pcap/.pcapng/.pcap_ISCX e/ou CSVs já extraídos",
    )
    parser.add_argument(
        "--features-dir",
        type=str,
        default="features",
        help="Diretório para salvar CSVs extraídos pelo CICFlowMeter",
    )
    parser.add_argument(
        "--model-path",
        type=str,
        default="intrusion_model.joblib",
        help="Caminho de saída do modelo treinado",
    )
    args = parser.parse_args()

    base_dir = Path(args.data_dir).resolve()
    features_dir = Path(args.features_dir).resolve()

    if not base_dir.exists():
        raise SystemExit(f"Diretório não encontrado: {base_dir}")

    # Detect CICFlowMeter command if needed
    cic_cmd = find_cicflowmeter_command()

    inputs = list_input_files(base_dir)
    if not inputs:
        raise SystemExit("Nenhum arquivo de entrada encontrado (.pcap, .pcapng, .pcap_ISCX, .pcap_ISCX.csv)")

    all_dfs: List[pd.DataFrame] = []
    labels: List[str] = []

    print(f"Encontrados {len(inputs)} arquivos de entrada.")

    for path in inputs:
        label = extract_label_from_filename(path)
        csv_path: Optional[Path] = None

        if path.suffix.lower() == ".csv":
            # Already a CSV (likely *pcap_ISCX.csv)
            csv_path = path
        else:
            # Need to extract flows using CICFlowMeter
            try:
                csv_path = ensure_cicflowmeter_csv(path, features_dir, cic_cmd)
            except RuntimeError as e:
                print(str(e))
                print("Pulando este arquivo por falha na extração...")
                continue

        try:
            df = read_flows_csv(csv_path)
            df = clean_columns(df)
            # Only set Label from filename if CSV has no valid Label column
            if ("Label" not in df.columns) or (not df["Label"].astype(str).str.strip().any()):
                df["Label"] = label
            all_dfs.append(df)
            labels.append(label)
            print(f"Carregado: {csv_path.name} (Label={label}, Linhas={len(df)})")
        except Exception as e:
            print(f"Falha ao ler {csv_path}: {e}. Pulando...")
            continue

    if not all_dfs:
        raise SystemExit("Nenhum CSV de fluxos válido foi processado.")

    data = pd.concat(all_dfs, ignore_index=True)
    print(f"Dataset combinado: {data.shape[0]} linhas, {data.shape[1]} colunas")

    # Drop irrelevant columns
    data, dropped_cols = drop_irrelevant_columns(data)

    # Separate features and labels
    if "Label" not in data.columns:
        raise SystemExit("Coluna 'Label' não encontrada após leitura dos CSVs.")

    X = data.drop(columns=["Label"], errors="ignore")
    y_text = data["Label"].astype(str)

    # Binary target mapping: BENIGN vs MALICIOUS
    y = np.where(y_text.str.upper().str.contains("BENIGN"), 0, 1)

    # Validate class presence
    unique_classes = np.unique(y)
    if unique_classes.size < 2:
        benign_count = int((y == 0).sum())
        malicious_count = int((y == 1).sum())
        raise SystemExit(
            "O dataset de treino contém apenas uma classe após o mapeamento (BENIGN vs MALICIOUS).\n"
            f"Contagens → BENIGN={benign_count}, MALICIOUS={malicious_count}.\n"
            "Verifique se seus CSVs possuem a coluna 'Label' com BENIGN e ataques.\n"
            "Caso esteja treinando a partir de PCAPs sem rótulo, inclua também dados BENIGN ou CSVs com rótulos."
        )

    # Pre-sanitize infinities before building pipeline/splitting
    X = _replace_inf_with_nan(X)

    # Build pipeline
    pipeline, cat_cols, num_cols = build_pipeline(X)

    # Train/test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Fit model
    print("Treinando o modelo (com SMOTE no conjunto de treino)...")
    pipeline.fit(X_train, y_train)

    # Evaluate
    print("Avaliando no conjunto de teste...")
    y_pred = pipeline.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["BENIGN", "MALICIOUS"]))
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    print("Matriz de confusão (linhas=verdadeiro, colunas=previsto):")
    print(cm)

    # Persist model + metadata in a single joblib artifact
    model_artifact = {
        "pipeline": pipeline,
        "dropped_columns": dropped_cols,
        "expected_feature_columns": list(X.columns),
        "categorical_columns": cat_cols,
        "numeric_columns": num_cols,
        "label_mapping": {0: "BENIGN", 1: "MALICIOUS"},
        "version": 1,
    }
    joblib.dump(model_artifact, args.model_path)
    print(f"Modelo salvo em: {args.model_path}")


if __name__ == "__main__":
    main() 