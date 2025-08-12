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


def normalize_labels_for_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize dataset-specific label columns to a unified 'Label' with BENIGN/MALICIOUS.

    - For CIC-IDS like CSVs: already have 'Label' (keep as is)
    - For UNSW-NB15: may have 'attack_cat' and/or 'label' (0/1). Convert to 'Label'.
    """
    df = df.copy()
    columns_lower = {c.lower(): c for c in df.columns}

    # If Label already present and non-empty, standardize string values
    if 'Label' in df.columns:
        df['Label'] = df['Label'].astype(str).str.strip()
        return df

    # UNSW: binary label in 'label' where 0 = normal, 1 = attack
    label_col = columns_lower.get('label')
    if label_col and df[label_col].dropna().shape[0] > 0:
        try:
            yb = pd.to_numeric(df[label_col], errors='coerce').fillna(0).astype(int)
            df['Label'] = yb.map({0: 'BENIGN', 1: 'MALICIOUS'})
            return df
        except Exception:
            pass

    # UNSW: attack category in 'attack_cat' (NaN or 'Normal' means benign)
    attack_cat_col = columns_lower.get('attack_cat')
    if attack_cat_col and attack_cat_col in df.columns:
        ac = df[attack_cat_col].astype(str).str.strip().str.lower()
        is_benign = (ac.isna()) | (ac.eq('nan')) | (ac.eq('normal')) | (ac.eq('benign'))
        df['Label'] = np.where(is_benign, 'BENIGN', 'MALICIOUS')
        return df

    # Fallback: no label column detected; leave as-is
    return df


def list_input_files(base_dir: Path) -> List[Path]:
    """List pcap-like inputs and CSVs (including generic CSVs for datasets like UNSW-NB15).

    Includes files with extensions: .pcap, .pcapng, .pcap_ISCX and CSVs (both *pcap_ISCX.csv and generic *.csv).
    """
    patterns = ["*.pcap", "*.pcapng", "*.pcap_ISCX", "*.pcap_ISCX.csv", "*.csv"]
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
    """Read a flows CSV robustly with pandas.

    - Tries UTF-8 then Latin-1 encodings
    - Detects headerless UNSW files and assigns official header
    """
    read_kwargs = dict(low_memory=False)
    try:
        df = pd.read_csv(csv_path, **read_kwargs)
    except UnicodeDecodeError:
        df = pd.read_csv(csv_path, encoding="latin1", **read_kwargs)

    # If looks like UNSW and missing label columns, try re-read as headerless with official columns
    lower_name = csv_path.name.lower()
    unsw_like = ("unsw" in lower_name and "nb15" in lower_name)
    has_label_cols = any(c.lower() in ("label", "attack_cat") for c in df.columns)
    if unsw_like and not has_label_cols:
        # Official UNSW-NB15 columns
        unsw_columns = [
            "id","dur","proto","service","state","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat","smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports","attack_cat","label"
        ]
        try:
            df2 = pd.read_csv(csv_path, header=None, names=unsw_columns, **read_kwargs)
            # Heuristic: accept only if column count matches
            if df2.shape[1] == len(unsw_columns):
                df = df2
        except Exception:
            pass

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
        # UNSW / common variants
        "srcip",
        "dstip",
        "sport",
        "dsport",
        "src_port",
        "dst_port",
        "id",
        "stid",
        "dtid",
        "ct_state_ttl",
        "StartTime",
        "LastTime",
        "stime",
        "ltime",
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


def _to_string_2d(X):
    """Convert a 2D array/dataframe to strings, preserving shape.

    Ensures OneHotEncoder gets uniform string dtype, avoiding mixed float/str errors.
    """
    if isinstance(X, pd.DataFrame):
        return X.astype("object").astype(str).fillna("")
    arr = np.asarray(X, dtype=object)
    # Convert nan/None to empty string, others to str
    def conv(v):
        if v is None:
            return ""
        try:
            if isinstance(v, float) and np.isnan(v):
                return ""
        except Exception:
            pass
        return str(v)
    vec = np.vectorize(conv, otypes=[str])
    return vec(arr)


def _to_numeric_2d(X):
    """Convert a 2D array/dataframe to numeric, coercing errors to NaN."""
    if isinstance(X, pd.DataFrame):
        return X.apply(pd.to_numeric, errors="coerce")
    df = pd.DataFrame(X)
    df = df.apply(pd.to_numeric, errors="coerce")
    return df.values


def build_pipeline(X: pd.DataFrame) -> Tuple[ImbPipeline, List[str], List[str]]:
    """Build the preprocessing + SMOTE + XGBoost pipeline.

    Returns (pipeline, categorical_columns, numeric_columns)
    """
    # Identify categorical and numeric columns, with robust typing
    # Heuristic: columns with small number of unique values relative to rows become categorical
    categorical_columns: List[str] = []
    numeric_columns: List[str] = []
    max_categorical_cardinality = 200  # avoid exploding OHE on high-card columns
    for col in X.columns:
        series = X[col]
        # Try numeric coercion first
        numeric_candidate = pd.to_numeric(series, errors="coerce")
        num_nans = numeric_candidate.isna().sum()
        num_total = len(series)
        num_unique = series.astype(str).nunique(dropna=True)
        is_mostly_numeric = (num_nans / max(1, num_total)) < 0.5
        if is_mostly_numeric and num_unique > max_categorical_cardinality:
            numeric_columns.append(col)
        else:
            # Treat as categorical if limited unique values or non-numeric
            if num_unique <= max_categorical_cardinality and num_unique > 1:
                categorical_columns.append(col)
            else:
                numeric_columns.append(col)

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
            ("to_str", FunctionTransformer(_to_string_2d, validate=False)),
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", ohe),
        ]
    )
    numeric_transformer = SkPipeline(
        steps=[
            ("inf_to_nan", FunctionTransformer(_replace_inf_with_nan, validate=False)),
            ("to_num", FunctionTransformer(_to_numeric_2d, validate=False)),
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
    parser.add_argument(
        "--no-smote",
        action="store_true",
        help="Desabilitar SMOTE (recomendado para datasets muito grandes)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=1000000,
        help="Número máximo de amostras para treino (amostragem aleatória estratificada). 0 para desabilitar",
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
            # Skip auxiliary UNSW files
            lower_name = path.name.lower()
            if lower_name.endswith("features.csv") or "list_events" in lower_name:
                print(f"Ignorando auxiliar: {path.name}")
                continue
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
            # Normalize dataset-specific columns to 'Label'
            df = normalize_labels_for_dataset(df)
            # If still missing, fallback to filename-derived label
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

    # Remove target-like leak columns from features
    X = data.drop(columns=["Label", "label", "attack_cat", "Attack_cat", "ATTACK_CAT"], errors="ignore")
    y_text = data["Label"].astype(str)

    # Binary target mapping: BENIGN vs MALICIOUS (robust)
    y_upper = y_text.str.upper().str.strip()
    y = np.where(y_upper.eq("BENIGN") | y_upper.eq("NORMAL") | y_upper.eq("BENIGNO"), 0, 1)

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

    # Optional downsampling to control memory (stratified)
    if args.max_samples and args.max_samples > 0 and len(X) > args.max_samples:
        print(f"Amostrando {args.max_samples} de {len(X)} exemplos para treino (estratificado)...")
        # Stratified sampling
        # Get indices per class
        rng = np.random.default_rng(42)
        idx = np.arange(len(X))
        mask = np.zeros(len(X), dtype=bool)
        for cls in [0, 1]:
            cls_idx = idx[y == cls]
            if cls_idx.size == 0:
                continue
            take = min(args.max_samples // 2, cls_idx.size)
            choose = rng.choice(cls_idx, size=take, replace=False)
            mask[choose] = True
        # If still under target due to class imbalance, fill up randomly
        need = args.max_samples - int(mask.sum())
        if need > 0:
            remain = idx[~mask]
            choose = rng.choice(remain, size=min(need, remain.size), replace=False)
            mask[choose] = True
        X = X.loc[mask].reset_index(drop=True)
        y = y[mask]
        print(f"Amostrado: {len(X)} linhas")

    # Pre-sanitize infinities before building pipeline/splitting
    X = _replace_inf_with_nan(X)

    # Build pipeline
    pipeline, cat_cols, num_cols = build_pipeline(X)

    # Optionally disable SMOTE for large datasets
    if args.no_smote or len(X) > 500_000:
        print("Desabilitando SMOTE para evitar estouro de memória...")
        steps = [(name, step) for name, step in pipeline.steps if name != "smote"]
        from imblearn.pipeline import Pipeline as ImbPipeline
        pipeline = ImbPipeline(steps=steps)

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