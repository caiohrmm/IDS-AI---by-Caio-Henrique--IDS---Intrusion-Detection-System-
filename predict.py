import argparse
import subprocess
from pathlib import Path
from typing import List, Optional

import joblib
import numpy as np
import pandas as pd


def _replace_inf_with_nan(X):
    if isinstance(X, pd.DataFrame):
        return X.replace([np.inf, -np.inf], np.nan)
    X = np.asarray(X)
    X = X.copy()
    X[np.isinf(X)] = np.nan
    return X


def _to_string_2d(X):
    """Mirror of training-time helper: convert categorical features to strings.
    Present here to allow unpickling of FunctionTransformer referencing this.
    """
    if isinstance(X, pd.DataFrame):
        return X.astype("object").astype(str).fillna("")
    arr = np.asarray(X, dtype=object)
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
    """Mirror of training-time helper: convert numeric-like features to floats.
    Present here to allow unpickling of FunctionTransformer referencing this.
    """
    if isinstance(X, pd.DataFrame):
        return X.apply(pd.to_numeric, errors="coerce")
    df = pd.DataFrame(X)
    df = df.apply(pd.to_numeric, errors="coerce")
    return df.values


def read_flows_csv(csv_path: Path) -> pd.DataFrame:
    """Robust CSV reader for prediction.

    - Tries UTF-8 then Latin-1
    - If UNSW headerless, re-read with official UNSW columns
    """
    read_kwargs = dict(low_memory=False)
    try:
        df = pd.read_csv(csv_path, **read_kwargs)
    except UnicodeDecodeError:
        df = pd.read_csv(csv_path, encoding="latin1", **read_kwargs)

    lower_name = csv_path.name.lower()
    unsw_like = ("unsw" in lower_name and "nb15" in lower_name)
    has_label_cols = any(c.lower() in ("label", "attack_cat") for c in df.columns)
    # Heuristic: if UNSW-like and missing typical columns, consider it headerless
    typical_cols = {"proto", "service", "state", "spkts", "dpkts"}
    has_typical = any(c.lower() in typical_cols for c in df.columns)
    if unsw_like and (not has_label_cols or not has_typical):
        unsw_columns = [
            "id","dur","proto","service","state","spkts","dpkts","sbytes","dbytes","rate","sttl","dttl","sload","dload","sloss","dloss","sinpkt","dinpkt","sjit","djit","swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat","smean","dmean","trans_depth","response_body_len","ct_srv_src","ct_state_ttl","ct_dst_ltm","ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm","is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd","ct_src_ltm","ct_srv_dst","is_sm_ips_ports","attack_cat","label"
        ]
        try:
            df2 = pd.read_csv(csv_path, header=None, names=unsw_columns, **read_kwargs)
            if df2.shape[1] == len(unsw_columns):
                df = df2
        except Exception:
            pass

    df.columns = [c.strip() for c in df.columns]
    return df


def find_cicflowmeter_command() -> Optional[List[str]]:
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


def ensure_flows_csv(input_path: Path, output_dir: Path, cic_cmd: Optional[List[str]]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_name = f"{input_path.stem}_flows.csv"
    out_csv = output_dir / csv_name
    if out_csv.exists():
        return out_csv
    if cic_cmd is None:
        raise RuntimeError(
            "CICFlowMeter não encontrado no PATH. Instale com 'pip install cicflowmeter' ou adicione ao PATH."
        )
    cmd = cic_cmd + ["-f", str(input_path), "-c", str(out_csv)]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError(
            f"Falha ao executar CICFlowMeter para {input_path.name}.\nComando: {' '.join(cmd)}\nSaída:\n{completed.stdout}\nErro:\n{completed.stderr}"
        )
    if not out_csv.exists():
        raise RuntimeError(f"CSV esperado não foi gerado: {out_csv}")
    return out_csv


def main():
    parser = argparse.ArgumentParser(description="Predizer percentual de tráfego malicioso em um arquivo de rede")
    parser.add_argument("--model", type=str, default="intrusion_model.joblib", help="Caminho do modelo treinado")
    parser.add_argument("--input", type=str, required=True, help="Arquivo de entrada (.pcap/.pcapng/.pcap_ISCX ou CSV de fluxos)")
    parser.add_argument(
        "--features-dir", type=str, default="features", help="Diretório para salvar CSVs extraídos (se necessário)"
    )
    args = parser.parse_args()

    model_artifact = joblib.load(args.model)
    pipeline = model_artifact["pipeline"]
    dropped_columns = set(model_artifact.get("dropped_columns", []))
    expected_columns = list(model_artifact.get("expected_feature_columns", []))
    label_mapping = model_artifact.get("label_mapping", {0: "BENIGN", 1: "MALICIOUS"})

    input_path = Path(args.input).resolve()
    if not input_path.exists():
        raise SystemExit(f"Arquivo não encontrado: {input_path}")

    # Determine CSV of flows
    if input_path.suffix.lower() == ".csv":
        csv_path = input_path
    else:
        cic_cmd = find_cicflowmeter_command()
        csv_path = ensure_flows_csv(input_path, Path(args.features_dir).resolve(), cic_cmd)

    # Load flows
    df = read_flows_csv(csv_path)

    # Drop irrelevant columns used during training
    for col in dropped_columns:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    # Align to expected columns from training; fill missing with NaN
    X = df.reindex(columns=expected_columns, fill_value=np.nan)

    # Replace infinities with NaN
    X = X.replace([np.inf, -np.inf], np.nan)

    # Ensure dtypes consistent with training pipeline expectations
    # Categorical features will be converted to strings inside pipeline; numeric coerced to floats

    # Predict probabilities and classes
    if hasattr(pipeline, "predict_proba"):
        proba = pipeline.predict_proba(X)
        # Assume binary with classes [0,1]
        malicious_prob = proba[:, 1]
    else:
        # Fallback: use decision function if available
        y_dec = pipeline.decision_function(X)
        # Convert logits to probabilities via sigmoid
        malicious_prob = 1 / (1 + np.exp(-y_dec))

    y_pred = (malicious_prob >= 0.5).astype(int)

    total = len(y_pred)
    malicious = int(y_pred.sum())
    benign = int(total - malicious)
    pct_malicious = 100.0 * malicious / total if total > 0 else 0.0

    print(f"Fluxos analisados: {total}")
    print(f"BENIGN: {benign} | MALICIOUS: {malicious}")
    print(f"Percentual de tráfego malicioso: {pct_malicious:.2f}%")


if __name__ == "__main__":
    main() 