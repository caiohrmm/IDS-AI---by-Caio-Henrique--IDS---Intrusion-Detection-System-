# IDS AI — by Caio Henrique (IDS = Intrusion Detection System)

## Detector de Intrusão por Fluxo (Python + XGBoost) e API (Node.js/Express)



### O que é
Este projeto implementa um classificador de tráfego de rede (por fluxo) treinado sobre features extraídas pelo CICFlowMeter (baseado no dataset CIC-IDS2017). O objetivo é classificar cada fluxo como BENIGN ou MALICIOUS e fornecer um resumo do percentual de tráfego malicioso.

### Para que serve
- Você envia um arquivo `.pcap`, `.pcapng` ou um CSV de fluxos (`.pcap_ISCX.csv`/`.csv`) para a API.
- A API chama o script Python `predict.py`, que aplica o modelo `intrusion_model.joblib` e retorna:
  - Quantidade de fluxos analisados
  - Contagem BENIGN/MALICIOUS
  - Percentual de tráfego malicioso

### Principais componentes
- `train.py` (Python): treino do modelo (SMOTE + XGBoost) e avaliação.
- `predict.py` (Python): predição por fluxo com o modelo salvo (`intrusion_model.joblib`).
- `server.js` (Node.js / Express): servidor HTTP.
- `routes/predict.js`: endpoint `POST /predict` com upload via `multer`.
- `utils/runPython.js`: executa o `predict.py` e faz parse da saída.

## Datasets de teste e Modelo pré-treinado
Baixe os arquivos (datasets de teste e `intrusion_model.joblib`) no Google Drive e coloque o arquivo do modelo na raiz do projeto.

- Link (Google Drive): https://drive.google.com/drive/folders/1wcMc90GWXmECSsGqQiGeWrvAnn8lZXW0?usp=drive_link
- Após baixar, garanta que o arquivo do modelo se chama `intrusion_model.joblib` e esteja na pasta raiz do projeto.
- Os arquivos de dataset (por exemplo, `*pcap_ISCX.csv`) podem ser usados para testar a API.


Caso o link do Google Drive não seja direto (download com confirmação), baixe manualmente via navegador e coloque o arquivo na raiz do projeto.

## Requisitos
- Python 3.10+ disponível no PATH
- Node.js 16+
- Dependências Python para predição (ver `requirements.txt`)
- Para arquivos `.pcap`/`.pcapng`: CICFlowMeter acessível no PATH (opcional se usar somente CSVs de fluxos)

## Instalação (somente inferência: rodar a API)
1) Dependências Python:
```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
2) Dependências Node:
```bash
npm install
```
3) Baixe o `intrusion_model.joblib` (ver seção acima) e coloque-o na raiz do projeto.

## Executar a API
```bash
node server.js
```
A API escutará em `http://localhost:3000` (CORS liberado).

## Endpoint
### POST `/predict`
- Body: `form-data` com o campo `file` (tipo File)
- Arquivos aceitos: `.pcap`, `.pcapng`, `.pcap_ISCX`, `.pcap_ISCX.csv`, `.csv`
- Retorno: JSON com a saída do `predict.py` e campos parseados

Exemplo de requisição (PowerShell):
```powershell
# Use curl.exe para evitar o alias do PowerShell
curl.exe -X POST http://localhost:3000/predict -F file=@".\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
```

Exemplo de resposta:
```json
{
  "success": true,
  "file": "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
  "stdout": "Fluxos analisados: 170366\nBENIGN: 168098 | MALICIOUS: 2268\nPercentual de tráfego malicioso: 1.33%\n",
  "parsed": {
    "flowsAnalyzed": 170366,
    "benign": 168098,
    "malicious": 2268,
    "maliciousPercent": 1.33,
    "raw": [
      "Fluxos analisados: 170366",
      "BENIGN: 168098 | MALICIOUS: 2268",
      "Percentual de tráfego malicioso: 1.33%"
    ]
  }
}
```

### Notas importantes
- `.pcap`/`.pcapng`: o `predict.py` chamará o CICFlowMeter para extrair as features. Instale com `pip install cicflowmeter` e garanta que `cicflowmeter` está no PATH.
- `.csv`/`*pcap_ISCX.csv`: o `predict.py` usa diretamente as colunas (como no CIC-IDS2017), não requer CICFlowMeter.
- Se `Python não encontrado`: adicione `python` ao PATH (em Windows, o `py` também é suportado).
- Se erro de upload: confirme que o campo do formulário é `file` e o arquivo tem extensão aceita.

## Treino do modelo (opcional)
Caso queira (re)treinar o modelo localmente:
```bash
python train.py --data-dir "." --features-dir "features" --model-path "intrusion_model.joblib"
```
- O script lê `.pcap`/`.pcapng` (extrai features via CICFlowMeter) e/ou CSVs `*pcap_ISCX.csv`.
- Faz limpeza, One-Hot Encoding, imputação, SMOTE (apenas no treino) e treina XGBoost.
- Mostra métricas e salva `intrusion_model.joblib`.

## Versionamento e arquivos grandes
- O `.gitignore` já ignora `intrusion_model.joblib`, `features/`, `uploads/` e arquivos grandes (`*.pcap`, `.pcapng`, `.pcap_ISCX`, `*pcap_ISCX.csv`).
- Se precisar versionar binários grandes: avalie Git LFS, GitHub Releases, Hugging Face Hub, S3 ou similares.

## Estrutura do projeto
- `server.js`
- `routes/predict.js`
- `utils/runPython.js`
- `train.py`
- `predict.py`
- `requirements.txt`
- `package.json`
- `README.md`
- `.gitignore` 