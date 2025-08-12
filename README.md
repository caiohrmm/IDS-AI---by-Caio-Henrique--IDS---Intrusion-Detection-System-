# IDS AI — by Caio Henrique (IDS = Intrusion Detection System)

## Detector de Intrusão por Fluxo (Python + XGBoost) e API (Node.js/Express)

⚡ Novo: Insights por IA (Gemini)

- A interface agora gera “Insights (IA)” com base nos resultados de análise, usando a API do Google Gemini.
- Foco em baixo custo: usa o modelo `gemini-1.5-flash` por padrão e respostas curtas (máx. ~6 bullets).
- Se a IA não estiver configurada, o frontend exibe insights padrão (fallback) sem interromper o fluxo.



### O que é
Este projeto implementa um classificador de tráfego de rede (por fluxo) treinado sobre features extraídas pelo CICFlowMeter (baseado no dataset CIC-IDS2017 e UNSW-NB15). O objetivo é classificar cada fluxo como BENIGN ou MALICIOUS e fornecer um resumo do percentual de tráfego malicioso.

Agora o projeto também inclui uma interface web (frontend) servida pela própria API, com upload via drag & drop, barra de progresso com velocidade/ETA, botão de cancelar, exibição de métricas, gráfico do tipo donut (BENIGN vs MALICIOUS) e uma seção de insights didáticos.

### Para que serve
- Você envia um arquivo `.pcap`, `.pcapng` ou um CSV de fluxos (`.pcap_ISCX.csv`/`.csv`) para a API.
- A API chama o script Python `predict.py`, que aplica o modelo `intrusion_model.joblib` e retorna:
  - Quantidade de fluxos analisados
  - Contagem BENIGN/MALICIOUS
  - Percentual de tráfego malicioso

### Principais componentes
- `train.py` (Python): treino do modelo (SMOTE + XGBoost) e avaliação.
- `predict.py` (Python): predição por fluxo com o modelo salvo (`intrusion_model.joblib`).
- `server.js` (Node.js / Express): servidor HTTP e servidor de arquivos estáticos do frontend.
- `routes/predict.js`: endpoint `POST /predict` com upload via `multer`.
- `utils/runPython.js`: executa o `predict.py` e faz parse da saída.
- `public/` (frontend):
  - `index.html`
  - `app.js`
  - `styles.css`

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

### Variáveis de ambiente (Insights por IA)
Para ativar os insights por IA (Gemini), crie um arquivo `.env` na raiz com:

```
GEMINI_API_KEY=SEU_TOKEN
GEMINI_MODEL=gemini-1.5-flash
```

Observações:
- Recomenda-se `gemini-1.5-flash` para reduzir custo de tokens.
- Sem `GEMINI_API_KEY`, o frontend usa os insights padrão (sem IA).

## Interface Web (Frontend)
- Acesse `http://localhost:3000/` no navegador com a API em execução.
- Arraste e solte um arquivo (ou clique para selecionar), depois clique em “Analisar”.
- O frontend exibe:
  - Progresso real de upload (porcentagem, velocidade, ETA, tempo decorrido) e botão “Cancelar”.
  - Status de envio e processamento no servidor.
  - Métricas: total de fluxos, contagens BENIGN/MALICIOUS e percentual malicioso.
  - Gráfico donut (Chart.js) com a distribuição BENIGN vs MALICIOUS.
  - Insights com recomendações e as estatísticas agregadas (arquivo, fluxos, etc.).
- Em caso de erro, a UI mostra a mensagem e, quando disponível, detalhes técnicos do Python (stderr/stdout) para depuração.

Observações:
- O frontend usa Chart.js via CDN. Se estiver sem internet, o gráfico pode não carregar; o restante da página funciona normalmente.
- Limite de upload: 1GB.
- Extensões aceitas: `.pcap`, `.pcapng`, `.pcap_ISCX`, `.pcap_ISCX.csv`, `.csv`.

Compatibilidade de dados: a inferência foi validada com CSVs de fluxo no padrão do **CICFlowMeter (CIC-IDS2017)** e com mapeamento de colunas do **UNSW-NB15**. Enviar outros formatos/colunas não suportados pode causar erros ou deteriorar a qualidade dos resultados. Para novos esquemas de features, ajuste o pré-processamento e considere **re-treinar** o modelo.

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

### Notas sobre o modelo e datasets
- O modelo (`intrusion_model.joblib`) deve estar na raiz do projeto para que a API e o frontend funcionem.
- O `train.py` aceita CSVs do CIC-IDS2017 e também do UNSW-NB15 (inclui normalização de rótulos e leitura robusta).
- Para treinos grandes, use `--no-smote` e `--max-samples` para controlar memória e tempo.

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
- `public/`
  - `index.html`
  - `app.js`
  - `styles.css`