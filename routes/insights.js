const express = require('express');
const https = require('https');

const router = express.Router();

function callGemini(apiKey, model, prompt) {
  const endpoint = `/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

  const payload = JSON.stringify({
    contents: [
      {
        role: 'user',
        parts: [{ text: prompt }],
      },
    ],
    generationConfig: {
      temperature: 0.2,
      topK: 20,
      topP: 0.9,
      maxOutputTokens: 320,
    },
  });

  const options = {
    hostname: 'generativelanguage.googleapis.com',
    port: 443,
    path: endpoint,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'x-goog-api-key': apiKey,
    },
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => {
        try {
          const json = JSON.parse(data || '{}');
          const candidate = json.candidates && json.candidates[0];
          const parts = candidate && candidate.content && candidate.content.parts;
          let text = '';
          if (Array.isArray(parts)) {
            text = parts
              .map((p) => (p && (p.text || p.inlineData || p.functionCall) ? (p.text || '') : ''))
              .filter(Boolean)
              .join('\n');
          }
          if (!text) {
            // Graceful fallback text to avoid hard error
            text = '- Não foi possível gerar insights de IA neste momento. Use as recomendações padrão.';
          }
          resolve(text);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

router.post('/', async (req, res) => {
  try {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(503).json({ success: false, error: 'GEMINI_API_KEY não configurada no servidor.' });
    }

    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
    const body = req.body || {};
    const parsed = body.parsed || {};
    const file = body.file || '-';

    const benign = Number(parsed.benign || 0);
    const malicious = Number(parsed.malicious || 0);
    const flowsAnalyzed = Number(parsed.flowsAnalyzed || benign + malicious || 0);
    const maliciousPercent = Number(
      parsed.maliciousPercent != null
        ? parsed.maliciousPercent
        : flowsAnalyzed > 0
        ? (malicious / Math.max(1, flowsAnalyzed)) * 100
        : 0
    );

    const prompt = `Você é um analista de segurança. Gere insights concisos e econômicos em tokens (máx. ~6 bullets) com base nestes resultados de classificação de fluxos de rede.

Arquivo: ${file}
Fluxos analisados: ${flowsAnalyzed}
BENIGN: ${benign}
MALICIOUS: ${malicious}
% Malicioso: ${maliciousPercent.toFixed(2)}%
Base do modelo: CIC-IDS2017 + UNSW-NB15 (features CICFlowMeter)

Requisitos da resposta (máx. ~6 bullets, português):
- Avaliação do risco geral do tráfego
- Possíveis causas e limitações (viés, qualidade dos dados, FP/FN)
- Próximos passos práticos (investigação, contenção, coleta de evidências)
- Dicas de melhoria do dataset/modelo quando aplicável
Formate como lista de bullets curtos (sem preâmbulo, sem desculpas).`;

    const text = await callGemini(apiKey, model, prompt);
    return res.json({ success: true, insights: text });
  } catch (err) {
    const message = err && err.message ? err.message : 'Falha ao gerar insights de IA';
    console.warn('Insights IA erro:', message);
    // Responder 200 para permitir UI sinalizar fallback
    return res.json({ success: false, error: message });
  }
});

module.exports = router;


