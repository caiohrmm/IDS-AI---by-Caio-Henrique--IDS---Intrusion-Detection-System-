const form = document.getElementById('upload-form');
const fileInput = document.getElementById('file-input');
const dropzone = document.getElementById('dropzone');
const dropzoneLabel = document.getElementById('dropzone-label');
const fileInfo = document.getElementById('file-info');
const submitBtn = document.getElementById('submit-btn');
const cancelBtn = document.getElementById('cancel-btn');
const statusEl = document.getElementById('status');
const progressEl = document.getElementById('progress');
const progressFill = document.getElementById('progress-fill');
const progressPercent = document.getElementById('progress-percent');
const progressSpeed = document.getElementById('progress-speed');
const progressEta = document.getElementById('progress-eta');
const progressElapsed = document.getElementById('progress-elapsed');
const resultEl = document.getElementById('result');
const errorEl = document.getElementById('error');
const resultsWrap = document.getElementById('results-wrap');
const chartArea = document.getElementById('chart-area');
const insightsEl = document.getElementById('insights');
let chartInstance = null;

function show(el) { el.classList.remove('hidden'); }
function hide(el) { el.classList.add('hidden'); }
function resetViews() { hide(progressEl); hide(resultsWrap); hide(resultEl); hide(errorEl); hide(statusEl); hide(chartArea); hide(insightsEl); progressFill.style.width = '0%'; progressPercent.textContent = '0%'; progressSpeed.textContent = '0 MB/s'; progressEta.textContent = 'ETA —'; progressElapsed.textContent = 'Tempo: 0s'; resultEl.innerHTML = ''; errorEl.textContent = ''; insightsEl.innerHTML = ''; if (chartInstance) { chartInstance.destroy(); chartInstance = null; } }

function humanPercent(p) {
  if (p == null || Number.isNaN(p)) return '-';
  return `${p.toFixed(2)}%`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let val = bytes;
  while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
  return `${val.toFixed(val >= 100 ? 0 : 2)} ${units[i]}`;
}

function renderError(message, details) {
  const hasDetails = details && (details.stderr || details.stdout || details.exitCode);
  errorEl.innerHTML = hasDetails
    ? `${message}<details style="margin-top:8px"><summary>Detalhes</summary><pre style="white-space:pre-wrap">${(details.stderr || details.stdout || '').trim()}</pre></details>`
    : message;
  show(errorEl);
}

function renderResult(data) {
  const parsed = data.parsed || {};
  const lines = (parsed.raw || []).map(l => `<code>${l}</code>`).join('<br/>');
  const maliciousPercent = parsed.maliciousPercent != null ? parsed.maliciousPercent : (parsed.malicious && parsed.benign ? (parsed.malicious / (parsed.malicious + parsed.benign)) * 100 : null);

  const statusClass = maliciousPercent != null && maliciousPercent >= 5 ? 'badge-danger' : (maliciousPercent != null && maliciousPercent > 0 ? 'badge-warn' : 'badge-ok');
  const statusText = maliciousPercent == null ? 'Desconhecido' : (maliciousPercent >= 5 ? 'ALTO' : (maliciousPercent > 0 ? 'BAIXO' : 'NENHUM'));

  resultEl.innerHTML = `
    <div class="summary">
      <div class="metric">
        <span class="label">Arquivo</span>
        <span class="value">${data.file || '-'}</span>
      </div>
      <div class="metric">
        <span class="label">Fluxos analisados</span>
        <span class="value">${parsed.flowsAnalyzed ?? '-'}</span>
      </div>
      <div class="metric">
        <span class="label">BENIGN</span>
        <span class="value">${parsed.benign ?? '-'}</span>
      </div>
      <div class="metric">
        <span class="label">MALICIOUS</span>
        <span class="value">${parsed.malicious ?? '-'}</span>
      </div>
      <div class="metric">
        <span class="label">% Malicioso</span>
        <span class="value ${statusClass}">${humanPercent(maliciousPercent)}</span>
      </div>
    </div>
    <details class="raw">
      <summary>Ver saída completa</summary>
      <div class="raw-lines">${lines || '<em>Sem saída</em>'}</div>
    </details>
  `;
  show(resultsWrap);

  // Render donut chart if we have counts
  if (typeof parsed.benign === 'number' && typeof parsed.malicious === 'number') {
    show(chartArea);
    const ctx = document.getElementById('dist-chart').getContext('2d');
    chartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['BENIGN', 'MALICIOUS'],
        datasets: [{
          data: [parsed.benign, parsed.malicious],
          backgroundColor: ['#10b981', '#ef4444'],
          borderColor: ['rgba(16,185,129,0.9)', 'rgba(239,68,68,0.9)'],
          borderWidth: 1,
          hoverOffset: 8,
        }]
      },
      options: {
        plugins: {
          legend: { labels: { color: '#e5e7eb' } },
          tooltip: {
            callbacks: {
              label: (context) => {
                const label = context.label || '';
                const value = context.parsed || 0;
                const total = (parsed.benign + parsed.malicious) || 1;
                const pct = (value / total) * 100;
                return `${label}: ${value.toLocaleString()} (${pct.toFixed(2)}%)`;
              }
            }
          }
        },
        cutout: '60%',
        animation: { animateRotate: true, animateScale: true },
      }
    });
  }

  // Insights section
  const tips = [];
  if (maliciousPercent != null) {
    if (maliciousPercent === 0) {
      tips.push('Nenhum tráfego malicioso detectado. Continue monitorando regularmente.');
    } else if (maliciousPercent < 1) {
      tips.push('Baixo percentual malicioso. Verifique hosts com maior volume para garantir ausência de falsos positivos.');
    } else if (maliciousPercent < 5) {
      tips.push('Atenção: percentual moderado de tráfego malicioso. Considere isolar fluxos suspeitos para inspeção.');
    } else {
      tips.push('ALERTA: percentual alto de tráfego malicioso. Aplique contenção (bloqueio ACL/Firewall) e investigue IOC imediatamente.');
    }
  }
  tips.push('Garanta que o modelo e as features correspondem ao ambiente atual (versões e colunas).');
  tips.push('Para arquivos PCAP, verifique se o CICFlowMeter está instalado e funcionando (PATH).');

  const totalFlows = (typeof parsed.flowsAnalyzed === 'number') ? parsed.flowsAnalyzed : ((parsed.benign || 0) + (parsed.malicious || 0));
  const statsHtml = `
    <div class="stats-grid">
      <div class="stat"><span class="label">Fluxos analisados</span><span class="value">${totalFlows.toLocaleString()}</span></div>
      <div class="stat"><span class="label">BENIGN</span><span class="value">${(parsed.benign ?? 0).toLocaleString()}</span></div>
      <div class="stat"><span class="label">MALICIOUS</span><span class="value">${(parsed.malicious ?? 0).toLocaleString()}</span></div>
      <div class="stat"><span class="label">% Malicioso</span><span class="value">${humanPercent(maliciousPercent ?? 0)}</span></div>
    </div>
  `;

  insightsEl.innerHTML = `
    <h3>Insights</h3>
    <p>Interpretação rápida dos resultados e próximos passos sugeridos.</p>
    ${statsHtml}
    <div class="tips">
      ${tips.map(t => `<div class="tip">${t}</div>`).join('')}
    </div>
  `;
  show(insightsEl);
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  resetViews();

  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    errorEl.textContent = 'Selecione um arquivo antes de analisar.';
    show(errorEl); return;
  }

  // Client-side validation
  const allowed = [/\.pcap$/i, /\.pcapng$/i, /\.pcap_iscx$/i, /\.pcap_iscx\.csv$/i, /\.csv$/i];
  const isAllowed = allowed.some((re) => re.test(file.name));
  if (!isAllowed) {
    renderError('Arquivo não suportado. Envie um .pcap, .pcapng, .pcap_ISCX, .pcap_ISCX.csv ou .csv');
    return;
  }
  const maxBytes = 1024 * 1024 * 1024; // 1GB
  if (file.size > maxBytes) {
    renderError(`Arquivo muito grande (${formatBytes(file.size)}). Limite: ${formatBytes(maxBytes)}.`);
    return;
  }

  // Show file info and prepare progress
  const formatMB = (bytes) => (bytes / 1024 / 1024).toFixed(2);
  const fileName = file.name;
  const fileSizeMB = formatMB(file.size);
  fileInfo.innerHTML = `<strong>Arquivo:</strong> ${fileName} • ${fileSizeMB} MB`;
  show(fileInfo);

  submitBtn.disabled = true;
  cancelBtn.classList.remove('hidden');
  show(progressEl);
  show(statusEl);
  statusEl.textContent = 'Enviando arquivo...';

  try {
    const data = new FormData();
    data.append('file', file);

    // Build XMLHttpRequest to get upload progress
    const xhr = new XMLHttpRequest();
    const startedAt = Date.now();
    let lastLoaded = 0;
    let lastTime = startedAt;

    const updateElapsed = () => {
      const elapsedSec = Math.max(0, Math.round((Date.now() - startedAt) / 1000));
      progressElapsed.textContent = `Tempo: ${elapsedSec}s`;
    };
    const elapsedTimer = setInterval(updateElapsed, 1000);

    xhr.upload.onprogress = (evt) => {
      if (!evt.lengthComputable) return;
      const percent = Math.round((evt.loaded / evt.total) * 100);
      progressFill.style.width = `${percent}%`;
      progressPercent.textContent = `${percent}%`;

      const now = Date.now();
      const deltaBytes = evt.loaded - lastLoaded;
      const deltaTime = (now - lastTime) / 1000;
      if (deltaTime > 0) {
        const speedMBs = (deltaBytes / 1024 / 1024) / deltaTime;
        progressSpeed.textContent = `${speedMBs.toFixed(2)} MB/s`;
        const remainingBytes = evt.total - evt.loaded;
        const etaSec = speedMBs > 0 ? Math.round((remainingBytes / 1024 / 1024) / speedMBs) : Infinity;
        progressEta.textContent = Number.isFinite(etaSec) ? `ETA ${etaSec}s` : 'ETA —';
      }
      lastLoaded = evt.loaded;
      lastTime = now;
    };

    xhr.upload.onload = () => {
      // Upload finished, now server is processing
      statusEl.textContent = 'Arquivo enviado. Processando no servidor...';
    };

    xhr.onreadystatechange = async () => {
      if (xhr.readyState === XMLHttpRequest.DONE) {
        clearInterval(elapsedTimer);
        cancelBtn.classList.add('hidden');
        statusEl.textContent = 'Processando no servidor...';

        try {
          const resOk = xhr.status >= 200 && xhr.status < 300;
          let json = {};
          try { json = JSON.parse(xhr.responseText || '{}'); } catch (_) { }
          if (!resOk || json.success === false) {
            const message = (json && json.error) ? json.error : `Falha (${xhr.status})`;
            renderError(message, json && json.details);
            return;
          }
          statusEl.textContent = 'Análise concluída.';
          renderResult(json);
        } finally {
          submitBtn.disabled = false;
          hide(progressEl);
          hide(statusEl);
        }
      }
    };

    xhr.onerror = () => {
      submitBtn.disabled = false;
      hide(progressEl);
      hide(statusEl);
      cancelBtn.classList.add('hidden');
      errorEl.textContent = 'Erro de rede ao enviar o arquivo.';
      show(errorEl);
    };

    xhr.onabort = () => {
      submitBtn.disabled = false;
      hide(progressEl);
      hide(statusEl);
      cancelBtn.classList.add('hidden');
      errorEl.textContent = 'Envio cancelado pelo usuário.';
      show(errorEl);
    };

    cancelBtn.onclick = () => {
      try { xhr.abort(); } catch (_) { }
    };

    xhr.open('POST', '/predict');
    xhr.send(data);
  } catch (err) {
    errorEl.textContent = err.message || 'Erro inesperado.';
    show(errorEl);
  } finally {
    // Restabelecido nos handlers específicos
  }
});

// Drag & drop
['dragenter', 'dragover'].forEach(evt => dropzone.addEventListener(evt, (e) => {
  e.preventDefault(); e.stopPropagation();
  dropzone.classList.add('drag');
}));
['dragleave', 'drop'].forEach(evt => dropzone.addEventListener(evt, (e) => {
  e.preventDefault(); e.stopPropagation();
  dropzone.classList.remove('drag');
}));

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('drop', (e) => {
  const files = e.dataTransfer.files;
  if (files && files[0]) {
    fileInput.files = files;
    dropzoneLabel.textContent = 'Arquivo selecionado';
    fileInfo.innerHTML = `<strong>Arquivo:</strong> ${files[0].name} • ${(files[0].size / 1024 / 1024).toFixed(2)} MB`;
    show(fileInfo);
  }
});

fileInput.addEventListener('change', () => {
  const file = fileInput.files && fileInput.files[0];
  if (file) {
    dropzoneLabel.textContent = 'Arquivo selecionado';
    fileInfo.innerHTML = `<strong>Arquivo:</strong> ${file.name} • ${(file.size / 1024 / 1024).toFixed(2)} MB`;
    show(fileInfo);
  } else {
    dropzoneLabel.textContent = 'Arraste e solte seu arquivo aqui ou clique para selecionar';
    hide(fileInfo);
  }
});


