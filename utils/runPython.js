const { spawn } = require('child_process');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');

async function trySpawn(cmd, args, options) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { ...options, shell: false });
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (d) => (stdout += d.toString()))
    child.stderr.on('data', (d) => (stderr += d.toString()))

    child.on('error', (err) => reject({ err, stdout, stderr }));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

async function runWithPythonCommand(command, filePath) {
  const scriptPath = path.resolve(projectRoot, 'predict.py');
  const args = [scriptPath, '--model', 'intrusion_model.joblib', '--input', filePath, '--features-dir', 'features'];
  const { code, stdout, stderr } = await trySpawn(command, args, { cwd: projectRoot });
  return { code, stdout, stderr };
}

async function detectPythonCommand() {
  // Prefer 'python' on Windows, 'python3' on Linux/macOS, but try several
  const candidates = process.platform === 'win32'
    ? ['python', 'py', 'python3']
    : ['python3', 'python'];

  for (const cmd of candidates) {
    try {
      const { code } = await trySpawn(cmd, ['-V'], { cwd: projectRoot });
      if (code === 0) return cmd;
    } catch (_) {}
  }
  throw new Error('Python não encontrado no PATH. Instale Python 3.10+ e tente novamente.');
}

function safeNumber(str) {
  if (str == null) return null;
  const s = String(str).replace(',', '.');
  const v = Number(s);
  return Number.isFinite(v) ? v : null;
}

function parsePredictOutput(stdout) {
  const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  let flowsAnalyzed = null;
  let benign = null;
  let malicious = null;
  let maliciousPercent = null;

  for (const line of lines) {
    let m;
    // Flux count
    m = line.match(/^Fluxos analisados:\s*(\d+)/i);
    if (m) { flowsAnalyzed = Number(m[1]); continue; }

    // Counts
    m = line.match(/^BENIGN:\s*(\d+)\s*\|\s*MALICIOUS:\s*(\d+)/i);
    if (m) { benign = Number(m[1]); malicious = Number(m[2]); continue; }

    // Percent - be lenient (any number followed by % on the line)
    m = line.match(/([0-9]+(?:[.,][0-9]+)?)\s*%/);
    if (m) { maliciousPercent = safeNumber(m[1]); continue; }

    // Also try specific prefix without accent sensitivity
    m = line.match(/^Percentual de.*?:\s*([0-9]+(?:[.,][0-9]+)?)\s*%/i);
    if (m) { maliciousPercent = safeNumber(m[1]); continue; }
  }

  // Fallback: compute percent from counts
  if (maliciousPercent == null && benign != null && malicious != null) {
    const total = benign + malicious;
    if (total > 0) maliciousPercent = (malicious / total) * 100;
  }

  return { flowsAnalyzed, benign, malicious, maliciousPercent, raw: lines };
}

async function runPredict(filePath) {
  const py = await detectPythonCommand();
  let result = await runWithPythonCommand(py, filePath);

  // On Windows, 'py' needs '-3' to ensure Python 3 when default is Python 2 (rare today)
  if (result.code !== 0 && py === 'py') {
    result = await trySpawn('py', ['-3', path.resolve(projectRoot, 'predict.py'), '--model', 'intrusion_model.joblib', '--input', filePath, '--features-dir', 'features'], { cwd: projectRoot });
  }

  if (result.code !== 0) {
    const err = new Error('Falha ao executar predict.py');
    err.details = { exitCode: result.code, stderr: result.stderr, stdout: result.stdout };
    throw err;
  }

  const parsed = parsePredictOutput(result.stdout);
  return { file: path.basename(filePath), stdout: result.stdout, parsed };
}

module.exports = { runPredict }; 