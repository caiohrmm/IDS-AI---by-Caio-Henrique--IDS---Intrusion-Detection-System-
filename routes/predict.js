const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const { runPredict } = require('../utils/runPython');

const router = express.Router();

// Multer setup
const uploadsDir = path.resolve(__dirname, '..', 'uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    const safeName = file.originalname.replace(/[^a-zA-Z0-9_.-]/g, '_');
    cb(null, `${timestamp}__${safeName}`);
  },
});

const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    const name = String(file.originalname || '').toLowerCase();
    const allowed = [
      name.endsWith('.pcap'),
      name.endsWith('.pcapng'),
      name.endsWith('.pcap_iscx'),
      name.endsWith('.pcap_iscx.csv'),
      name.endsWith('.csv'),
    ].some(Boolean);
    if (allowed) return cb(null, true);
    return cb(new Error('Arquivo não suportado. Envie um .pcap, .pcapng, .pcap_ISCX, .pcap_ISCX.csv ou .csv'));
  },
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1GB
});

router.post('/', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Arquivo não enviado. Use campo form-data "file".' });
  }

  const uploadedPath = req.file.path;

  try {
    const result = await runPredict(uploadedPath);
    return res.json({ success: true, ...result });
  } catch (err) {
    const message = err && err.message ? err.message : 'Falha ao executar predição';
    return res.status(500).json({ success: false, error: message, details: err && err.details });
  } finally {
    // Cleanup uploaded file
    try { await fs.unlink(uploadedPath); } catch (e) {}
  }
});

module.exports = router; 