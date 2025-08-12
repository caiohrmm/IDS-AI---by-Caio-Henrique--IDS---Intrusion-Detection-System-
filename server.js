const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

// Ensure uploads directory exists
const uploadsDir = path.resolve(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

const app = express();
app.use(cors()); // Allow all origins
app.use(express.json());

// Serve static frontend if available
const publicDir = path.resolve(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
}

const predictRouter = require('./routes/predict');
app.use('/predict', predictRouter);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
}); 