const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const upload = require('../utils/upload');
const { parseLine, detectBruteForce, detectHighVolume, detectScanner, getSummary } = require('../utils/parser');

// POST /api/logs/upload
router.post('/upload', upload.single('logfile'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    // read file contents
    const filePath = path.join(__dirname, '../uploads', req.file.filename);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() !== '');

    // TODO: parse lines
    // TODO: run detections
    // TODO: return results

    res.status(200).json({
      message: 'File uploaded successfully',
      totalLines: lines.length,
      filename: req.file.originalname
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

module.exports = router;
