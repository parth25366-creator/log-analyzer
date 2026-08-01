const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const upload = require('../utils/upload');
const { parseLine, detectBruteForce, detectHighVolume, detectScanner, detectRepeatedErrors, getSummary } = require('../utils/parser');

// POST /api/logs/upload
router.post('/upload', upload.single('logfile'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const filePath = path.join(__dirname, '../uploads', req.file.filename);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() !== '');

    // parse all lines
    const entries = lines.map(parseLine).filter(e => e !== null);

    // run all detections
    const bruteForce = detectBruteForce(entries);
    const highVolume = detectHighVolume(entries);
    const scanners = detectScanner(entries);
    const repeatedErrors = detectRepeatedErrors(entries);
    const summary = getSummary(entries);

    // combine all alerts
    const alerts = [...bruteForce, ...highVolume, ...scanners, ...repeatedErrors];

    // cleanup uploaded file
    fs.unlinkSync(filePath);

    res.status(200).json({
      filename: req.file.originalname,
      totalLines: lines.length,
      parsedEntries: entries.length,
      summary,
      alerts
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

module.exports = router;
