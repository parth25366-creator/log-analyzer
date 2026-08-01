const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const upload = require('../utils/upload');
const {
  detectFormat, parseLine,
  detectBruteForce, detectHighVolume, detectScanner, detectRepeatedErrors,
  getSummary
} = require('../utils/parser');

// POST /api/logs/upload
router.post('/upload', upload.single('logfile'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const filePath = path.join(__dirname, '../uploads', req.file.filename);
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n').filter(l => l.trim() !== '');

    // auto detect format
    const format = detectFormat(lines);

    // parse all lines using detected format
    const entries = lines.map(l => parseLine(l, format)).filter(e => e !== null);

    // run detections
    const alerts = [
      ...detectBruteForce(entries),
      ...detectHighVolume(entries),
      ...detectScanner(entries),
      ...detectRepeatedErrors(entries)
    ];

    const summary = getSummary(entries, format);

    // cleanup
    fs.unlinkSync(filePath);

    res.status(200).json({
      filename: req.file.originalname,
      totalLines: lines.length,
      parsedEntries: entries.length,
      format,
      summary,
      alerts
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: 'Analysis failed' });
  }
});

module.exports = router;
