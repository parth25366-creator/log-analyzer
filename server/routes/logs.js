const express = require('express');
const router = express.Router();
const upload = require('../utils/upload');

// POST /api/logs/upload
router.post('/upload', upload.single('logfile'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    res.status(200).json({
      message: 'File uploaded successfully',
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size
    });
  } catch (err) {
    res.status(500).json({ error: 'Upload failed' });
  }
});

module.exports = router;
