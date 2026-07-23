const express = require('express');
const cors = require('cors');
require('dotenv').config();

const logsRoute = require('./routes/logs');

const app = express();
const PORT = process.env.PORT || 5001;

app.use(cors());
app.use(express.json());

app.use('/api/logs', logsRoute);

app.get('/', (req, res) => {
  res.json({ message: 'Log Analyzer API is running!' });
});

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
