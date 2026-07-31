import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import FileUpload from '../components/FileUpload';
import Navbar from '../components/Navbar';

function Home() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const handleAnalyze = async () => {
    if (!file) { setError('Please select a log file first'); return; }
    setError('');
    setLoading(true);
    try {
      const formData = new FormData();
      formData.append('logfile', file);
      const res = await axios.post(
        `${process.env.REACT_APP_API_URL || 'http://localhost:5001'}/api/logs/upload`,
        formData,
        { headers: { 'Content-Type': 'multipart/form-data' } }
      );
      navigate('/results', { state: { results: res.data } });
    } catch (err) {
      setError(err.response?.data?.error || 'Analysis failed. Try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', fontFamily: 'sans-serif' }}>
      <Navbar />
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 'calc(100vh - 56px)', padding: '2rem' }}>
        <div style={{ width: '100%', maxWidth: '600px' }}>
          <h1 style={{ color: '#f1f5f9', fontSize: '2rem', marginBottom: '0.5rem', textAlign: 'center' }}>🔍 Log Analyzer</h1>
          <p style={{ color: '#94a3b8', marginBottom: '2rem', textAlign: 'center' }}>Upload a server log file to detect suspicious activity</p>
          <FileUpload onFileSelect={setFile} />
          {error && <p style={{ color: '#f87171', fontSize: '13px', marginTop: '12px', textAlign: 'center' }}>{error}</p>}
          <button
            onClick={handleAnalyze}
            disabled={loading || !file}
            style={{
              marginTop: '1.5rem', width: '100%', padding: '12px',
              background: file ? '#3b82f6' : '#1e293b',
              color: file ? 'white' : '#475569',
              border: 'none', borderRadius: '8px',
              fontSize: '15px', cursor: file ? 'pointer' : 'not-allowed',
              fontWeight: '500', transition: 'all 0.2s'
            }}
          >
            {loading ? '⏳ Analyzing...' : 'Analyze Log File'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default Home;
