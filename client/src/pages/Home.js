import React from 'react';

function Home() {
  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', fontFamily: 'sans-serif' }}>
      <h1 style={{ color: '#f1f5f9', fontSize: '2rem', marginBottom: '0.5rem' }}>🔍 Log Analyzer</h1>
      <p style={{ color: '#94a3b8', marginBottom: '2rem' }}>Upload a server log file to detect suspicious activity</p>
      <div style={{ background: '#1e293b', border: '2px dashed #334155', borderRadius: '12px', padding: '3rem 4rem', textAlign: 'center', cursor: 'pointer' }}>
        <p style={{ color: '#64748b', fontSize: '14px' }}>Drop your log file here or click to upload</p>
        <p style={{ color: '#475569', fontSize: '12px', marginTop: '8px' }}>Supports: .log, .txt</p>
      </div>
    </div>
  );
}

export default Home;
