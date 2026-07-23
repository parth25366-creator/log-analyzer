import React from 'react';
import { useNavigate } from 'react-router-dom';

function Navbar() {
  const navigate = useNavigate();
  return (
    <div style={{
      background: '#0f172a', borderBottom: '1px solid #1e293b',
      padding: '0 2rem', height: '56px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between'
    }}>
      <span
        onClick={() => navigate('/')}
        style={{ color: '#38bdf8', fontWeight: '600', fontSize: '16px', cursor: 'pointer', letterSpacing: '0.5px' }}
      >
        🔍 LogAnalyzer
      </span>
      <div style={{ display: 'flex', gap: '8px' }}>
        <a href="https://github.com/parth25366-creator/log-analyzer" target="_blank" rel="noreferrer"
          style={{ color: '#64748b', fontSize: '13px', textDecoration: 'none' }}>
          GitHub
        </a>
      </div>
    </div>
  );
}

export default Navbar;
