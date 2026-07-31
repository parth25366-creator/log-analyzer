import React from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import Navbar from '../components/Navbar';

const alertColors = {
  'Brute Force': '#ef4444',
  'High Volume': '#f59e0b',
  'Scanner / Path Enumeration': '#a855f7'
};

function Results() {
  const location = useLocation();
  const navigate = useNavigate();
  const results = location.state?.results;

  if (!results) return (
    <div style={{ minHeight: '100vh', background: '#0f172a', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center' }}>
        <p style={{ color: '#94a3b8', marginBottom: '1rem' }}>No results found.</p>
        <button onClick={() => navigate('/')} style={backBtn}>← Go Back</button>
      </div>
    </div>
  );

  const { filename, totalLines, parsedEntries, summary, alerts } = results;

  return (
    <div style={{ minHeight: '100vh', background: '#0f172a', fontFamily: 'sans-serif' }}>
      <Navbar />
      <div style={{ maxWidth: '900px', margin: '0 auto', padding: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '2rem' }}>
          <div>
            <h1 style={{ color: '#f1f5f9', fontSize: '1.5rem' }}>📋 Analysis Results</h1>
            <p style={{ color: '#64748b', fontSize: '13px', marginTop: '4px' }}>{filename} · {totalLines} lines · {parsedEntries} parsed</p>
          </div>
          <button onClick={() => navigate('/')} style={backBtn}>← Analyze Another</button>
        </div>

        {/* Summary Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem', marginBottom: '2rem' }}>
          {[
            { label: 'Total Requests', value: summary.totalRequests, color: '#38bdf8' },
            { label: 'Unique IPs', value: summary.uniqueIPs, color: '#34d399' },
            { label: 'Total Errors', value: summary.totalErrors, color: '#f87171' },
            { label: 'Alerts Found', value: alerts.length, color: alerts.length > 0 ? '#f59e0b' : '#34d399' },
          ].map(card => (
            <div key={card.label} style={{ background: '#1e293b', borderRadius: '10px', padding: '1.25rem', border: '1px solid #334155' }}>
              <p style={{ color: '#64748b', fontSize: '12px', marginBottom: '6px' }}>{card.label}</p>
              <p style={{ color: card.color, fontSize: '1.75rem', fontWeight: '600' }}>{card.value}</p>
            </div>
          ))}
        </div>

        {/* Alerts */}
        <div style={{ background: '#1e293b', borderRadius: '10px', padding: '1.5rem', marginBottom: '2rem', border: '1px solid #334155' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '1rem', marginBottom: '1rem' }}>🚨 Suspicious Activity Detected</h2>
          {alerts.length === 0
            ? <p style={{ color: '#34d399' }}>✅ No suspicious activity detected.</p>
            : alerts.map((alert, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid #0f172a' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <span style={{ fontSize: '11px', padding: '3px 10px', borderRadius: '20px', background: alertColors[alert.type] + '22', color: alertColors[alert.type], fontWeight: '500' }}>{alert.type}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: '14px' }}>{alert.ip}</span>
                </div>
                <span style={{ color: '#64748b', fontSize: '13px' }}>{alert.count} occurrences</span>
              </div>
            ))
          }
        </div>

        {/* Top IPs */}
        <div style={{ background: '#1e293b', borderRadius: '10px', padding: '1.5rem', border: '1px solid #334155' }}>
          <h2 style={{ color: '#f1f5f9', fontSize: '1rem', marginBottom: '1rem' }}>📊 Top 5 IPs by Request Count</h2>
          {summary.top5IPs.map((item, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '12px', padding: '8px 0', borderBottom: '1px solid #0f172a' }}>
              <span style={{ color: '#64748b', fontSize: '12px', minWidth: '20px' }}>#{i + 1}</span>
              <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: '14px', flex: 1 }}>{item.ip}</span>
              <div style={{ background: '#0f172a', borderRadius: '4px', height: '6px', flex: 2, overflow: 'hidden' }}>
                <div style={{ background: '#3b82f6', height: '100%', width: `${(item.count / summary.top5IPs[0].count) * 100}%` }} />
              </div>
              <span style={{ color: '#64748b', fontSize: '13px', minWidth: '60px', textAlign: 'right' }}>{item.count} reqs</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

const backBtn = { padding: '8px 16px', background: '#1e293b', color: '#94a3b8', border: '1px solid #334155', borderRadius: '6px', cursor: 'pointer', fontSize: '13px' };

export default Results;
