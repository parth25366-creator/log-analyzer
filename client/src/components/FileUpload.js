import React, { useState, useRef } from 'react';

function FileUpload({ onFileSelect }) {
  const [dragging, setDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const inputRef = useRef();

  const handleDragOver = (e) => {
    e.preventDefault();
    setDragging(true);
  };

  const handleDragLeave = () => setDragging(false);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  const handleFile = (file) => {
    setSelectedFile(file);
    if (onFileSelect) onFileSelect(file);
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={() => inputRef.current.click()}
      style={{
        background: dragging ? '#1e3a5f' : '#1e293b',
        border: `2px dashed ${dragging ? '#3b82f6' : '#334155'}`,
        borderRadius: '12px',
        padding: '3rem 4rem',
        textAlign: 'center',
        cursor: 'pointer',
        transition: 'all 0.2s'
      }}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".log,.txt"
        style={{ display: 'none' }}
        onChange={(e) => handleFile(e.target.files[0])}
      />
      <p style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📂</p>
      {selectedFile
        ? <p style={{ color: '#38bdf8', fontWeight: '500' }}>✅ {selectedFile.name}</p>
        : <p style={{ color: '#64748b' }}>Drop your log file here or click to upload</p>
      }
      <p style={{ color: '#475569', fontSize: '12px', marginTop: '8px' }}>Supports: .log, .txt</p>
    </div>
  );
}

export default FileUpload;
