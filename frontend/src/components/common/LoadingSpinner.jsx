import React from 'react';

function LoadingSpinner({ message }) {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '60px',
      color: '#94a3b8'
    }}>
      <div className="spinner" />
      <p>{message || 'Loading...'}</p>
    </div>
  );
}

export default LoadingSpinner;
