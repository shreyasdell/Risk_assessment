import React from 'react';

function PageHeader({ title, description, primaryAction, primaryActionLabel, onPrimaryAction }) {
  return (
    <div style={{ marginBottom: '32px' }}>
      <h1 style={{
        fontSize: '24px',
        fontWeight: 600,
        color: '#202020',
        marginBottom: '8px',
        margin: 0
      }}>
        {title}
      </h1>
      {description && (
        <p style={{
          fontSize: '14px',
          color: '#606060',
          marginBottom: '16px',
          margin: '0 0 16px 0'
        }}>
          {description}
        </p>
      )}
      {primaryAction && (
        <button
          onClick={onPrimaryAction}
          style={{
            backgroundColor: '#0076CE',
            color: '#FFFFFF',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '4px',
            fontSize: '14px',
            fontWeight: 500,
            cursor: 'pointer'
          }}
        >
          {primaryActionLabel || primaryAction}
        </button>
      )}
    </div>
  );
}

export default PageHeader;
