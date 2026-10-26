import React from 'react';
import { useAuth } from '../../context/AuthContext';
import SearchBar from './SearchBar';

function Header() {
  const { user, logout } = useAuth();

  return (
    <header style={{
      height: '56px',
      backgroundColor: '#FFFFFF',
      borderBottom: '1px solid #E0E0E0',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      zIndex: 1030,
      boxShadow: '0 1px 2px rgba(0, 0, 0, 0.04)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <img
          src="/assets/dell_logo.webp"
          alt="Dell Logo"
          style={{
            width: '36px',
            height: '36px',
            objectFit: 'contain'
          }}
        />
        <div>
          <span style={{
            fontSize: '16px',
            fontWeight: 600,
            color: '#1A1A1A',
            display: 'block',
            lineHeight: '1.25'
          }}>
            Risk Assessment Tool
          </span>
          <span style={{
            fontSize: '11px',
            color: '#5A5A5A',
            display: 'block',
            lineHeight: '1.25'
          }}>
            Third Party Risk Management
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <SearchBar />

        <button style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: '#5A5A5A',
          padding: '8px',
          position: 'relative',
          borderRadius: '6px',
          transition: 'background-color 100ms ease-in-out'
        }}
          onMouseEnter={(e) => e.target.style.backgroundColor = '#F5F7FA'}
          onMouseLeave={(e) => e.target.style.backgroundColor = 'transparent'}
        >
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
            <path
              d="M10 2C5.58172 2 2 5.58172 2 10C2 14.4183 5.58172 18 10 18C14.4183 18 18 14.4183 18 10C18 5.58172 14.4183 2 10 2Z"
              stroke="currentColor"
              strokeWidth="1.5"
            />
            <path
              d="M10 6V10H14"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
          <span style={{
            position: 'absolute',
            top: '6px',
            right: '6px',
            width: '8px',
            height: '8px',
            backgroundColor: '#D13438',
            borderRadius: '50%',
            border: '2px solid #FFFFFF'
          }}></span>
        </button>

        <div style={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: '12px',
          padding: '6px 12px',
          borderRadius: '6px',
          border: '1px solid #E0E0E0',
          backgroundColor: '#FFFFFF',
          transition: 'all 100ms ease-in-out'
        }}
          onMouseEnter={(e) => {
            e.target.style.borderColor = '#0076CE';
            e.target.style.boxShadow = '0 0 0 3px rgba(0, 118, 206, 0.1)';
          }}
          onMouseLeave={(e) => {
            e.target.style.borderColor = '#E0E0E0';
            e.target.style.boxShadow = 'none';
          }}
        >
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '50%',
            backgroundColor: '#0076CE',
            color: '#FFFFFF',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '14px',
            fontWeight: 600
          }}>
            {user?.username?.charAt(0).toUpperCase() || 'U'}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span style={{ fontSize: '13px', fontWeight: 500, color: '#1A1A1A', lineHeight: '1.25' }}>
              {user?.username || 'User'}
            </span>
            <span style={{ fontSize: '11px', color: '#8A8A8A', lineHeight: '1.25' }}>
              Administrator
            </span>
          </div>
          <button
            onClick={logout}
            style={{
              background: 'none',
              border: 'none',
              color: '#5A5A5A',
              cursor: 'pointer',
              fontSize: '12px',
              padding: '4px 8px',
              borderRadius: '4px',
              transition: 'all 100ms ease-in-out'
            }}
            onMouseEnter={(e) => {
              e.target.style.backgroundColor = '#F5F7FA';
              e.target.style.color = '#D13438';
            }}
            onMouseLeave={(e) => {
              e.target.style.backgroundColor = 'transparent';
              e.target.style.color = '#5A5A5A';
            }}
          >
            Sign Out
          </button>
        </div>
      </div>
    </header>
  );
}

export default Header;
