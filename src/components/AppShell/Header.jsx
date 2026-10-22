import React from 'react';
import { useAuth } from '../../context/AuthContext';

function Header() {
  const { user, logout } = useAuth();

  return (
    <header style={{
      height: '60px',
      backgroundColor: '#FFFFFF',
      borderBottom: '1px solid #D9D9D9',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 24px',
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      zIndex: 1000
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: '32px',
          height: '32px',
          backgroundColor: '#0076CE',
          borderRadius: '4px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#FFFFFF',
          fontWeight: 600,
          fontSize: '14px'
        }}>
          D
        </div>
        <span style={{
          fontSize: '16px',
          fontWeight: 600,
          color: '#202020'
        }}>
          Risk Assessment Tool
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '24px' }}>
        <div style={{
          flex: 1,
          maxWidth: '400px',
          position: 'relative'
        }}>
          <input
            type="text"
            placeholder="Search..."
            style={{
              width: '100%',
              padding: '8px 12px 8px 36px',
              fontSize: '14px',
              border: '1px solid #D9D9D9',
              borderRadius: '4px',
              backgroundColor: '#F7F8FA'
            }}
          />
          <svg
            width="16"
            height="16"
            viewBox="0 0 16 16"
            fill="none"
            style={{
              position: 'absolute',
              left: '12px',
              top: '50%',
              transform: 'translateY(-50%)',
              color: '#606060'
            }}
          >
            <path
              d="M7 12C9.76142 12 12 9.76142 12 7C12 4.23858 9.76142 2 7 2C4.23858 2 2 4.23858 2 7C2 9.76142 4.23858 12 7 12Z"
              stroke="currentColor"
              strokeWidth="1.5"
            />
            <path
              d="M11 11L14 14"
              stroke="currentColor"
              strokeWidth="1.5"
              strokeLinecap="round"
            />
          </svg>
        </div>

        <button style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: '#606060',
          padding: '8px',
          position: 'relative'
        }}>
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
            borderRadius: '50%'
          }}></span>
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
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
          <span style={{ fontSize: '14px', color: '#202020' }}>
            {user?.username || 'User'}
          </span>
          <button
            onClick={logout}
            style={{
              background: 'none',
              border: 'none',
              color: '#606060',
              cursor: 'pointer',
              fontSize: '13px',
              padding: '4px 8px'
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
