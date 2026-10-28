import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { loginUser, getCurrentUser } from '../api/client';
import dellLogo from '../assets/newlogo.png';

function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await loginUser({ username, password });
      const { access_token } = response.data;

      // Fetch user data after successful login
      const userResponse = await getCurrentUser();
      login(access_token, userResponse.data);
      navigate('/dashboard');
    } catch (err) {
      console.error('Login error:', err);
      if (err.response && err.response.status === 401) {
        setError('Invalid username or password.');
      } else if (err.response && err.response.data && err.response.data.detail) {
        const detail = err.response.data.detail;
        if (Array.isArray(detail) && detail.length > 0) {
          setError(typeof detail[0].msg === 'string' ? detail[0].msg : 'Invalid login data');
        } else if (typeof detail === 'string') {
          setError(detail);
        } else {
          setError('Invalid login data');
        }
      } else {
        setError('Unable to connect to the server.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      backgroundColor: '#F5F7FA',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '24px'
    }}>
      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '12px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.12)',
        width: '100%',
        maxWidth: '420px',
        overflow: 'hidden'
      }}>
        {/* Header */}
        <div style={{
          backgroundColor: '#0076CE',
          padding: '32px 32px 24px 32px',
          textAlign: 'center'
        }}>
          <img
            src={dellLogo}
            alt="Dell Logo"
            style={{
              width: '150px',
              height: 'auto',
              margin: '0 auto 16px',
              display: 'block'
            }}
          />
          <h1 style={{
            fontSize: '24px',
            fontWeight: 600,
            color: '#FFFFFF',
            margin: '0 0 8px 0',
            lineHeight: '1.25'
          }}>
            Risk Assessment Tool
          </h1>
          <p style={{
            fontSize: '13px',
            color: 'rgba(255, 255, 255, 0.9)',
            margin: 0,
            lineHeight: '1.5'
          }}>
            Third Party Risk Management
          </p>
        </div>

        {/* Form */}
        <div style={{ padding: '32px' }}>
          {error && (
            <div style={{
              backgroundColor: '#FDE8E8',
              border: '1px solid #D13438',
              borderRadius: '6px',
              padding: '12px 16px',
              marginBottom: '24px',
              fontSize: '13px',
              color: '#A4262A',
              lineHeight: '1.5'
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '20px' }}>
              <label style={{
                display: 'block',
                marginBottom: '8px',
                fontSize: '13px',
                fontWeight: 500,
                color: '#1A1A1A',
                lineHeight: '1.5'
              }}>
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  fontSize: '14px',
                  border: '1px solid #E0E0E0',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  color: '#1A1A1A',
                  transition: 'all 100ms ease-in-out',
                  outline: 'none'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#0076CE';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0, 118, 206, 0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#E0E0E0';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            <div style={{ marginBottom: '24px' }}>
              <label style={{
                display: 'block',
                marginBottom: '8px',
                fontSize: '13px',
                fontWeight: 500,
                color: '#1A1A1A',
                lineHeight: '1.5'
              }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                style={{
                  width: '100%',
                  padding: '12px 16px',
                  fontSize: '14px',
                  border: '1px solid #E0E0E0',
                  borderRadius: '6px',
                  backgroundColor: '#FFFFFF',
                  color: '#1A1A1A',
                  transition: 'all 100ms ease-in-out',
                  outline: 'none'
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = '#0076CE';
                  e.target.style.boxShadow = '0 0 0 3px rgba(0, 118, 206, 0.1)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = '#E0E0E0';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                backgroundColor: loading ? '#005A8C' : '#0076CE',
                color: '#FFFFFF',
                border: 'none',
                padding: '14px 24px',
                borderRadius: '6px',
                fontSize: '14px',
                fontWeight: 600,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition: 'all 100ms ease-in-out',
                outline: 'none'
              }}
              onMouseEnter={(e) => {
                if (!loading) {
                  e.target.style.backgroundColor = '#005A8C';
                }
              }}
              onMouseLeave={(e) => {
                if (!loading) {
                  e.target.style.backgroundColor = '#0076CE';
                }
              }}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          {/* Footer */}
          <div style={{
            marginTop: '24px',
            paddingTop: '24px',
            borderTop: '1px solid #F0F0F0',
            textAlign: 'center'
          }}>
            <p style={{
              fontSize: '12px',
              color: '#8A8A8A',
              margin: '0 0 8px 0',
              lineHeight: '1.5'
            }}>
              Secure login powered by Dell Technologies
            </p>
            <p style={{
              fontSize: '11px',
              color: '#8A8A8A',
              margin: 0,
              lineHeight: '1.5'
            }}>
              Need help? Contact your system administrator
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;
