/**
 * SearchBar Component
 * Global search with live results dropdown.
 */

import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../../api/client';

export default function SearchBar() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef(null);
  const debounceRef = useRef(null);
  const navigate = useNavigate();

  // Close dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(e) {
      if (
        dropdownRef.current
        && !dropdownRef.current.contains(e.target)
      ) {
        setShowDropdown(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener(
      'mousedown', handleClickOutside
    );
  }, []);

  const search = async (searchQuery) => {
    if (searchQuery.length < 2) {
      setResults(null);
      setShowDropdown(false);
      return;
    }

    setLoading(true);
    try {
      const res = await api.get(
        `/search/?q=${encodeURIComponent(searchQuery)}`
      );
      setResults(res.data);
      setShowDropdown(true);
    } catch (err) {
      console.error('Search error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const value = e.target.value;
    setQuery(value);

    // Debounce: wait 300ms after typing stops
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      search(value);
    }, 300);
  };

  const handleSelect = (type, id) => {
    setShowDropdown(false);
    setQuery('');

    switch (type) {
      case 'vendor':
        navigate('/vendors');
        break;
      case 'application':
        navigate('/applications');
        break;
      case 'component':
        navigate('/components');
        break;
      case 'cve':
        navigate('/cves');
        break;
      default:
        break;
    }
  };

  const renderSection = (title, items) => {
    if (!items || items.length === 0) return null;

    return (
      <div style={{ marginBottom: 8 }}>
        <div style={{
          fontSize: 11,
          fontWeight: 600,
          color: '#606060',
          textTransform: 'uppercase',
          letterSpacing: 0.5,
          padding: '6px 12px',
        }}>
          {title} ({items.length})
        </div>
        {items.map((item, i) => (
          <div
            key={`${item.type}-${item.id}-${i}`}
            onClick={() => handleSelect(
              item.type, item.id
            )}
            style={{
              padding: '8px 12px',
              cursor: 'pointer',
              fontSize: 13,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderRadius: 4,
              transition: 'background 0.15s',
            }}
            onMouseEnter={(e) => {
              e.target.style.background = '#F5F7FA';
            }}
            onMouseLeave={(e) => {
              e.target.style.background =
                'transparent';
            }}
          >
            <span>
              {item.name || item.cve_id}
              {item.version && (
                <span style={{
                  color: '#606060',
                  marginLeft: 6,
                }}>
                  v{item.version}
                </span>
              )}
            </span>
            {item.severity && (
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 500,
                  textTransform: 'uppercase',
                  backgroundColor: item.severity === 'critical' ? '#FDE8E8' : item.severity === 'high' ? '#FFF4E5' : '#E6F4EA',
                  color: item.severity === 'critical' ? '#D13438' : item.severity === 'high' ? '#F4B400' : '#107C10'
                }}
              >
                {item.severity}
              </span>
            )}
            {item.criticality && (
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '12px',
                  fontWeight: 500,
                  textTransform: 'uppercase',
                  backgroundColor: item.criticality === 'critical' ? '#FDE8E8' : item.criticality === 'high' ? '#FFF4E5' : '#E6F4EA',
                  color: item.criticality === 'critical' ? '#D13438' : item.criticality === 'high' ? '#F4B400' : '#107C10'
                }}
              >
                {item.criticality}
              </span>
            )}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div
      ref={dropdownRef}
      style={{ position: 'relative', width: 320 }}
    >
      <input
        type="text"
        value={query}
        onChange={handleChange}
        placeholder="Search apps, vendors, CVEs..."
        style={{
          width: '100%',
          padding: '8px 14px',
          background: '#FFFFFF',
          border: '1px solid #D9D9D9',
          borderRadius: 6,
          color: '#202020',
          fontSize: 13,
          outline: 'none',
          transition: 'all 100ms ease-in-out'
        }}
        onFocus={(e) => {
          e.target.style.borderColor = '#0076CE';
          e.target.style.boxShadow = '0 0 0 3px rgba(0, 118, 206, 0.1)';
        }}
        onBlur={(e) => {
          e.target.style.borderColor = '#D9D9D9';
          e.target.style.boxShadow = 'none';
        }}
      />

      {loading && (
        <div style={{
          position: 'absolute',
          right: 12,
          top: 10,
          fontSize: 12,
          color: '#606060',
        }}>
          ...
        </div>
      )}

      {showDropdown && results && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          background: '#FFFFFF',
          border: '1px solid #D9D9D9',
          borderRadius: 6,
          marginTop: 4,
          maxHeight: 400,
          overflowY: 'auto',
          zIndex: 1000,
          boxShadow:
            '0 10px 25px rgba(0,0,0,0.1)',
        }}>
          {results.total_results === 0 ? (
            <div style={{
              padding: 20,
              textAlign: 'center',
              color: '#606060',
              fontSize: 13,
            }}>
              No results for "{query}"
            </div>
          ) : (
            <div style={{ padding: '8px 0' }}>
              {renderSection(
                'Applications',
                results.applications
              )}
              {renderSection(
                'Vendors',
                results.vendors
              )}
              {renderSection(
                'Components',
                results.components
              )}
              {renderSection(
                'CVEs',
                results.cves
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
