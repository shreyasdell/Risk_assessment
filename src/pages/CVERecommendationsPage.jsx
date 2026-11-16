import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { fetchCVE } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function CVERecommendationsPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [cve, setCve] = useState(null);
  const [nvdData, setNvdData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadCVE();
  }, [id]);

  const loadCVE = async () => {
    try {
      const response = await fetchCVE(id);
      setCve(response.data);
      
      // Fetch NVD data
      const token = localStorage.getItem('token');
      const nvdResponse = await fetch(`http://localhost:8000/api/cves/${id}/nvd-data`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (nvdResponse.ok) {
        const nvdJson = await nvdResponse.json();
        setNvdData(nvdJson);
      }
    } catch (err) {
      console.error('Error loading CVE:', err);
      setError('Failed to load CVE details');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <LoadingSpinner />;
  }

  if (error) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>
        {error}
      </div>
    );
  }

  if (!cve) {
    return (
      <div style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>
        CVE not found
      </div>
    );
  }

  const severityColor = cve.severity?.toLowerCase() === 'critical' ? '#F8D7DA' : cve.severity?.toLowerCase() === 'high' ? '#FDE8E8' : cve.severity?.toLowerCase() === 'medium' ? '#FFF4E5' : '#E6F4EA';
  const severityTextColor = cve.severity?.toLowerCase() === 'critical' ? '#721C24' : cve.severity?.toLowerCase() === 'high' ? '#D13438' : cve.severity?.toLowerCase() === 'medium' ? '#F4B400' : '#107C10';

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '24px' }}>
        <button 
          onClick={() => navigate('/cves')}
          style={{ 
            padding: '8px 16px', 
            fontSize: '14px', 
            border: '1px solid #D9D9D9', 
            borderRadius: '4px', 
            backgroundColor: '#FFFFFF', 
            color: '#606060', 
            cursor: 'pointer',
            marginBottom: '16px'
          }}
        >
          ← Back to CVEs
        </button>
        <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', marginBottom: '8px' }}>
          {cve.cve_id}
        </h1>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ padding: '4px 12px', borderRadius: '4px', fontSize: '13px', fontWeight: 500, backgroundColor: severityColor, color: severityTextColor }}>
            {cve.severity ? cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1).toLowerCase() : 'Unknown'}
          </span>
          <span style={{ fontSize: '14px', color: '#606060' }}>
            CVSS: {cve.cvss_score || 'N/A'}
          </span>
          {cve.published_date && (
            <span style={{ fontSize: '14px', color: '#606060' }}>
              Published: {new Date(cve.published_date).toLocaleDateString()}
            </span>
          )}
        </div>
      </div>

      {/* Description */}
      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>Description</h2>
        <p style={{ fontSize: '14px', color: '#404040', lineHeight: '1.6' }}>
          {cve.description || 'No description available'}
        </p>
      </div>

      {/* Section 1: Recommended Fix */}
      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>Recommended Fix</h2>
        <div style={{ fontSize: '14px', color: '#404040', lineHeight: '1.6' }}>
          {cve.patch_available ? (
            <p style={{ color: '#107C10', fontWeight: 500 }}>
              ✓ Patch Available - Upgrade to the latest patched version
            </p>
          ) : (
            <p style={{ color: '#D13438', fontWeight: 500 }}>
              ⚠ No Patch Available - Monitor vendor advisories for updates
            </p>
          )}
          {cve.exploit_available && (
            <p style={{ color: '#D13438', fontWeight: 500, marginTop: '8px' }}>
              ⚠ Exploit Available - Apply mitigations immediately
            </p>
          )}
        </div>
      </div>

      {/* Section 2: Official References */}
      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>Official References</h2>
        <div style={{ fontSize: '14px', color: '#404040' }}>
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#0076CE', textDecoration: 'none', display: 'block', marginBottom: '8px' }}
          >
            NVD Entry →
          </a>
          <a
            href={`https://cve.org/CVERecord?id=${cve.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: '#0076CE', textDecoration: 'none', display: 'block', marginBottom: '8px' }}
          >
            CVE.org Entry →
          </a>
        </div>
      </div>

      {/* Section 2.5: NVD References */}
      {nvdData && nvdData.references && nvdData.references.length > 0 && (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>References to Advisories, Solutions and Tools</h2>
          <div style={{ fontSize: '14px', color: '#404040' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>URL</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Source</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Tags</th>
                </tr>
              </thead>
              <tbody>
                {nvdData.references.map((ref, index) => (
                  <tr key={index} style={{ borderBottom: '1px solid #E5E5E5' }}>
                    <td style={{ padding: '12px 16px' }}>
                      <a
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: '#0076CE', textDecoration: 'none', wordBreak: 'break-all' }}
                      >
                        {ref.url}
                      </a>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#606060' }}>{ref.source || '—'}</td>
                    <td style={{ padding: '12px 16px' }}>
                      {ref.tags && ref.tags.length > 0 ? (
                        ref.tags.map((tag, tagIndex) => (
                          <span key={tagIndex} style={{ 
                            display: 'inline-block', 
                            padding: '2px 8px', 
                            borderRadius: '4px', 
                            fontSize: '11px', 
                            backgroundColor: '#E5F3FF', 
                            color: '#0076CE',
                            marginRight: '4px',
                            marginBottom: '4px'
                          }}>
                            {tag}
                          </span>
                        ))
                      ) : (
                        <span style={{ color: '#606060' }}></span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Section 3: Weakness Information */}
      {nvdData && nvdData.cwes && nvdData.cwes.length > 0 && (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>Weakness Enumeration</h2>
          <div style={{ fontSize: '14px', color: '#404040' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CWE-ID</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CWE Name</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Source</th>
                </tr>
              </thead>
              <tbody>
                {nvdData.cwes.map((cwe, index) => (
                  <tr key={index} style={{ borderBottom: '1px solid #E5E5E5' }}>
                    <td style={{ padding: '12px 16px', color: '#202020', fontWeight: 500 }}>
                      <a
                        href={`https://cwe.mitre.org/data/definitions/${cwe.cwe_id.replace('CWE-', '')}.html`}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: '#0076CE', textDecoration: 'none' }}
                      >
                        {cwe.cwe_id}
                      </a>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#606060' }}>{cwe.cwe_name || '—'}</td>
                    <td style={{ padding: '12px 16px', color: '#606060' }}>{cwe.source || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Section 4: AI Remediation Summary (Placeholder for future) */}
      <div style={{ backgroundColor: '#F5F5F5', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', marginBottom: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#606060', marginBottom: '12px' }}>AI Remediation Summary</h2>
        <p style={{ fontSize: '14px', color: '#606060', fontStyle: 'italic' }}>
          AI-generated remediation guidance will be available in a future iteration.
        </p>
      </div>
    </div>
  );
}

export default CVERecommendationsPage;
