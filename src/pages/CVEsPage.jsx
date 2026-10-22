import React, { useState, useEffect } from 'react';
import { fetchCVEs, deleteCVE } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function CVEsPage() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');

  useEffect(() => {
    loadCVEs();
  }, [severityFilter]);

  const loadCVEs = async () => {
    try {
      const response = await fetchCVEs(severityFilter ? { severity: severityFilter } : {});
      setCves(response.data);
    } catch (err) {
      console.error('Error loading CVEs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Delete this CVE?')) {
      try {
        await deleteCVE(id);
        loadCVEs();
      } catch (err) {
        console.error('Error:', err);
      }
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>CVE Intelligence</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>View and manage Common Vulnerabilities and Exposures</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CVE ID</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Description</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CVSS</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Severity</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Exploit</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Patch</th>
              <th style={{ padding: '12px 16px', textAlign: 'right', fontWeight: 600, color: '#606060' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {cves.length === 0 ? (
              <tr><td colSpan="8" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No CVEs found</td></tr>
            ) : (
              cves.map((cve) => (
                <tr key={cve.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                  <td style={{ padding: '12px 16px', color: '#0076CE', fontWeight: 500 }}>{cve.cve_id}</td>
                  <td style={{ padding: '12px 16px', color: '#202020', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cve.description || '—'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{cve.cvss_score || '—'}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, textTransform: 'uppercase', backgroundColor: cve.severity === 'critical' ? '#FDE8E8' : cve.severity === 'high' ? '#FFF4E5' : cve.severity === 'medium' ? '#FFF4E5' : '#E6F4EA', color: cve.severity === 'critical' ? '#D13438' : cve.severity === 'high' ? '#F4B400' : cve.severity === 'medium' ? '#F4B400' : '#107C10' }}>{cve.severity || '—'}</span>
                  </td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{cve.exploit_available ? 'Yes' : 'No'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{cve.patch_available ? 'Yes' : 'No'}</td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    <button onClick={() => handleDelete(cve.id)} style={{ background: 'none', border: 'none', color: '#D13438', cursor: 'pointer', fontSize: '13px' }}>Delete</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default CVEsPage;
