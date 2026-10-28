import React, { useState, useEffect } from 'react';
import { fetchCVEs, deleteCVE } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../context/AuthContext';

function CVEsPage() {
  const [cves, setCves] = useState([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalCVEs, setTotalCVEs] = useState(0);
  const { canDelete } = useAuth();

  useEffect(() => {
    loadCVEs();
  }, [severityFilter, currentPage, pageSize]);

  const loadCVEs = async () => {
    try {
      const params = {
        skip: (currentPage - 1) * pageSize,
        limit: pageSize,
      };
      if (severityFilter) {
        params.severity = severityFilter;
      }
      const response = await fetchCVEs(params);
      setCves(response.data);
      setTotalCVEs(response.total || response.data.length);
    } catch (err) {
      console.error('Error loading CVEs:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Delete this CVE? This will unlink it from all components.')) {
      try {
        await deleteCVE(id);
        loadCVEs();
      } catch (err) {
        console.error('Error:', err);
        alert('Failed to delete CVE');
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
                    <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, backgroundColor: cve.severity === 'critical' ? '#FDE8E8' : cve.severity === 'high' ? '#FFF4E5' : cve.severity === 'medium' ? '#FFF4E5' : '#E6F4EA', color: cve.severity === 'critical' ? '#D13438' : cve.severity === 'high' ? '#F4B400' : cve.severity === 'medium' ? '#F4B400' : '#107C10' }}>{cve.severity ? cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1).toLowerCase() : '—'}</span>
                  </td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{cve.exploit_available ? 'Yes' : 'No'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{cve.patch_available ? 'Yes' : 'No'}</td>
                  <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                    {canDelete && (
                      <button onClick={() => handleDelete(cve.id)} style={{ background: 'none', border: 'none', color: '#D13438', cursor: 'pointer', fontSize: '13px' }}>Delete</button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', padding: '16px', backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px' }}>
        <div style={{ fontSize: '13px', color: '#606060' }}>
          Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalCVEs)} of {totalCVEs} CVEs
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            onClick={() => setCurrentPage(1)}
            disabled={currentPage === 1}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage === 1 ? '#F5F5F5' : '#FFFFFF',
              color: currentPage === 1 ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            First
          </button>
          <button
            onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
            disabled={currentPage === 1}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage === 1 ? '#F5F5F5' : '#FFFFFF',
              color: currentPage === 1 ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            Previous
          </button>
          <span style={{ padding: '6px 12px', fontSize: '13px', color: '#606060' }}>
            Page {currentPage} of {Math.ceil(totalCVEs / pageSize)}
          </span>
          <button
            onClick={() => setCurrentPage(prev => Math.min(Math.ceil(totalCVEs / pageSize), prev + 1))}
            disabled={currentPage >= Math.ceil(totalCVEs / pageSize)}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage >= Math.ceil(totalCVEs / pageSize) ? '#F5F5F5' : '#FFFFFF',
              color: currentPage >= Math.ceil(totalCVEs / pageSize) ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage >= Math.ceil(totalCVEs / pageSize) ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            Next
          </button>
          <button
            onClick={() => setCurrentPage(Math.ceil(totalCVEs / pageSize))}
            disabled={currentPage >= Math.ceil(totalCVEs / pageSize)}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage >= Math.ceil(totalCVEs / pageSize) ? '#F5F5F5' : '#FFFFFF',
              color: currentPage >= Math.ceil(totalCVEs / pageSize) ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage >= Math.ceil(totalCVEs / pageSize) ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            Last
          </button>
        </div>
      </div>
    </div>
  );
}

export default CVEsPage;
