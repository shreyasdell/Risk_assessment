import React, { useState, useEffect } from 'react';
import { fetchAuditLogs } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function AuditPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');

  useEffect(() => {
    loadLogs();
  }, [actionFilter, resourceFilter]);

  const loadLogs = async () => {
    try {
      const params = {};
      if (actionFilter) params.action = actionFilter;
      if (resourceFilter) params.resource_type = resourceFilter;
      const response = await fetchAuditLogs(params);
      setLogs(response.data);
    } catch (err) {
      console.error('Error loading audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>Audit Logs</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>View system activity and audit trail</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
            <option value="">All Actions</option>
            <option value="CREATE">Create</option>
            <option value="UPDATE">Update</option>
            <option value="DELETE">Delete</option>
            <option value="LOGIN">Login</option>
          </select>
          <select value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)} style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
            <option value="">All Resources</option>
            <option value="vendor">Vendor</option>
            <option value="application">Application</option>
            <option value="component">Component</option>
            <option value="cve">CVE</option>
          </select>
        </div>
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Timestamp</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Action</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Resource</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>User</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>IP Address</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Description</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr><td colSpan="7" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No audit logs found</td></tr>
            ) : (
              logs.map((log) => (
                <tr key={log.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{new Date(log.timestamp).toLocaleString()}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, textTransform: 'uppercase', backgroundColor: log.action === 'DELETE' ? '#FDE8E8' : log.action === 'CREATE' ? '#E6F4EA' : '#E5F3FF', color: log.action === 'DELETE' ? '#D13438' : log.action === 'CREATE' ? '#107C10' : '#0076CE' }}>{log.action}</span>
                  </td>
                  <td style={{ padding: '12px 16px', color: '#202020' }}>{log.resource_type || '—'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{log.username || '—'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{log.ip_address || '—'}</td>
                  <td style={{ padding: '12px 16px', color: '#606060', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.description || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AuditPage;
