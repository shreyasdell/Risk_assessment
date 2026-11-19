import React, { useState, useEffect } from 'react';
import { fetchAuditLogs, fetchScanHistory } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function AuditPage() {
  const [activeTab, setActiveTab] = useState('audit-logs');
  const [logs, setLogs] = useState([]);
  const [scanHistory, setScanHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [resourceFilter, setResourceFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalLogs, setTotalLogs] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);
  const pageSize = 50;

  useEffect(() => {
    if (activeTab === 'audit-logs') {
      loadLogs();
    } else {
      loadScanHistory();
    }
  }, [activeTab, actionFilter, resourceFilter, userFilter, startDate, endDate, currentPage]);

  const loadLogs = async () => {
    try {
      const params = {
        skip: (currentPage - 1) * pageSize,
        limit: pageSize,
      };
      if (actionFilter) params.action = actionFilter;
      if (resourceFilter) params.resource_type = resourceFilter;
      if (userFilter) params.username = userFilter;
      if (startDate) params.start_date = startDate;
      if (endDate) params.end_date = endDate;
      const response = await fetchAuditLogs(params);
      setLogs(Array.isArray(response.data) ? response.data : []);
      setTotalLogs(response.total || 0);
    } catch (err) {
      console.error('Error loading audit logs:', err);
      setLogs([]);
      setTotalLogs(0);
    } finally {
      setLoading(false);
    }
  };

  const loadScanHistory = async () => {
    try {
      const params = {
        skip: (currentPage - 1) * pageSize,
        limit: pageSize,
      };
      const response = await fetchScanHistory(params);
      setScanHistory(Array.isArray(response.data) ? response.data : []);
      setTotalLogs(response.total || 0);
    } catch (err) {
      console.error('Error loading scan history:', err);
      setScanHistory([]);
      setTotalLogs(0);
    } finally {
      setLoading(false);
    }
  };

  const exportCSV = () => {
    const data = activeTab === 'audit-logs' ? logs : scanHistory;
    const headers = activeTab === 'audit-logs' 
      ? ['Timestamp', 'Action', 'Resource Type', 'Resource ID', 'User', 'Role', 'IP Address', 'Description']
      : ['Task Type', 'Status', 'Total Items', 'Processed', 'Failed', 'Created At', 'Started At', 'Completed At', 'Created By'];
    
    const rows = data.map(item => {
      if (activeTab === 'audit-logs') {
        return [
          new Date(item.timestamp).toLocaleString(),
          item.action,
          item.resource_type,
          item.resource_id || '',
          item.username || '',
          item.user_role || '',
          item.ip_address || '',
          item.description || ''
        ];
      } else {
        return [
          item.task_type,
          item.status,
          item.total_items || 0,
          item.processed_items || 0,
          item.failed_items || 0,
          item.created_at ? new Date(item.created_at).toLocaleString() : '',
          item.started_at ? new Date(item.started_at).toLocaleString() : '',
          item.completed_at ? new Date(item.completed_at).toLocaleString() : '',
          item.created_by || ''
        ];
      }
    });
    
    const csvContent = [headers, ...rows].map(row => row.join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeTab}_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getActionColor = (action) => {
    if (action === 'DELETE') return { bg: '#FDE8E8', color: '#D13438' };
    if (action === 'CREATE') return { bg: '#E6F4EA', color: '#107C10' };
    if (action === 'LOGIN_FAILED') return { bg: '#FFF4E5', color: '#F4B400' };
    if (action === 'UPDATE') return { bg: '#E5F3FF', color: '#0076CE' };
    return { bg: '#F5F5F5', color: '#606060' };
  };

  const getStatusColor = (status) => {
    if (status === 'completed') return { bg: '#E6F4EA', color: '#107C10' };
    if (status === 'failed') return { bg: '#FDE8E8', color: '#D13438' };
    if (status === 'running') return { bg: '#E5F3FF', color: '#0076CE' };
    if (status === 'pending') return { bg: '#F5F5F5', color: '#606060' };
    return { bg: '#F5F5F5', color: '#606060' };
  };

  const shouldHighlight = (log) => {
    return log.action === 'DELETE' || 
           log.action === 'LOGIN_FAILED' ||
           (log.details && log.details.old_values && log.details.old_values.role !== log.details.new_values?.role);
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>Audit Logs</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>View system activity and scan history</p>
        </div>
        <button onClick={exportCSV} style={{ padding: '8px 16px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', backgroundColor: '#FFFFFF', color: '#202020', cursor: 'pointer' }}>Export CSV</button>
      </div>

      <div style={{ marginBottom: '24px' }}>
        <button 
          onClick={() => setActiveTab('audit-logs')}
          style={{ 
            padding: '8px 16px', 
            fontSize: '14px', 
            border: 'none', 
            borderRadius: '4px 4px 0 0', 
            backgroundColor: activeTab === 'audit-logs' ? '#0076CE' : '#F5F5F5', 
            color: activeTab === 'audit-logs' ? '#FFFFFF' : '#606060', 
            cursor: 'pointer',
            marginRight: '4px'
          }}
        >
          Audit Logs
        </button>
        <button 
          onClick={() => setActiveTab('scan-history')}
          style={{ 
            padding: '8px 16px', 
            fontSize: '14px', 
            border: 'none', 
            borderRadius: '4px 4px 0 0', 
            backgroundColor: activeTab === 'scan-history' ? '#0076CE' : '#F5F5F5', 
            color: activeTab === 'scan-history' ? '#FFFFFF' : '#606060', 
            cursor: 'pointer'
          }}
        >
          Scan History
        </button>
      </div>

      {activeTab === 'audit-logs' && (
        <>
          <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap' }}>
            <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
              <option value="">All Actions</option>
              <option value="CREATE">Create</option>
              <option value="UPDATE">Update</option>
              <option value="DELETE">Delete</option>
              <option value="LOGIN">Login</option>
              <option value="LOGIN_FAILED">Login Failed</option>
              <option value="SYNC">Sync</option>
              <option value="UPLOAD">Upload</option>
              <option value="EXPORT">Export</option>
            </select>
            <select value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)} style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
              <option value="">All Resources</option>
              <option value="user">User</option>
              <option value="vendor">Vendor</option>
              <option value="application">Application</option>
              <option value="component">Component</option>
              <option value="sbom">SBOM</option>
              <option value="cve">CVE</option>
              <option value="remediation">Remediation</option>
              <option value="report">Report</option>
            </select>
            <input 
              type="text" 
              placeholder="Filter by username" 
              value={userFilter}
              onChange={(e) => setUserFilter(e.target.value)}
              style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}
            />
            <input 
              type="date" 
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}
            />
            <input 
              type="date" 
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}
            />
          </div>

          <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Action</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Resource</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>User</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Role</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>IP Address</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Description</th>
                  <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Details</th>
                </tr>
              </thead>
              <tbody>
                {logs.length === 0 ? (
                  <tr><td colSpan="9" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No audit logs found</td></tr>
                ) : (
                  logs.map((log) => {
                    const actionColor = getActionColor(log.action);
                    const isHighlighted = shouldHighlight(log);
                    return (
                      <React.Fragment key={log.id}>
                        <tr 
                          style={{ 
                            borderBottom: '1px solid #E5E5E5',
                            backgroundColor: isHighlighted ? '#FFF4E5' : 'transparent'
                          }}
                        >
                          <td style={{ padding: '12px 16px', color: '#606060' }}>{new Date(log.timestamp).toLocaleString()}</td>
                          <td style={{ padding: '12px 16px' }}>
                            <span style={{ 
                              padding: '2px 8px', 
                              borderRadius: '4px', 
                              fontSize: '12px', 
                              fontWeight: 500, 
                              textTransform: 'uppercase', 
                              backgroundColor: actionColor.bg, 
                              color: actionColor.color 
                            }}>{log.action}</span>
                          </td>
                          <td style={{ padding: '12px 16px', color: '#202020' }}>{log.resource_type || '—'}</td>
                          <td style={{ padding: '12px 16px', color: '#606060' }}>{log.username || '—'}</td>
                          <td style={{ padding: '12px 16px', color: '#606060' }}>{log.user_role || '—'}</td>
                          <td style={{ padding: '12px 16px', color: '#606060' }}>{log.ip_address || '—'}</td>
                          <td style={{ padding: '12px 16px', color: '#606060', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{log.description || '—'}</td>
                          <td style={{ padding: '12px 16px' }}>
                            <button 
                              onClick={() => setExpandedRow(expandedRow === log.id ? null : log.id)}
                              style={{ 
                                padding: '4px 8px', 
                                fontSize: '12px', 
                                border: '1px solid #D9D9D9', 
                                borderRadius: '4px', 
                                backgroundColor: '#FFFFFF', 
                                color: '#0076CE', 
                                cursor: 'pointer' 
                              }}
                            >
                              {expandedRow === log.id ? 'Hide' : 'Show'}
                            </button>
                          </td>
                        </tr>
                        {expandedRow === log.id && (
                          <tr style={{ backgroundColor: '#F9F9F9' }}>
                            <td colSpan="9" style={{ padding: '16px' }}>
                              <pre style={{ margin: 0, fontSize: '12px', color: '#404040', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                                {JSON.stringify(log.details, null, 2)}
                              </pre>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
            
            {totalLogs > pageSize && (
              <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '12px', padding: '16px' }}>
                <button 
                  onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                  style={{ 
                    padding: '8px 16px', 
                    fontSize: '14px', 
                    border: '1px solid #D9D9D9', 
                    borderRadius: '4px', 
                    backgroundColor: currentPage === 1 ? '#F5F5F5' : '#FFFFFF', 
                    color: '#202020', 
                    cursor: currentPage === 1 ? 'not-allowed' : 'pointer' 
                  }}
                >
                  Previous
                </button>
                <span style={{ fontSize: '14px', color: '#606060' }}>
                  Page {currentPage} of {Math.ceil(totalLogs / pageSize)}
                </span>
                <button 
                  onClick={() => setCurrentPage(p => p + 1)}
                  disabled={currentPage >= Math.ceil(totalLogs / pageSize)}
                  style={{ 
                    padding: '8px 16px', 
                    fontSize: '14px', 
                    border: '1px solid #D9D9D9', 
                    borderRadius: '4px', 
                    backgroundColor: currentPage >= Math.ceil(totalLogs / pageSize) ? '#F5F5F5' : '#FFFFFF', 
                    color: '#202020', 
                    cursor: currentPage >= Math.ceil(totalLogs / pageSize) ? 'not-allowed' : 'pointer' 
                  }}
                >
                  Next
                </button>
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'scan-history' && (
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Task Type</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Status</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Progress</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Created At</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Duration</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Created By</th>
                <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Details</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.length === 0 ? (
                <tr><td colSpan="7" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No scan history found</td></tr>
              ) : (
                scanHistory.map((task) => {
                  const statusColor = getStatusColor(task.status);
                  const duration = task.started_at && task.completed_at 
                    ? Math.round((new Date(task.completed_at) - new Date(task.started_at)) / 1000) + 's'
                    : '—';
                  return (
                    <React.Fragment key={task.id}>
                      <tr style={{ borderBottom: '1px solid #E5E5E5' }}>
                        <td style={{ padding: '12px 16px', color: '#202020' }}>{task.task_type || '—'}</td>
                        <td style={{ padding: '12px 16px' }}>
                          <span style={{ 
                            padding: '2px 8px', 
                            borderRadius: '4px', 
                            fontSize: '12px', 
                            fontWeight: 500, 
                            textTransform: 'capitalize', 
                            backgroundColor: statusColor.bg, 
                            color: statusColor.color 
                          }}>{task.status}</span>
                        </td>
                        <td style={{ padding: '12px 16px', color: '#606060' }}>
                          {task.progress_percentage !== undefined ? `${task.progress_percentage}%` : '—'}
                          {task.current_item && <div style={{ fontSize: '11px', color: '#909090' }}>{task.current_item}</div>}
                        </td>
                        <td style={{ padding: '12px 16px', color: '#606060' }}>{task.created_at ? new Date(task.created_at).toLocaleString() : '—'}</td>
                        <td style={{ padding: '12px 16px', color: '#606060' }}>{duration}</td>
                        <td style={{ padding: '12px 16px', color: '#606060' }}>{task.created_by || '—'}</td>
                        <td style={{ padding: '12px 16px' }}>
                          <button 
                            onClick={() => setExpandedRow(expandedRow === task.id ? null : task.id)}
                            style={{ 
                              padding: '4px 8px', 
                              fontSize: '12px', 
                              border: '1px solid #D9D9D9', 
                              borderRadius: '4px', 
                              backgroundColor: '#FFFFFF', 
                              color: '#0076CE', 
                              cursor: 'pointer' 
                            }}
                          >
                            {expandedRow === task.id ? 'Hide' : 'Show'}
                          </button>
                        </td>
                      </tr>
                      {expandedRow === task.id && (
                        <tr style={{ backgroundColor: '#F9F9F9' }}>
                          <td colSpan="7" style={{ padding: '16px' }}>
                            <pre style={{ margin: 0, fontSize: '12px', color: '#404040', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                              {JSON.stringify(task, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
          
          {totalLogs > pageSize && (
            <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '12px', padding: '16px' }}>
              <button 
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                style={{ 
                  padding: '8px 16px', 
                  fontSize: '14px', 
                  border: '1px solid #D9D9D9', 
                  borderRadius: '4px', 
                  backgroundColor: currentPage === 1 ? '#F5F5F5' : '#FFFFFF', 
                  color: '#202020', 
                  cursor: currentPage === 1 ? 'not-allowed' : 'pointer' 
                }}
              >
                Previous
              </button>
              <span style={{ fontSize: '14px', color: '#606060' }}>
                Page {currentPage} of {Math.ceil(totalLogs / pageSize)}
              </span>
              <button 
                onClick={() => setCurrentPage(p => p + 1)}
                disabled={currentPage >= Math.ceil(totalLogs / pageSize)}
                style={{ 
                  padding: '8px 16px', 
                  fontSize: '14px', 
                  border: '1px solid #D9D9D9', 
                  borderRadius: '4px', 
                  backgroundColor: currentPage >= Math.ceil(totalLogs / pageSize) ? '#F5F5F5' : '#FFFFFF', 
                  color: '#202020', 
                  cursor: currentPage >= Math.ceil(totalLogs / pageSize) ? 'not-allowed' : 'pointer' 
                }}
              >
                Next
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AuditPage;
