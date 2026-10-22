import React, { useState, useEffect } from 'react';
import { fetchDashboard } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  const loadDashboard = async () => {
    try {
      const response = await fetchDashboard();
      setData(response.data);
    } catch (err) {
      console.error('Error loading dashboard:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>
          Dashboard
        </h1>
        <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>
          Overview of third-party risk assessment metrics and security posture
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px', marginBottom: '32px' }}>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <div style={{ fontSize: '13px', color: '#606060', marginBottom: '8px' }}>Total Applications</div>
          <div style={{ fontSize: '32px', fontWeight: 600, color: '#202020' }}>{data?.total_applications || 0}</div>
        </div>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <div style={{ fontSize: '13px', color: '#606060', marginBottom: '8px' }}>Total Vendors</div>
          <div style={{ fontSize: '32px', fontWeight: 600, color: '#202020' }}>{data?.total_vendors || 0}</div>
        </div>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <div style={{ fontSize: '13px', color: '#606060', marginBottom: '8px' }}>Total Components</div>
          <div style={{ fontSize: '32px', fontWeight: 600, color: '#202020' }}>{data?.total_components || 0}</div>
        </div>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <div style={{ fontSize: '13px', color: '#606060', marginBottom: '8px' }}>Critical Apps</div>
          <div style={{ fontSize: '32px', fontWeight: 600, color: '#D13438' }}>{data?.critical_applications || 0}</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '32px' }}>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>Criticality Distribution</h2>
          <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#606060' }}>
            Chart placeholder
          </div>
        </div>
        <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>Environment Distribution</h2>
          <div style={{ height: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#606060' }}>
            Chart placeholder
          </div>
        </div>
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', padding: '24px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', marginBottom: '16px', margin: 0 }}>Recent Applications</h2>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Name</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Owner</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Criticality</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Environment</th>
            </tr>
          </thead>
          <tbody>
            {data?.recent_applications?.length === 0 ? (
              <tr>
                <td colSpan="4" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No recent applications</td>
              </tr>
            ) : (
              data?.recent_applications?.map((app) => (
                <tr key={app.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                  <td style={{ padding: '12px 16px', color: '#202020' }}>{app.name}</td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{app.owner || '—'}</td>
                  <td style={{ padding: '12px 16px' }}>
                    <span style={{ 
                      padding: '2px 8px', 
                      borderRadius: '4px', 
                      fontSize: '12px', 
                      fontWeight: 500, 
                      textTransform: 'uppercase',
                      backgroundColor: app.criticality === 'critical' ? '#FDE8E8' : app.criticality === 'high' ? '#FFF4E5' : '#E6F4EA',
                      color: app.criticality === 'critical' ? '#D13438' : app.criticality === 'high' ? '#F4B400' : '#107C10'
                    }}>
                      {app.criticality || '—'}
                    </span>
                  </td>
                  <td style={{ padding: '12px 16px', color: '#606060' }}>{app.environment || '—'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default DashboardPage;
