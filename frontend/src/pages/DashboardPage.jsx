import React, { useState, useEffect } from 'react';
import { fetchDashboard } from '../api/client';
import SummaryCards from '../components/Dashboard/SummaryCards';
import LoadingSpinner from '../components/common/LoadingSpinner';

function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadDashboard = async () => {
    try {
      setError(null);
      const response = await fetchDashboard();
      setData(response.data);
    } catch (err) {
      console.error('Dashboard load error:', err);
      setError('Failed to load dashboard data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  if (loading) return <LoadingSpinner message="Loading dashboard..." />;
  if (error) return <div style={{ color: '#ef4444', padding: '20px' }}>{error}</div>;
  if (!data) return <div style={{ color: '#64748b', padding: '20px' }}>No data received.</div>;

  return (
    <div>
      <SummaryCards summary={data.summary} />
      <div className="dashboard-grid">
        <div className="card">
          <div className="card-title">Dashboard Features</div>
          <p style={{ color: '#94a3b8' }}>
            More dashboard widgets will be added here:
          </p>
          <ul style={{ color: '#94a3b8', marginTop: '12px', paddingLeft: '20px' }}>
            <li>Risk Distribution Chart</li>
            <li>Top Vulnerable Applications</li>
            <li>Top Vulnerable Components</li>
            <li>Vendor Risk Summary</li>
            <li>Recent CVEs</li>
            <li>Remediation Progress</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
