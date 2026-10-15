import React, { useState, useEffect } from 'react';
import { fetchApplications, deleteApplication } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function ApplicationsPage() {
  const [apps, setApps] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadApplications();
  }, []);

  const loadApplications = async () => {
    try {
      const response = await fetchApplications();
      setApps(response.data);
    } catch (err) {
      console.error('Error loading applications:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Delete this application?')) {
      try {
        await deleteApplication(id);
        loadApplications();
      } catch (err) {
        console.error('Error:', err);
      }
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <h3 style={{ fontSize: '16px', color: '#94a3b8', marginBottom: '20px' }}>
        {apps.length} application(s) registered
      </h3>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Owner</th>
              <th>Criticality</th>
              <th>Environment</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {apps.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', color: '#64748b', padding: '40px' }}>
                  No applications yet.
                </td>
              </tr>
            ) : (
              apps.map((app) => (
                <tr key={app.id}>
                  <td style={{ fontWeight: 500 }}>{app.name}</td>
                  <td>{app.owner || '—'}</td>
                  <td>
                    <span className={`badge badge-${app.criticality || 'info'}`}>
                      {app.criticality}
                    </span>
                  </td>
                  <td>{app.environment}</td>
                  <td>
                    <button
                      onClick={() => handleDelete(app.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#ef4444',
                        cursor: 'pointer',
                        fontSize: '13px'
                      }}
                    >
                      Delete
                    </button>
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

export default ApplicationsPage;
