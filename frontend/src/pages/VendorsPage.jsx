import React, { useState, useEffect } from 'react';
import { fetchVendors, createVendor, deleteVendor } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';

function VendorsPage() {
  const [vendors, setVendors] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadVendors();
  }, []);

  const loadVendors = async () => {
    try {
      const response = await fetchVendors();
      setVendors(response.data);
    } catch (err) {
      console.error('Error loading vendors:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this vendor?')) {
      try {
        await deleteVendor(id);
        loadVendors();
      } catch (err) {
        console.error('Error deleting vendor:', err);
      }
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <h3 style={{ fontSize: '16px', color: '#94a3b8', marginBottom: '20px' }}>
        {vendors.length} vendor(s) registered
      </h3>
      <div className="card">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Country</th>
              <th>Business Owner</th>
              <th>Service Type</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {vendors.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', color: '#64748b', padding: '40px' }}>
                  No vendors yet.
                </td>
              </tr>
            ) : (
              vendors.map((vendor) => (
                <tr key={vendor.id}>
                  <td style={{ fontWeight: 500 }}>{vendor.name}</td>
                  <td>{vendor.country || '—'}</td>
                  <td>{vendor.business_owner || '—'}</td>
                  <td>{vendor.service_type || '—'}</td>
                  <td>
                    <button
                      onClick={() => handleDelete(vendor.id)}
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

export default VendorsPage;
