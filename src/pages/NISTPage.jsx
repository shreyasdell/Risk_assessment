import React, { useState, useEffect } from 'react';
import { fetchNISTRecommendations, createNISTRecommendation } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../context/AuthContext';

function NISTPage() {
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ cwe_id: '', cwe_name: '', nist_category: '', nist_function: '', recommendation: '', detailed_guidance: '' });
  const { canWrite } = useAuth();

  useEffect(() => { loadRecommendations(); }, []);

  const loadRecommendations = async () => {
    try { const response = await fetchNISTRecommendations(); setRecommendations(response.data); } catch (err) { console.error(err); } finally { setLoading(false); }
  };

  const handleCreate = () => { setFormData({ cwe_id: '', cwe_name: '', nist_category: '', nist_function: '', recommendation: '', detailed_guidance: '' }); setShowModal(true); };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try { await createNISTRecommendation(formData); setShowModal(false); loadRecommendations(); } catch (err) { console.error(err); alert('Failed'); }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>NIST Recommendations</h1>
 <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>Security recommendations mapped to CWE weaknesses</p>
        </div>
        {canWrite && (
          <button onClick={handleCreate} style={{ backgroundColor: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>Add Recommendation</button>
        )}
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CWE ID</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>CWE Name</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>NIST Category</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>NIST Function</th>
            </tr>
          </thead>
          <tbody>
            {recommendations.length === 0 ? <tr><td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No recommendations found</td></tr> : recommendations.map((rec) => (
              <tr key={rec.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                <td style={{ padding: '12px 16px', color: '#0076CE', fontWeight: 500 }}>{rec.cwe_id}</td>
                <td style={{ padding: '12px 16px', color: '#202020' }}>{rec.cwe_name || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{rec.nist_category || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{rec.nist_function || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '500px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5' }}><h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>Add NIST Recommendation</h2></div>
            <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>CWE ID *</label><input type="text" required value={formData.cwe_id} onChange={(e) => setFormData({ ...formData, cwe_id: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>CWE Name *</label><input type="text" required value={formData.cwe_name} onChange={(e) => setFormData({ ...formData, cwe_name: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>NIST Category</label><input type="text" value={formData.nist_category} onChange={(e) => setFormData({ ...formData, nist_category: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>NIST Function</label><input type="text" value={formData.nist_function} onChange={(e) => setFormData({ ...formData, nist_function: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Recommendation *</label><textarea required value={formData.recommendation} onChange={(e) => setFormData({ ...formData, recommendation: e.target.value })} rows="3" style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Detailed Guidance</label><textarea value={formData.detailed_guidance} onChange={(e) => setFormData({ ...formData, detailed_guidance: e.target.value })} rows="3" style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E5E5E5' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ background: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Create</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default NISTPage;
