import React, { useState, useEffect } from 'react';
import { fetchRemediations, createRemediation, updateRemediation, deleteRemediation } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../context/AuthContext';

function RemediationsPage() {
  const [remediations, setRemediations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingRemediation, setEditingRemediation] = useState(null);
  const [formData, setFormData] = useState({ title: '', description: '', status: 'open', priority: 'medium', assigned_to: '', target_date: '', cve_id: '', component_id: '' });
  const { canWrite, canDelete } = useAuth();

  useEffect(() => { loadRemediations(); }, []);

  const loadRemediations = async () => { try { const response = await fetchRemediations(); setRemediations(response.data); } catch (err) { console.error(err); } finally { setLoading(false); } };

  const handleDelete = async (id) => {
    if (window.confirm('Delete this remediation? This action cannot be undone.')) {
      try {
        await deleteRemediation(id);
        loadRemediations();
      } catch (err) {
        console.error(err);
        alert('Failed to delete remediation');
      }
    }
  };
  const handleCreate = () => { setEditingRemediation(null); setFormData({ title: '', description: '', status: 'open', priority: 'medium', assigned_to: '', target_date: '', cve_id: '', component_id: '' }); setShowModal(true); };
  const handleEdit = (rem) => { setEditingRemediation(rem); setFormData({ title: rem.title, description: rem.description || '', status: rem.status || 'open', priority: rem.priority || 'medium', assigned_to: rem.assigned_to || '', target_date: rem.target_date || '', cve_id: rem.cve_id || '', component_id: rem.component_id || '' }); setShowModal(true); };
  const handleSubmit = async (e) => { e.preventDefault(); try { if (editingRemediation) await updateRemediation(editingRemediation.id, formData); else await createRemediation(formData); setShowModal(false); loadRemediations(); } catch (err) { console.error(err); alert('Failed'); } };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>Remediation Tracking</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>Track vulnerability remediation activities and progress</p>
        </div>
        <button onClick={handleCreate} style={{ backgroundColor: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>Add Remediation</button>
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Title</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Status</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Priority</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Assigned To</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Target Date</th>
              <th style={{ padding: '12px 16px', textAlign: 'right', fontWeight: 600, color: '#606060' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {remediations.length === 0 ? <tr><td colSpan="7" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No remediations found</td></tr> : remediations.map((rem) => (
              <tr key={rem.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                <td style={{ padding: '12px 16px', color: '#202020', fontWeight: 500 }}>{rem.title}</td>
                <td style={{ padding: '12px 16px' }}><span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, backgroundColor: rem.status === 'completed' ? '#E6F4EA' : rem.status === 'in_progress' ? '#E5F3FF' : '#FFF4E5', color: rem.status === 'completed' ? '#107C10' : rem.status === 'in_progress' ? '#0076CE' : '#F4B400' }}>{rem.status ? rem.status.charAt(0).toUpperCase() + rem.status.slice(1).toLowerCase() : '—'}</span></td>
                <td style={{ padding: '12px 16px' }}><span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, backgroundColor: rem.priority === 'critical' ? '#FDE8E8' : rem.priority === 'high' ? '#FFF4E5' : '#E6F4EA', color: rem.priority === 'critical' ? '#D13438' : rem.priority === 'high' ? '#F4B400' : '#107C10' }}>{rem.priority ? rem.priority.charAt(0).toUpperCase() + rem.priority.slice(1).toLowerCase() : '—'}</span></td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{rem.assigned_to || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{rem.target_date || '—'}</td>
                <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                  {canWrite && (
                    <button onClick={() => handleEdit(rem)} style={{ background: 'none', border: 'none', color: '#0076CE', cursor: 'pointer', fontSize: '13px', marginRight: '16px' }}>Edit</button>
                  )}
                  {canDelete && (
                    <button onClick={() => handleDelete(rem.id)} style={{ background: 'none', border: 'none', color: '#D13438', cursor: 'pointer', fontSize: '13px' }}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '500px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5' }}><h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>{editingRemediation ? 'Edit Remediation' : 'Add Remediation'}</h2></div>
            <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Title *</label><input type="text" required value={formData.title} onChange={(e) => setFormData({ ...formData, title: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Description</label><textarea value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} rows="3" style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Status</label><select value={formData.status} onChange={(e) => setFormData({ ...formData, status: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}><option value="open">Open</option><option value="in_progress">In Progress</option><option value="completed">Completed</option></select></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Priority</label><select value={formData.priority} onChange={(e) => setFormData({ ...formData, priority: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Assigned To</label><input type="text" value={formData.assigned_to} onChange={(e) => setFormData({ ...formData, assigned_to: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Target Date</label><input type="date" value={formData.target_date} onChange={(e) => setFormData({ ...formData, target_date: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E5E5E5' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ background: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>{editingRemediation ? 'Update' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default RemediationsPage;
