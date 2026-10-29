import React, { useState, useEffect } from 'react';
import { fetchComponents, fetchApplications, createComponent, updateComponent, deleteComponent, syncCVEs, fetchLinkedCVEs } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../context/AuthContext';

function ComponentsPage() {
  const [components, setComponents] = useState([]);
  const [applications, setApplications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingComponent, setEditingComponent] = useState(null);
  const [syncingCVEs, setSyncingCVEs] = useState({});
  const [showCVEsModal, setShowCVEsModal] = useState(false);
  const [selectedComponentCVEs, setSelectedComponentCVEs] = useState(null);
  const [selectedApplication, setSelectedApplication] = useState('');
  const [formData, setFormData] = useState({ name: '', version: '', component_type: 'library', purl: '', supplier: '', description: '', license: '', application_id: '' });
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [totalComponents, setTotalComponents] = useState(0);
  const { canWrite, canDelete } = useAuth();

  useEffect(() => { loadComponents(); loadApplications(); }, [currentPage, pageSize]);

  const loadComponents = async () => {
    try {
      const params = {
        skip: (currentPage - 1) * pageSize,
        limit: pageSize,
      };
      if (selectedApplication) {
        params.application_id = selectedApplication;
      }
      const response = await fetchComponents(params);
      setComponents(response.data);
      setTotalComponents(response.total || response.data.length);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };
  
  const loadApplications = async () => { try { const response = await fetchApplications(); setApplications(response.data); } catch (err) { console.error(err); } };

  const handleApplicationFilterChange = (appId) => {
    setSelectedApplication(appId);
    setCurrentPage(1); // Reset to first page when filter changes
    setLoading(true);
    // Reload components with new filter
    const loadFiltered = async () => {
      try {
        const params = {
          skip: 0,
          limit: pageSize,
        };
        if (appId) {
          params.application_id = appId;
        }
        const response = await fetchComponents(params);
        setComponents(response.data);
        setTotalComponents(response.total || response.data.length);
      } catch (err) {
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    loadFiltered();
  };

  const handleDelete = async (id) => { if (window.confirm('Delete this component?')) { try { await deleteComponent(id); loadComponents(); } catch (err) { console.error(err); } } };
  const handleCreate = () => { setEditingComponent(null); setFormData({ name: '', version: '', component_type: 'library', purl: '', supplier: '', description: '', license: '', application_id: '' }); setShowModal(true); };
  const handleEdit = (component) => { setEditingComponent(component); setFormData({ name: component.name, version: component.version || '', component_type: component.component_type || 'library', purl: component.purl || '', supplier: component.supplier || '', description: component.description || '', license: component.license || '', application_id: component.application_id || '' }); setShowModal(true); };
  const handleSubmit = async (e) => { e.preventDefault(); try { if (editingComponent) await updateComponent(editingComponent.id, formData); else await createComponent(formData); setShowModal(false); loadComponents(); } catch (err) { console.error(err); alert('Failed'); } };
  const handleSyncCVEs = async (componentId) => { setSyncingCVEs(prev => ({ ...prev, [componentId]: true })); try { await syncCVEs(componentId); alert('CVEs synced'); loadComponents(); } catch (err) { console.error(err); alert('Failed'); } finally { setSyncingCVEs(prev => ({ ...prev, [componentId]: false })); } };
  const handleViewCVEs = async (componentId) => { try { const response = await fetchLinkedCVEs(componentId); setSelectedComponentCVEs(response.data); setShowCVEsModal(true); } catch (err) { console.error(err); alert('Failed'); } };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>Component Management</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>Manage software components and their vulnerabilities</p>
        </div>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <select 
            value={selectedApplication} 
            onChange={(e) => handleApplicationFilterChange(e.target.value)}
            style={{ padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020', backgroundColor: '#FFFFFF' }}
          >
            <option value="">All Applications</option>
            {applications.map((app) => (
              <option key={app.id} value={app.id}>{app.name}</option>
            ))}
          </select>
          {canWrite && (
            <button onClick={handleCreate} style={{ backgroundColor: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>Add Component</button>
          )}
        </div>
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Name</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Version</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Type</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Application</th>
              <th style={{ padding: '12px 16px', textAlign: 'right', fontWeight: 600, color: '#606060' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {components.length === 0 ? <tr><td colSpan="5" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No components yet</td></tr> : components.map((component) => (
              <tr key={component.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                <td style={{ padding: '12px 16px', color: '#202020', fontWeight: 500 }}>{component.name}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{component.version || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>{component.component_type || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#606060' }}>
                  {component.application_id ? (
                    applications.find(app => app.id === component.application_id)?.name || component.application_id
                  ) : (
                    '—'
                  )}
                </td>
                <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                  {canWrite && (
                    <button onClick={() => handleSyncCVEs(component.id)} disabled={syncingCVEs[component.id]} style={{ background: syncingCVEs[component.id] ? '#64748B' : '#107C10', color: '#FFFFFF', border: 'none', padding: '4px 8px', borderRadius: '4px', cursor: syncingCVEs[component.id] ? 'not-allowed' : 'pointer', fontSize: '12px', marginRight: '8px' }}>{syncingCVEs[component.id] ? 'Syncing...' : 'Sync CVEs'}</button>
                  )}
                  <button onClick={() => handleViewCVEs(component.id)} style={{ background: 'none', border: 'none', color: '#F4B400', cursor: 'pointer', fontSize: '13px', marginRight: '8px' }}>View CVEs</button>
                  {canWrite && (
                    <button onClick={() => handleEdit(component)} style={{ background: 'none', border: 'none', color: '#0076CE', cursor: 'pointer', fontSize: '13px', marginRight: '8px' }}>Edit</button>
                  )}
                  {canDelete && (
                    <button onClick={() => handleDelete(component.id)} style={{ background: 'none', border: 'none', color: '#D13438', cursor: 'pointer', fontSize: '13px' }}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px', padding: '16px', backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px' }}>
        <div style={{ fontSize: '13px', color: '#606060' }}>
          Showing {((currentPage - 1) * pageSize) + 1} to {Math.min(currentPage * pageSize, totalComponents)} of {totalComponents} components
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
            Page {currentPage} of {Math.ceil(totalComponents / pageSize)}
          </span>
          <button
            onClick={() => setCurrentPage(prev => Math.min(Math.ceil(totalComponents / pageSize), prev + 1))}
            disabled={currentPage >= Math.ceil(totalComponents / pageSize)}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage >= Math.ceil(totalComponents / pageSize) ? '#F5F5F5' : '#FFFFFF',
              color: currentPage >= Math.ceil(totalComponents / pageSize) ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage >= Math.ceil(totalComponents / pageSize) ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            Next
          </button>
          <button
            onClick={() => setCurrentPage(Math.ceil(totalComponents / pageSize))}
            disabled={currentPage >= Math.ceil(totalComponents / pageSize)}
            style={{
              padding: '6px 12px',
              border: '1px solid #D9D9D9',
              backgroundColor: currentPage >= Math.ceil(totalComponents / pageSize) ? '#F5F5F5' : '#FFFFFF',
              color: currentPage >= Math.ceil(totalComponents / pageSize) ? '#A0A0A0' : '#202020',
              borderRadius: '4px',
              cursor: currentPage >= Math.ceil(totalComponents / pageSize) ? 'not-allowed' : 'pointer',
              fontSize: '13px'
            }}
          >
            Last
          </button>
        </div>
      </div>

      {showModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '500px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5' }}><h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>{editingComponent ? 'Edit Component' : 'Add Component'}</h2></div>
            <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Name <span style={{ color: '#D13438' }}>*</span></label><input type="text" required value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Version <span style={{ color: '#D13438' }}>*</span></label><input type="text" required value={formData.version} onChange={(e) => setFormData({ ...formData, version: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} /></div>
              <div style={{ marginBottom: '16px' }}><label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Application</label><select value={formData.application_id} onChange={(e) => setFormData({ ...formData, application_id: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}><option value="">Select Application</option>{applications.map((app) => <option key={app.id} value={app.id}>{app.name}</option>)}</select></div>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E5E5E5' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ background: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>{editingComponent ? 'Update' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showCVEsModal && selectedComponentCVEs && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '700px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '24px', borderBottom: '1px solid #E5E5E5' }}>
              <h2 style={{ color: '#202020', margin: 0, fontSize: '18px', fontWeight: 600 }}>CVEs for {selectedComponentCVEs.component_name} {selectedComponentCVEs.component_version}</h2>
              <button onClick={() => setShowCVEsModal(false)} style={{ background: 'none', border: 'none', color: '#606060', cursor: 'pointer', fontSize: '20px' }}>×</button>
            </div>
            <div style={{ padding: '24px' }}>
              <p style={{ color: '#606060', marginBottom: '16px' }}>Total CVEs: {selectedComponentCVEs.total_cves}</p>
              {selectedComponentCVEs.cves.length === 0 ? <p style={{ color: '#606060', textAlign: 'center', padding: '40px' }}>No CVEs found</p> : selectedComponentCVEs.cves.map((cve) => (
                <div key={cve.id} style={{ backgroundColor: '#F7F8FA', padding: '16px', borderRadius: '4px', marginBottom: '12px', border: '1px solid #E5E5E5' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ fontWeight: 500, color: '#0076CE', textDecoration: 'none' }}
                      onMouseEnter={(e) => e.target.style.textDecoration = 'underline'}
                      onMouseLeave={(e) => e.target.style.textDecoration = 'none'}
                    >
                      {cve.cve_id}
                    </a>
                    <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, textTransform: 'uppercase', backgroundColor: cve.severity === 'critical' ? '#FDE8E8' : cve.severity === 'high' ? '#FFF4E5' : '#E6F4EA', color: cve.severity === 'critical' ? '#D13438' : cve.severity === 'high' ? '#F4B400' : '#107C10' }}>{cve.severity}</span>
                  </div>
                  <p style={{ color: '#606060', fontSize: '13px', marginBottom: '8px' }}>{cve.description}</p>
                  <div style={{ display: 'flex', gap: '16px', fontSize: '12px', color: '#606060' }}><span>CVSS: {cve.cvss_score}</span><span>Exploit: {cve.exploit_available ? 'Yes' : 'No'}</span><span>Patch: {cve.patch_available ? 'Yes' : 'No'}</span></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ComponentsPage;
