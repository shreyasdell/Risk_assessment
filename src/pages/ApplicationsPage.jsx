import React, { useState, useEffect } from 'react';
import { fetchApplications, fetchVendors, createApplication, updateApplication, deleteApplication, calculateRiskScore, uploadSBOM, fetchRiskScore } from '../api/client';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { useAuth } from '../context/AuthContext';

function ApplicationsPage() {
  const [apps, setApps] = useState([]);
  const [riskScores, setRiskScores] = useState({});
  const [vendors, setVendors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [showSBOMModal, setShowSBOMModal] = useState(false);
  const [showRiskModal, setShowRiskModal] = useState(false);
  const [selectedRiskDetails, setSelectedRiskDetails] = useState(null);
  const [editingApp, setEditingApp] = useState(null);
  const [selectedAppForSBOM, setSelectedAppForSBOM] = useState(null);
  const [sbomFile, setSbomFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [formData, setFormData] = useState({ name: '', description: '', owner: '', business_unit: '', criticality: 'medium', internet_facing: false, data_classification: 'internal', environment: 'development', vendor_id: '' });
  const { canWrite, canDelete } = useAuth();

  useEffect(() => { loadApplications(); loadVendors(); }, []);

  const loadApplications = async () => {
    try { 
      const response = await fetchApplications(); 
      setApps(response.data);
      // Load risk scores after applications are loaded
      loadRiskScores(response.data);
    } catch (err) { console.error(err); } finally { setLoading(false); }
  };

  const loadVendors = async () => {
    try { const response = await fetchVendors(); setVendors(response.data); } catch (err) { console.error(err); }
  };

  const loadRiskScores = async (applications) => {
    const scores = {};
    for (const app of applications) {
      try {
        const response = await fetchRiskScore(app.id);
        scores[app.id] = response.data;
      } catch (err) {
        // No risk score calculated yet
      }
    }
    setRiskScores(scores);
  };

  const handleDelete = async (id) => {
    const app = apps.find(a => a.id === id);
    if (!app) return;
    
    const confirmMessage = `Delete application "${app.name}"?\n\nThis will also delete all associated components, risk scores, and remediations. This action cannot be undone.`;
    
    if (window.confirm(confirmMessage)) {
      try {
        await deleteApplication(id);
        loadApplications();
      } catch (err) {
        console.error(err);
        alert('Failed to delete application');
      }
    }
  };

  const handleCreate = () => {
    setEditingApp(null);
    setFormData({ name: '', description: '', owner: '', business_unit: '', criticality: 'medium', internet_facing: false, data_classification: 'internal', environment: 'development', vendor_id: '' });
    setShowModal(true);
  };

  const handleEdit = (app) => {
    setEditingApp(app);
    setFormData({ name: app.name, description: app.description || '', owner: app.owner || '', business_unit: app.business_unit || '', criticality: app.criticality || 'medium', internet_facing: app.internet_facing || false, data_classification: app.data_classification || 'internal', environment: app.environment || 'development', vendor_id: app.vendor_id || '' });
    setShowModal(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      // Convert empty string vendor_id to null
      const submissionData = {
        ...formData,
        vendor_id: formData.vendor_id ? parseInt(formData.vendor_id) : null
      };
      if (editingApp) await updateApplication(editingApp.id, submissionData);
      else await createApplication(submissionData);
      setShowModal(false);
      loadApplications();
    } catch (err) {
      console.error(err);
      alert('Failed to save application');
    }
  };

  const handleCalculateRisk = async (appId) => {
    try {
      await calculateRiskScore(appId);
      alert('Risk score calculated successfully');
      loadApplications();
    } catch (err) {
      console.error(err);
      alert('Failed to calculate risk score');
    }
  };

  const handleViewRiskDetails = async (appId) => {
    try {
      const response = await fetchRiskScore(appId);
      setSelectedRiskDetails(response.data);
      setShowRiskModal(true);
    } catch (err) {
      console.error(err);
      alert('No risk score found for this application. Calculate one first.');
    }
  };

  const handleOpenSBOMUpload = (app) => {
    setSelectedAppForSBOM(app);
    setSbomFile(null);
    setShowSBOMModal(true);
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSbomFile(file);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) {
      setSbomFile(file);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleSBOMUpload = async () => {
    if (!sbomFile || !selectedAppForSBOM) {
      alert('Please select a file');
      return;
    }
    setUploading(true);
    try {
      await uploadSBOM(selectedAppForSBOM.id, sbomFile);
      alert('SBOM uploaded successfully');
      setShowSBOMModal(false);
      loadApplications();
    } catch (err) {
      console.error(err);
      alert('Failed to upload SBOM');
    } finally {
      setUploading(false);
    }
  };

  if (loading) return <LoadingSpinner />;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 600, color: '#202020', margin: '0 0 8px 0' }}>Application Inventory</h1>
          <p style={{ fontSize: '14px', color: '#606060', margin: 0 }}>Manage applications and their risk assessments</p>
        </div>
        {canWrite && (
          <button onClick={handleCreate} style={{ backgroundColor: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', fontWeight: 500, cursor: 'pointer' }}>
            Add Application
          </button>
        )}
      </div>

      <div style={{ backgroundColor: '#FFFFFF', border: '1px solid #D9D9D9', borderRadius: '8px', boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '13px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #D9D9D9' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Name</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Owner</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Criticality</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Risk Score</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontWeight: 600, color: '#606060' }}>Environment</th>
              <th style={{ padding: '12px 16px', textAlign: 'right', fontWeight: 600, color: '#606060' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {apps.length === 0 ? (
              <tr><td colSpan="6" style={{ padding: '40px', textAlign: 'center', color: '#606060' }}>No applications yet</td></tr>
            ) : (
              apps.map((app) => {
                const riskScore = riskScores[app.id];
                return (
                  <tr key={app.id} style={{ borderBottom: '1px solid #E5E5E5' }}>
                    <td style={{ padding: '12px 16px', color: '#202020', fontWeight: 500 }}>{app.name}</td>
                    <td style={{ padding: '12px 16px', color: '#606060' }}>{app.owner || '—'}</td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: 500, backgroundColor: app.criticality === 'critical' ? '#FDE8E8' : app.criticality === 'high' ? '#FFF4E5' : '#E6F4EA', color: app.criticality === 'critical' ? '#D13438' : app.criticality === 'high' ? '#F4B400' : '#107C10' }}>{app.criticality ? app.criticality.charAt(0).toUpperCase() + app.criticality.slice(1).toLowerCase() : '—'}</span>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      {riskScore ? (
                        <div>
                          <span style={{ fontWeight: 600, color: '#202020' }}>{riskScore.overall_score?.toFixed(1) || 'N/A'}</span>
                          <span style={{ marginLeft: '8px', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 500, textTransform: 'uppercase', backgroundColor: riskScore.rating === 'Critical' ? '#FDE8E8' : riskScore.rating === 'Very High' ? '#FECACA' : riskScore.rating === 'High' ? '#FFF4E5' : riskScore.rating === 'Moderate' ? '#FEF9C3' : '#DCFCE7', color: riskScore.rating === 'Critical' ? '#D13438' : riskScore.rating === 'Very High' ? '#DC2626' : riskScore.rating === 'High' ? '#F4B400' : riskScore.rating === 'Moderate' ? '#EAB308' : '#22C55E' }}>{riskScore.rating || 'Unknown'}</span>
                        </div>
                      ) : (
                        <span style={{ color: '#8A8A8A', fontStyle: 'italic' }}>Not calculated</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px', color: '#606060' }}>{app.environment || '—'}</td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      {canWrite && (
                        <button onClick={() => handleOpenSBOMUpload(app)} style={{ background: 'none', border: 'none', color: '#0076CE', cursor: 'pointer', fontSize: '13px', marginRight: '12px' }}>Upload SBOM</button>
                      )}
                      {canWrite && (
                        <button onClick={() => handleCalculateRisk(app.id)} style={{ background: 'none', border: 'none', color: '#107C10', cursor: 'pointer', fontSize: '13px', marginRight: '12px' }}>Calculate Risk</button>
                      )}
                      {riskScore && (
                        <button onClick={() => handleViewRiskDetails(app.id)} style={{ background: 'none', border: 'none', color: '#0076CE', cursor: 'pointer', fontSize: '13px', marginRight: '12px' }}>View Details</button>
                      )}
                      {canWrite && (
                        <button onClick={() => handleEdit(app)} style={{ background: 'none', border: 'none', color: '#0076CE', cursor: 'pointer', fontSize: '13px', marginRight: '12px' }}>Edit</button>
                      )}
                      {canDelete && (
                        <button onClick={() => handleDelete(app.id)} style={{ background: 'none', border: 'none', color: '#D13438', cursor: 'pointer', fontSize: '13px' }}>Delete</button>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '500px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>{editingApp ? 'Edit Application' : 'Add Application'}</h2>
            </div>
            <form onSubmit={handleSubmit} style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Name <span style={{ color: '#D13438' }}>*</span></label>
                <input type="text" required value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Description</label>
                <textarea value={formData.description} onChange={(e) => setFormData({ ...formData, description: e.target.value })} rows="3" style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Owner</label>
                <input type="text" value={formData.owner} onChange={(e) => setFormData({ ...formData, owner: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }} />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Criticality</label>
                <select value={formData.criticality} onChange={(e) => setFormData({ ...formData, criticality: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Vendor</label>
                <select value={formData.vendor_id} onChange={(e) => setFormData({ ...formData, vendor_id: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
                  <option value="">Select Vendor</option>
                  {vendors.map((v) => <option key={v.id} value={v.id}>{v.name}</option>)}
                </select>
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500, color: '#606060' }}>Environment</label>
                <select value={formData.environment} onChange={(e) => setFormData({ ...formData, environment: e.target.value })} style={{ width: '100%', padding: '8px 12px', fontSize: '14px', border: '1px solid #D9D9D9', borderRadius: '4px', color: '#202020' }}>
                  <option value="development">Development</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </select>
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'flex', alignItems: 'center', fontSize: '13px', fontWeight: 500, color: '#606060' }}>
                  <input type="checkbox" checked={formData.internet_facing} onChange={(e) => setFormData({ ...formData, internet_facing: e.target.checked })} style={{ marginRight: '8px' }} />
                  Internet Facing
                </label>
              </div>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E5E5E5' }}>
                <button type="button" onClick={() => setShowModal(false)} style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Cancel</button>
                <button type="submit" style={{ background: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>{editingApp ? 'Update' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showSBOMModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '500px', maxWidth: '90%', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>Upload SBOM</h2>
              <p style={{ fontSize: '13px', color: '#606060', margin: '8px 0 0 0' }}>Application: {selectedAppForSBOM?.name} (ID: {selectedAppForSBOM?.id})</p>
            </div>
            <div style={{ padding: '24px' }}>
              <div
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                style={{
                  border: '2px dashed #D9D9D9',
                  borderRadius: '8px',
                  padding: '40px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  backgroundColor: '#F7F8FA'
                }}
                onClick={() => document.getElementById('sbom-file-input').click()}
              >
                <input
                  id="sbom-file-input"
                  type="file"
                  accept=".json,.xml,.spdx,.cyclonedx"
                  onChange={handleFileSelect}
                  style={{ display: 'none' }}
                />
                <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style={{ marginBottom: '16px' }}>
                  <path d="M24 4L8 12V36L24 44L40 36V12L24 4Z" stroke="#0076CE" strokeWidth="2" fill="none" />
                  <path d="M24 4V24" stroke="#0076CE" strokeWidth="2" />
                  <path d="M24 24L40 12" stroke="#0076CE" strokeWidth="2" />
                  <path d="M24 24L8 12" stroke="#0076CE" strokeWidth="2" />
                </svg>
                <p style={{ fontSize: '14px', color: '#202020', marginBottom: '8px' }}>
                  {sbomFile ? sbomFile.name : 'Drag and drop SBOM file here or click to browse'}
                </p>
                <p style={{ fontSize: '12px', color: '#606060' }}>Supported formats: CycloneDX JSON, SPDX JSON</p>
              </div>
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '24px', borderTop: '1px solid #E5E5E5', marginTop: '24px' }}>
                <button
                  type="button"
                  onClick={() => setShowSBOMModal(false)}
                  disabled={uploading}
                  style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: uploading ? 'not-allowed' : 'pointer' }}
                >
                  Cancel
                </button>
                <button
                  onClick={handleSBOMUpload}
                  disabled={uploading || !sbomFile}
                  style={{ background: '#0076CE', color: '#FFFFFF', border: 'none', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: uploading || !sbomFile ? 'not-allowed' : 'pointer' }}
                >
                  {uploading ? 'Uploading...' : 'Upload'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {showRiskModal && selectedRiskDetails && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0, 0, 0, 0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div style={{ backgroundColor: '#FFFFFF', borderRadius: '8px', width: '600px', maxWidth: '90%', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 4px 8px rgba(0, 0, 0, 0.12)' }}>
            <div style={{ padding: '24px', borderBottom: '1px solid #E5E5E5', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: '18px', fontWeight: 600, color: '#202020', margin: 0 }}>Risk Score Details</h2>
              <button onClick={() => setShowRiskModal(false)} style={{ background: 'none', border: 'none', fontSize: '20px', cursor: 'pointer', color: '#606060' }}>&times;</button>
            </div>
            <div style={{ padding: '24px' }}>
              <div style={{ marginBottom: '24px', textAlign: 'center', padding: '20px', backgroundColor: '#F7F8FA', borderRadius: '8px' }}>
                <div style={{ fontSize: '48px', fontWeight: 700, color: selectedRiskDetails.rating === 'Critical' ? '#D13438' : selectedRiskDetails.rating === 'Very High' ? '#DC2626' : selectedRiskDetails.rating === 'High' ? '#F4B400' : selectedRiskDetails.rating === 'Moderate' ? '#EAB308' : '#22C55E' }}>
                  {selectedRiskDetails.overall_score?.toFixed(1) || 'N/A'}
                </div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: '#606060', marginTop: '8px', textTransform: 'uppercase' }}>
                  {selectedRiskDetails.rating || 'Unknown'}
                </div>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>Risk Breakdown</h3>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>CVSS Weighted</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.cvss_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>Criticality</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.criticality_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>Exposure</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.exposure_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>Exploit Risk</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.exploit_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>Patch Delay</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.patch_delay_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#606060', marginBottom: '4px' }}>Vendor Risk</div>
                    <div style={{ fontSize: '18px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.vendor_risk_weighted?.toFixed(2) || 'N/A'}</div>
                  </div>
                </div>
              </div>

              <div style={{ marginBottom: '24px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#202020', marginBottom: '12px' }}>CVE Summary</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
                  <div style={{ padding: '12px', backgroundColor: '#F7F8FA', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 600, color: '#202020' }}>{selectedRiskDetails.total_cves_found || 0}</div>
                    <div style={{ fontSize: '11px', color: '#606060', marginTop: '4px' }}>Total CVEs</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#FDE8E8', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 600, color: '#D13438' }}>{selectedRiskDetails.critical_cves_count || 0}</div>
                    <div style={{ fontSize: '11px', color: '#606060', marginTop: '4px' }}>Critical</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#FECACA', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 600, color: '#DC2626' }}>{selectedRiskDetails.high_cves_count || 0}</div>
                    <div style={{ fontSize: '11px', color: '#606060', marginTop: '4px' }}>High</div>
                  </div>
                  <div style={{ padding: '12px', backgroundColor: '#FEF9C3', borderRadius: '6px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 600, color: '#EAB308' }}>{selectedRiskDetails.medium_cves_count || 0}</div>
                    <div style={{ fontSize: '11px', color: '#606060', marginTop: '4px' }}>Medium</div>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end', paddingTop: '16px', borderTop: '1px solid #E5E5E5' }}>
                <button onClick={() => setShowRiskModal(false)} style={{ background: '#FFFFFF', color: '#606060', border: '1px solid #D9D9D9', padding: '8px 16px', borderRadius: '4px', fontSize: '14px', cursor: 'pointer' }}>Close</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ApplicationsPage;
