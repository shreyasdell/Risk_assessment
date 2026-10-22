import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 15000,
});

apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      localStorage.removeItem('access_token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const loginUser = (credentials) => {
  console.log('Login request:', credentials);
  return apiClient.post('/auth/login', credentials);
};

export const registerUser = (data) =>
  apiClient.post('/auth/register', data);

export const getCurrentUser = () =>
  apiClient.get('/auth/me');

export const fetchDashboard = (params = {}) =>
  apiClient.get('/dashboard', { params });

export const fetchVendors = () =>
  apiClient.get('/vendors');

export const createVendor = (data) =>
  apiClient.post('/vendors', data);

export const updateVendor = (id, data) =>
  apiClient.put(`/vendors/${id}`, data);

export const deleteVendor = (id) =>
  apiClient.delete(`/vendors/${id}`);

export const fetchApplications = (params = {}) =>
  apiClient.get('/applications', { params });

export const createApplication = (data) =>
  apiClient.post('/applications', data);

export const updateApplication = (id, data) =>
  apiClient.put(`/applications/${id}`, data);

export const deleteApplication = (id) =>
  apiClient.delete(`/applications/${id}`);

export const uploadSBOM = (applicationId, file) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('application_id', applicationId);
  return apiClient.post('/components/upload-sbom', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};

export const fetchComponents = (params = {}) =>
  apiClient.get('/components', { params });

export const createComponent = (data) =>
  apiClient.post('/components', data);

export const updateComponent = (id, data) =>
  apiClient.put(`/components/${id}`, data);

export const deleteComponent = (id) =>
  apiClient.delete(`/components/${id}`);

// CVEs
export const fetchCVEs = (params = {}) =>
  apiClient.get('/cves', { params });

export const fetchCVE = (id) =>
  apiClient.get(`/cves/${id}`);

export const createCVE = (data) =>
  apiClient.post('/cves', data);

export const updateCVE = (id, data) =>
  apiClient.put(`/cves/${id}`, data);

export const deleteCVE = (id) =>
  apiClient.delete(`/cves/${id}`);

export const syncCVEs = (componentId, forceRefresh = false) =>
  apiClient.post(`/cves/sync/${componentId}`, null, {
    params: { force_refresh: forceRefresh }
  });

export const linkCVEToComponent = (cveId, componentId) =>
  apiClient.post('/cves/link', null, {
    params: { cve_id: cveId, component_id: componentId }
  });

export const unlinkCVEFromComponent = (cveId, componentId) =>
  apiClient.delete('/cves/unlink', {
    params: { cve_id: cveId, component_id: componentId }
  });

export const fetchLinkedCVEs = (componentId) =>
  apiClient.get(`/cves/component/${componentId}/linked`);

// Risk Scores
export const calculateRiskScore = (applicationId) =>
  apiClient.post(`/risk-scores/calculate/${applicationId}`);

export const calculateAllRiskScores = () =>
  apiClient.post('/risk-scores/calculate-all');

export const fetchRiskScore = (applicationId) =>
  apiClient.get(`/risk-scores/application/${applicationId}`);

export const fetchRiskScoreHistory = (applicationId) =>
  apiClient.get(`/risk-scores/application/${applicationId}/history`);

export const fetchAllRiskScores = () =>
  apiClient.get('/risk-scores');

// NIST Recommendations
export const fetchNISTRecommendations = () =>
  apiClient.get('/nist');

export const fetchNISTRecommendationByCWE = (cweId) =>
  apiClient.get(`/nist/cwe/${cweId}`);

export const fetchNISTRecommendationForCVE = (cveId) =>
  apiClient.get(`/nist/cve/${cveId}`);

export const createNISTRecommendation = (data) =>
  apiClient.post('/nist', data);

// Remediations
export const fetchRemediations = (params = {}) =>
  apiClient.get('/remediations', { params });

export const fetchRemediation = (id) =>
  apiClient.get(`/remediations/${id}`);

export const createRemediation = (data) =>
  apiClient.post('/remediations', data);

export const updateRemediation = (id, data) =>
  apiClient.put(`/remediations/${id}`, data);

export const deleteRemediation = (id) =>
  apiClient.delete(`/remediations/${id}`);

// Audit Logs
export const fetchAuditLogs = (params = {}) =>
  apiClient.get('/audit-logs', { params });

export const fetchRecentActivity = (limit = 20) =>
  apiClient.get('/audit-logs/recent', { params: { limit } });

export default apiClient;
