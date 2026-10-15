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

export const loginUser = (credentials) =>
  apiClient.post('/auth/login', credentials);

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

export default apiClient;
