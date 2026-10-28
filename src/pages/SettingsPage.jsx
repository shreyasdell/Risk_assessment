import React, { useState, useEffect } from 'react';
import { getUsers, createUser, updateUser, deleteUser } from '../api/client';
import { useAuth } from '../context/AuthContext';

function SettingsPage() {
  const { user: currentUser, canManageUsers } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [editingUser, setEditingUser] = useState(null);
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    role: 'viewer'
  });
  const [error, setError] = useState('');

  useEffect(() => {
    if (canManageUsers()) {
      fetchUsers();
    }
  }, [canManageUsers]);

  const fetchUsers = async () => {
    try {
      const response = await getUsers();
      setUsers(response.data);
    } catch (err) {
      console.error('Error fetching users:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    try {
      if (editingUser) {
        // Update existing user
        await updateUser(editingUser.id, {
          email: formData.email,
          role: formData.role,
          is_active: formData.is_active
        });
      } else {
        // Create new user
        await createUser({
          username: formData.username,
          email: formData.email,
          password: formData.password,
          role: formData.role
        });
      }
      setShowModal(false);
      setEditingUser(null);
      setFormData({ username: '', email: '', password: '', role: 'viewer' });
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to save user');
    }
  };

  const handleEdit = (user) => {
    setEditingUser(user);
    setFormData({
      username: user.username,
      email: user.email,
      password: '',
      role: user.role,
      is_active: user.is_active
    });
    setShowModal(true);
  };

  const handleDelete = async (userId) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;

    try {
      await deleteUser(userId);
      fetchUsers();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to delete user');
    }
  };

  const handleCreateNew = () => {
    setEditingUser(null);
    setFormData({ username: '', email: '', password: '', role: 'viewer' });
    setShowModal(true);
  };

  if (!canManageUsers()) {
    return (
      <div style={{ padding: '24px' }}>
        <h2 style={{ marginBottom: '16px' }}>Access Denied</h2>
        <p>You don't have permission to access this page.</p>
      </div>
    );
  }

  if (loading) {
    return <div style={{ padding: '24px' }}>Loading...</div>;
  }

  return (
    <div style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 600, margin: 0 }}>User Management</h1>
        <button
          onClick={handleCreateNew}
          style={{
            backgroundColor: '#0076CE',
            color: '#FFFFFF',
            border: 'none',
            padding: '10px 20px',
            borderRadius: '6px',
            fontSize: '14px',
            fontWeight: 500,
            cursor: 'pointer'
          }}
        >
          Add User
        </button>
      </div>

      {error && (
        <div style={{
          backgroundColor: '#FDE8E8',
          border: '1px solid #D13438',
          borderRadius: '6px',
          padding: '12px 16px',
          marginBottom: '24px',
          color: '#A4262A'
        }}>
          {error}
        </div>
      )}

      <div style={{
        backgroundColor: '#FFFFFF',
        borderRadius: '8px',
        border: '1px solid #E0E0E0',
        overflow: 'hidden'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: '#F5F7FA', borderBottom: '1px solid #E0E0E0' }}>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: '#5A5A5A' }}>Username</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: '#5A5A5A' }}>Email</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: '#5A5A5A' }}>Role</th>
              <th style={{ padding: '12px 16px', textAlign: 'left', fontSize: '13px', fontWeight: 600, color: '#5A5A5A' }}>Status</th>
              <th style={{ padding: '12px 16px', textAlign: 'right', fontSize: '13px', fontWeight: 600, color: '#5A5A5A' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id} style={{ borderBottom: '1px solid #E0E0E0' }}>
                <td style={{ padding: '12px 16px', fontSize: '14px', color: '#1A1A1A' }}>{user.username}</td>
                <td style={{ padding: '12px 16px', fontSize: '14px', color: '#5A5A5A' }}>{user.email}</td>
                <td style={{ padding: '12px 16px', fontSize: '14px', color: '#1A1A1A' }}>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 500,
                    backgroundColor: user.role === 'admin' ? '#E5F3FF' : user.role === 'analyst' ? '#FFF4E5' : '#F5F7FA',
                    color: user.role === 'admin' ? '#0076CE' : user.role === 'analyst' ? '#FF8C00' : '#5A5A5A'
                  }}>
                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                  </span>
                </td>
                <td style={{ padding: '12px 16px', fontSize: '14px', color: '#1A1A1A' }}>
                  <span style={{
                    padding: '4px 8px',
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 500,
                    backgroundColor: user.is_active ? '#E8F5E9' : '#FDE8E8',
                    color: user.is_active ? '#2E7D32' : '#D13438'
                  }}>
                    {user.is_active ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                  <button
                    onClick={() => handleEdit(user)}
                    disabled={user.id === currentUser.id}
                    style={{
                      backgroundColor: 'transparent',
                      border: '1px solid #E0E0E0',
                      color: '#0076CE',
                      padding: '6px 12px',
                      borderRadius: '4px',
                      fontSize: '13px',
                      cursor: user.id === currentUser.id ? 'not-allowed' : 'pointer',
                      marginRight: '8px'
                    }}
                  >
                    Edit
                  </button>
                  <button
                    onClick={() => handleDelete(user.id)}
                    disabled={user.id === currentUser.id}
                    style={{
                      backgroundColor: 'transparent',
                      border: '1px solid #E0E0E0',
                      color: '#D13438',
                      padding: '6px 12px',
                      borderRadius: '4px',
                      fontSize: '13px',
                      cursor: user.id === currentUser.id ? 'not-allowed' : 'pointer'
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2000
        }}>
          <div style={{
            backgroundColor: '#FFFFFF',
            borderRadius: '8px',
            padding: '24px',
            width: '100%',
            maxWidth: '400px'
          }}>
            <h2 style={{ fontSize: '20px', fontWeight: 600, marginBottom: '16px' }}>
              {editingUser ? 'Edit User' : 'Add User'}
            </h2>
            <form onSubmit={handleSubmit}>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500 }}>
                  Username
                </label>
                <input
                  type="text"
                  value={formData.username}
                  onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                  disabled={!!editingUser}
                  required
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #E0E0E0',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                />
              </div>
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500 }}>
                  Email
                </label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  required
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #E0E0E0',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                />
              </div>
              {!editingUser && (
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500 }}>
                    Password
                  </label>
                  <input
                    type="password"
                    value={formData.password}
                    onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                    required
                    style={{
                      width: '100%',
                      padding: '10px 12px',
                      border: '1px solid #E0E0E0',
                      borderRadius: '4px',
                      fontSize: '14px'
                    }}
                  />
                </div>
              )}
              <div style={{ marginBottom: '16px' }}>
                <label style={{ display: 'block', marginBottom: '8px', fontSize: '13px', fontWeight: 500 }}>
                  Role
                </label>
                <select
                  value={formData.role}
                  onChange={(e) => setFormData({ ...formData, role: e.target.value })}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: '1px solid #E0E0E0',
                    borderRadius: '4px',
                    fontSize: '14px'
                  }}
                >
                  <option value="viewer">Viewer</option>
                  <option value="analyst">Analyst</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              {editingUser && (
                <div style={{ marginBottom: '16px' }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <input
                      type="checkbox"
                      checked={formData.is_active}
                      onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
                    />
                    Active
                  </label>
                </div>
              )}
              <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  style={{
                    backgroundColor: 'transparent',
                    border: '1px solid #E0E0E0',
                    color: '#5A5A5A',
                    padding: '10px 20px',
                    borderRadius: '4px',
                    fontSize: '14px',
                    cursor: 'pointer'
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    backgroundColor: '#0076CE',
                    color: '#FFFFFF',
                    border: 'none',
                    padding: '10px 20px',
                    borderRadius: '4px',
                    fontSize: '14px',
                    cursor: 'pointer'
                  }}
                >
                  {editingUser ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default SettingsPage;
