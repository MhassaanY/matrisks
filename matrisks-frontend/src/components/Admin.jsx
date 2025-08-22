import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './Admin.module.css';
import { getUsers, deleteUser, getAnalysisEngines } from '../services/api';

const Admin = () => {
  const { currentUser, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState('users'); // 'users' or 'engines'
  const [users, setUsers] = useState([]);
  const [engines, setEngines] = useState([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [isVisible, setIsVisible] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(null);

  // Check if user is admin
  useEffect(() => {
    if (!currentUser || !isAdmin) {
      navigate('/dashboard');
    }
  }, [currentUser, isAdmin, navigate]);

  // Animation for page entrance
  useEffect(() => {
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  // Fetch users data
  const fetchUsers = async () => {
    try {
      setLoading(true);
      const userData = await getUsers();
      setUsers(userData);
      setMessage({ type: '', text: '' });
    } catch (error) {
      console.error('Failed to fetch users:', error);
      setMessage({ type: 'error', text: 'Failed to load users' });
    } finally {
      setLoading(false);
    }
  };

  // Fetch engines data
  const fetchEngines = async () => {
    try {
      setLoading(true);
      const enginesData = await getAnalysisEngines();
      setEngines(enginesData);
      setMessage({ type: '', text: '' });
    } catch (error) {
      console.error('Failed to fetch analysis engines:', error);
      setMessage({ type: 'error', text: 'Failed to load analysis engines' });
    } finally {
      setLoading(false);
    }
  };

  // Load data based on active section
  useEffect(() => {
    if (activeSection === 'users') {
      fetchUsers();
    } else if (activeSection === 'engines') {
      fetchEngines();
    }
  }, [activeSection]);

  // Handle delete user
  const handleDeleteUser = async (userId) => {
    try {
      setLoading(true);
      await deleteUser(userId);
      // Refresh the user list
      fetchUsers();
      setMessage({ type: 'success', text: 'User deleted successfully' });
      setConfirmDelete(null);
    } catch (error) {
      console.error('Failed to delete user:', error);
      setMessage({ type: 'error', text: 'Failed to delete user' });
    } finally {
      setLoading(false);
    }
  };

  // Show delete confirmation
  const showDeleteConfirmation = (userId) => {
    setConfirmDelete(userId);
  };

  // Cancel delete
  const cancelDelete = () => {
    setConfirmDelete(null);
  };

  // Render user table
  const renderUserTable = () => {
    if (loading && users.length === 0) {
      return <div className={styles.loading}>Loading users...</div>;
    }

    if (users.length === 0) {
      return <div className={styles.noData}>No users found</div>;
    }

    return (
      <div className={styles.tableContainer}>
        <table className={styles.dataTable}>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Email</th>
              <th>Name</th>
              <th>Admin</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>{user.id}</td>
                <td>{user.username}</td>
                <td>{user.email}</td>
                <td>{`${user.first_name || ''} ${user.last_name || ''}`}</td>
                <td>{user.is_admin ? 'Yes' : 'No'}</td>
                <td>
                  {confirmDelete === user.id ? (
                    <div className={styles.confirmDelete}>
                      <span>Are you sure?</span>
                      <button 
                        onClick={() => handleDeleteUser(user.id)}
                        className={styles.confirmBtn}
                        disabled={loading}
                      >
                        Yes
                      </button>
                      <button 
                        onClick={cancelDelete}
                        className={styles.cancelBtn}
                        disabled={loading}
                      >
                        No
                      </button>
                    </div>
                  ) : (
                    <button 
                      onClick={() => showDeleteConfirmation(user.id)}
                      className={styles.deleteBtn}
                      disabled={loading}
                    >
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Render engines table
  const renderEnginesTable = () => {
    if (loading && engines.length === 0) {
      return <div className={styles.loading}>Loading analysis engines...</div>;
    }

    if (engines.length === 0) {
      return <div className={styles.noData}>No analysis engines found</div>;
    }

    return (
      <div className={styles.tableContainer}>
        <table className={styles.dataTable}>
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Description</th>
              <th>Status</th>
              <th>Version</th>
            </tr>
          </thead>
          <tbody>
            {engines.map((engine) => (
              <tr key={engine.id}>
                <td>{engine.id}</td>
                <td>{engine.name}</td>
                <td>{engine.description}</td>
                <td>
                  <span className={`${styles.status} ${styles[engine.status]}`}>
                    {engine.status}
                  </span>
                </td>
                <td>{engine.version}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <div className={`${styles.adminWrapper} ${isVisible ? styles.visible : ''}`}>
      {/* Particle Background */}
      <div className={styles.particleBackground} />
      
      {/* Dashboard Navbar */}
      <nav className={styles.navbar}>
        <div className={styles.navbarLeft}>
          {/* Empty div for spacing */}
        </div>
        <div className={styles.navbarCenter}>
          <h2 className={styles.dashboardTitle}>Admin Dashboard</h2>
        </div>
        <div className={styles.navbarRight}>
          <button 
            onClick={() => navigate('/dashboard')} 
            className={styles.navLink}
          >
            Dashboard
          </button>
          <button 
            onClick={() => navigate('/profile')} 
            className={styles.navLink}
          >
            Profile
          </button>
          <button 
            onClick={() => navigate('/signin')} 
            className={styles.navLink}
          >
            Logout
          </button>
        </div>
      </nav>

      <main className={styles.adminContainer}>
        <div className={styles.adminControls}>
          <button 
            className={`${styles.sectionButton} ${activeSection === 'users' ? styles.active : ''}`}
            onClick={() => setActiveSection('users')}
          >
            Manage User Accounts
          </button>
          <button 
            className={`${styles.sectionButton} ${activeSection === 'engines' ? styles.active : ''}`}
            onClick={() => setActiveSection('engines')}
          >
            View Analysis Engines
          </button>
        </div>

        {message.text && (
          <div className={`${styles.message} ${styles[message.type]}`}>
            {message.text}
          </div>
        )}

        <div className={styles.adminCard}>
          <h1 className={styles.sectionTitle}>
            {activeSection === 'users' ? 'Manage User Accounts' : 'Analysis Engines'}
          </h1>
          
          <div className={styles.refreshContainer}>
            <button 
              onClick={activeSection === 'users' ? fetchUsers : fetchEngines}
              className={styles.refreshButton}
              disabled={loading}
            >
              {loading ? 'Refreshing...' : '↻ Refresh'}
            </button>
          </div>

          {activeSection === 'users' ? renderUserTable() : renderEnginesTable()}
        </div>
      </main>
    </div>
  );
};

export default Admin;
