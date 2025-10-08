import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import SharedNavbar from './SharedNavbar';
import styles from './Admin.module.css';
import { getUsers, deleteUser, getAnalysisEngines, getAdminAnalysisHistory } from '../services/api';

const Admin = () => {
  const { currentUser, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [activeSection, setActiveSection] = useState('users'); // 'users', 'engines', or 'history'
  const [users, setUsers] = useState([]);
  const [engines, setEngines] = useState([]);
  const [analysisHistory, setAnalysisHistory] = useState([]);
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

  // Fetch analysis history data
  const fetchAnalysisHistory = async () => {
    try {
      setLoading(true);
      const historyData = await getAdminAnalysisHistory();
      
      console.log('[Admin] RAW API Response:', historyData);
      console.log('[Admin] Total records received:', historyData?.length || 0);
      
      if (!historyData || !Array.isArray(historyData)) {
        console.error('[Admin] Invalid history data format');
        setAnalysisHistory([]);
        setMessage({ type: 'error', text: 'Failed to load analysis history' });
        return;
      }
      
      // Log first 5 records with their IDs and timestamps
      console.log('[Admin] First 5 records:');
      historyData.slice(0, 5).forEach((record, idx) => {
        console.log(`  ${idx + 1}. ${record.id} - ${record.apk_name} @ ${record.timestamp}`);
      });
      
      setAnalysisHistory(historyData);
      setMessage({ type: '', text: '' });
    } catch (error) {
      console.error('[Admin] Failed to fetch analysis history:', error);
      setMessage({ type: 'error', text: 'Failed to load analysis history' });
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
    } else if (activeSection === 'history') {
      fetchAnalysisHistory();
      
      // Set up polling for analysis history (refresh every 10 seconds)
      const intervalId = setInterval(() => {
        fetchAnalysisHistory();
      }, 10000);
      
      // Clean up interval when section changes or component unmounts
      return () => {
        clearInterval(intervalId);
      };
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
                <td>{user.is_admin || user.is_superuser ? 'Yes' : 'No'}</td>
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
              <th>Supported Formats</th>
              <th>Last Updated</th>
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
                <td>
                  <div className={styles.formatTags}>
                    {engine.supported_formats?.map((format) => (
                      <span key={format} className={styles.formatTag}>
                        {format.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </td>
                <td>{new Date(engine.last_updated).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Render analysis history table
  const renderAnalysisHistoryTable = () => {
    if (loading && analysisHistory.length === 0) {
      return <div className={styles.loading}>Loading analysis history...</div>;
    }

    if (analysisHistory.length === 0) {
      return <div className={styles.noData}>No analysis history found</div>;
    }

    console.log(`[Admin] Rendering table with ${analysisHistory.length} rows`);

    return (
      <div className={styles.tableContainer}>
        <div style={{ padding: '10px', background: '#2a2a3a', color: '#fff', marginBottom: '10px' }}>
          <strong>Total Records: {analysisHistory.length}</strong> | Showing rows 1-{analysisHistory.length}
        </div>
        <table className={styles.dataTable}>
          <thead>
            <tr>
              <th>Scan ID</th>
              <th>APK Name</th>
              <th>File Size</th>
              <th>Analysis Type</th>
              <th>User</th>
              <th>Timestamp</th>
              <th>Status</th>
              <th>Available Formats</th>
            </tr>
          </thead>
          <tbody>
            {analysisHistory.map((analysis) => (
              <tr key={analysis.id}>
                <td className={styles.scanId}>{analysis.id}</td>
                <td>{analysis.apk_name}</td>
                <td>{(analysis.file_size / (1024 * 1024)).toFixed(2)} MB</td>
                <td>{analysis.analysis_type}</td>
                <td>{analysis.user}</td>
                <td>{new Date(analysis.timestamp).toLocaleString()}</td>
                <td>
                  <span className={`${styles.status} ${styles[analysis.status]}`}>
                    {analysis.status}
                  </span>
                </td>
                <td>
                  <div className={styles.formatTags}>
                    {analysis.available_formats?.map((format) => (
                      <span key={format} className={styles.formatTag}>
                        {format.toUpperCase()}
                      </span>
                    ))}
                  </div>
                </td>
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
      
      {/* Shared Navbar */}
      <SharedNavbar activeAdminSection={activeSection} setActiveAdminSection={setActiveSection} />

      <main className={styles.adminContainer}>

        {message.text && (
          <div className={`${styles.message} ${styles[message.type]}`}>
            {message.text}
          </div>
        )}

        <div className={styles.adminCard}>
          <h1 className={styles.sectionTitle}>
            {activeSection === 'users' ? 'Manage User Accounts' : 
             activeSection === 'engines' ? 'Analysis Engines' : 'Analysis History'}
          </h1>
          
          <div className={styles.refreshContainer}>
            <button 
              onClick={activeSection === 'users' ? fetchUsers : 
                      activeSection === 'engines' ? fetchEngines : fetchAnalysisHistory}
              className={styles.refreshButton}
              disabled={loading}
            >
              {loading ? 'Refreshing...' : '↻ Refresh'}
            </button>
          </div>

          {activeSection === 'users' ? renderUserTable() : 
           activeSection === 'engines' ? renderEnginesTable() : renderAnalysisHistoryTable()}
        </div>
      </main>
    </div>
  );
};

export default Admin;
