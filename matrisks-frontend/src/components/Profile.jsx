import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import SharedNavbar from './SharedNavbar';
import styles from './Profile.module.css';
import { getAnalysisHistory } from '../services/api'; // Import the API service

const Profile = () => {
  const { currentUser, error, logout, updateProfile } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    username: '',
    email: '',
    password: '',
    confirm_password: '',
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState({ type: '', text: '' });
  const [isVisible, setIsVisible] = useState(false);
  const [analysisHistory, setAnalysisHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [refreshTrigger, setRefreshTrigger] = useState(0); // Add a trigger to force refresh
  const [activeSection, setActiveSection] = useState(
    location.state?.section === 'history' ? 'history' : 'profile'
  ); // 'profile' or 'history'

  // Function to fetch analysis history
  const fetchAnalysisHistory = async () => {
    if (!currentUser) return;
    
    try {
      setHistoryLoading(true);
      
      // Clear any previous error messages
      if (message.text === 'Failed to load analysis history') {
        setMessage({ type: '', text: '' });
      }
      
      // Get the history from the API
      const history = await getAnalysisHistory();
      
      console.log('[Profile] Received history:', history);
      console.log('[Profile] History length:', history ? history.length : 0);
      
      // Sort by timestamp (newest first)
      const sortedHistory = [...history].sort((a, b) => 
        new Date(b.timestamp) - new Date(a.timestamp)
      );
      
      console.log('[Profile] Setting analysisHistory with', sortedHistory.length, 'items');
      setAnalysisHistory(sortedHistory);
      
    } catch (error) {
      console.error('Failed to fetch analysis history:', error);
      // Only show error if we don't have any data to display
      if (analysisHistory.length === 0) {
        setMessage({ 
          type: 'error', 
          text: 'Using demo data. Connect to the backend for real analysis history.' 
        });
      }
    } finally {
      setHistoryLoading(false);
    }
  };

  // Set up polling for analysis history
  useEffect(() => {
    if (!currentUser) return;
    
    let isMounted = true;
    
    const fetchWithRetry = async () => {
      try {
        await fetchAnalysisHistory();
      } catch (error) {
        console.error('Error in fetchWithRetry:', error);
      }
    };
    
    // Initial fetch
    fetchWithRetry();
    
    // Set up polling every 10 seconds (reduced from 30 for better responsiveness)
    const intervalId = setInterval(fetchWithRetry, 10000);
    
    // Clean up interval on component unmount
    return () => {
      isMounted = false;
      clearInterval(intervalId);
    };
  }, [currentUser, refreshTrigger]);
  
  // Initialize form with user data
  useEffect(() => {
    if (currentUser) {
      setFormData({
        first_name: currentUser.first_name || '',
        last_name: currentUser.last_name || '',
        username: currentUser.username || '',
        email: currentUser.email || '',
        password: '',
        confirm_password: '',
      });
    }

    // Animation for page entrance
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);

    return () => clearTimeout(timer);
  }, [currentUser]);

  // Update form field
  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  // Submit form to update profile
  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage({ type: '', text: '' });
    
    // Validate passwords match
    if (formData.password && formData.password !== formData.confirm_password) {
      setMessage({ type: 'error', text: 'Passwords do not match' });
      return;
    }

    // Only include fields that have changed
    const changedData = {};
    if (formData.first_name !== (currentUser?.first_name || '')) changedData.first_name = formData.first_name;
    if (formData.last_name !== (currentUser?.last_name || '')) changedData.last_name = formData.last_name;
    if (formData.username !== (currentUser?.username || '')) changedData.username = formData.username;
    if (formData.email !== (currentUser?.email || '')) changedData.email = formData.email;
    if (formData.password) changedData.password = formData.password;

    // If nothing changed, show message and return
    if (Object.keys(changedData).length === 0) {
      setMessage({ type: 'info', text: 'No changes to save' });
      return;
    }

    try {
      setLoading(true);
      await updateProfile(changedData);
      setMessage({ type: 'success', text: 'Profile updated successfully' });
      
      // Clear password fields after successful update
      setFormData(prev => ({
        ...prev,
        password: '',
        confirm_password: ''
      }));
    } catch (err) {
      setMessage({ 
        type: 'error', 
        text: error || 'Failed to update profile. Please try again.' 
      });
    } finally {
      setLoading(false);
    }
  };

  // Go back to dashboard
  const handleCancel = () => {
    navigate('/dashboard');
  };

  if (!currentUser) {
    return <div className={styles.loadingContainer}>Loading user data...</div>;
  }

  return (
    <div className={`${styles.profileWrapper} ${isVisible ? styles.visible : ''}`}>
      {/* Particle Background */}
      <div className={styles.particleBackground} />
      
      {/* Shared Navbar */}
      <SharedNavbar activeProfileSection={activeSection} setActiveProfileSection={setActiveSection} />

      <main className={styles.profileContainer}>
        {/* Edit Profile Section */}
        {activeSection === 'profile' && (
        <div className={styles.profileSection}>
          <div className={styles.profileCard}>
            <h1 className={styles.profileTitle}>Edit Profile</h1>
            
            {message.text && message.text !== 'Using demo data. Connect to the backend for real analysis history.' && (
              <div className={`${styles.message} ${styles[message.type]}`}>
                {message.text}
              </div>
            )}
          
          <form onSubmit={handleSubmit} className={styles.profileForm}>
            <div className={styles.formRow}>
              <div className={styles.formGroup}>
                <label htmlFor="first_name">First Name</label>
                <input
                  type="text"
                  id="first_name"
                  name="first_name"
                  value={formData.first_name}
                  onChange={handleChange}
                  className={styles.formInput}
                  placeholder="First Name"
                />
              </div>
              
              <div className={styles.formGroup}>
                <label htmlFor="last_name">Last Name</label>
                <input
                  type="text"
                  id="last_name"
                  name="last_name"
                  value={formData.last_name}
                  onChange={handleChange}
                  className={styles.formInput}
                  placeholder="Last Name"
                />
              </div>
            </div>
            
            <div className={styles.formGroup}>
              <label htmlFor="username">Username</label>
              <input
                type="text"
                id="username"
                name="username"
                value={formData.username}
                onChange={handleChange}
                className={styles.formInput}
                placeholder="Username"
                required
              />
            </div>
            
            <div className={styles.formGroup}>
              <label htmlFor="email">Email</label>
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className={styles.formInput}
                placeholder="Email"
                required
              />
            </div>
            
            <div className={styles.formRow}>
              <div className={styles.formGroup}>
                <label htmlFor="password">New Password</label>
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  className={styles.formInput}
                  placeholder="Leave blank to keep current"
                />
                <small className={styles.passwordHint}>
                  Minimum 8 characters, with uppercase, lowercase, and number
                </small>
              </div>
              
              <div className={styles.formGroup}>
                <label htmlFor="confirm_password">Confirm Password</label>
                <input
                  type="password"
                  id="confirm_password"
                  name="confirm_password"
                  value={formData.confirm_password}
                  onChange={handleChange}
                  className={styles.formInput}
                  placeholder="Confirm new password"
                />
              </div>
            </div>
            
            <div className={styles.buttonGroup}>
              <button
                type="button"
                onClick={handleCancel}
                className={styles.cancelButton}
                disabled={loading}
              >
                Cancel
              </button>
              
              <button
                type="submit"
                className={styles.saveButton}
                disabled={loading}
              >
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
          </div>
        </div>
        )}
        
        {/* Analysis History Section - Separate Card */}
        {activeSection === 'history' && (
        <div className={styles.historySection}>
          <div className={styles.historyCard}>
            <div className={styles.sectionHeader}>
              <h2 className={styles.sectionTitle}>Analysis History</h2>
              <button 
                onClick={() => setRefreshTrigger(prev => prev + 1)}
                className={styles.refreshButton}
                disabled={historyLoading}
                title="Refresh history"
              >
                {historyLoading ? 'Refreshing...' : '↻ Refresh'}
              </button>
            </div>
            
            {message.text === 'Using demo data. Connect to the backend for real analysis history.' && (
              <div className={`${styles.message} ${styles.info}`}>
                {message.text}
              </div>
            )}
            
            {historyLoading && !analysisHistory.length ? (
              <div className={styles.loadingText}>Loading analysis history...</div>
            ) : analysisHistory.length > 0 ? (
              <div className={styles.tableContainer}>
                <table className={styles.historyTable}>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>APK Name</th>
                      <th>Analysis Type</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analysisHistory.map((item, index) => (
                      <tr key={item.id}>
                        <td>{index + 1}</td>
                        <td>{item.apk_name}</td>
                        <td>{item.analysis_type}</td>
                        <td>{new Date(item.timestamp).toLocaleString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className={styles.noHistory}>No analysis history found.</div>
            )}
          </div>
        </div>
        )}
      </main>
    </div>
  );
};

export default Profile;
