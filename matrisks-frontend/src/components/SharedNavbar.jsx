import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './SharedNavbar.module.css';

const SharedNavbar = ({ activeAdminSection, setActiveAdminSection, activeProfileSection, setActiveProfileSection }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { logout, isAdmin } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/signin');
  };

  const isActive = (path, section = null) => {
    if (path === '/profile') {
      if (section === 'history') {
        return location.pathname === path && activeProfileSection === 'history';
      }
      return location.pathname === path && activeProfileSection === 'profile';
    }
    if (path === '/admin') {
      return location.pathname === path && activeAdminSection === section;
    }
    return location.pathname === path;
  };

  const getPageTitle = () => {
    if (location.pathname === '/dashboard') return 'Dashboard';
    if (location.pathname === '/profile') {
      if (activeProfileSection === 'history') return 'Analysis History';
      return 'Edit Profile';
    }
    if (location.pathname === '/admin') {
      if (activeAdminSection === 'users') return 'User Accounts';
      if (activeAdminSection === 'engines') return 'Analysis Engines';
      if (activeAdminSection === 'history') return 'All Analysis History';
      return 'Admin Dashboard';
    }
    if (location.pathname === '/analysis') return 'Analysis';
    return 'MatRisks';
  };

  const handleProfileClick = () => {
    if (location.pathname !== '/profile') {
      navigate('/profile', { state: { section: 'profile' } });
    }
    if (setActiveProfileSection) {
      setActiveProfileSection('profile');
    }
  };

  const handleHistoryClick = () => {
    if (location.pathname !== '/profile') {
      navigate('/profile', { state: { section: 'history' } });
    }
    if (setActiveProfileSection) {
      setActiveProfileSection('history');
    }
  };

  return (
    <nav className={styles.navbar}>
      <div className={styles.navbarLeft}>
        <h2 className={styles.logo}>MatRisks</h2>
      </div>
      
      <div className={styles.navbarCenter}>
        <h2 className={styles.pageTitle}>{getPageTitle()}</h2>
      </div>
      
      <div className={styles.navbarRight}>
        <button 
          onClick={() => navigate('/dashboard')} 
          className={`${styles.navLink} ${isActive('/dashboard') ? styles.active : ''}`}
        >
          Dashboard
        </button>
        
        <button 
          onClick={handleProfileClick} 
          className={`${styles.navLink} ${isActive('/profile', 'profile') ? styles.active : ''}`}
        >
          Edit Profile
        </button>
        
        <button 
          onClick={handleHistoryClick} 
          className={`${styles.navLink} ${isActive('/profile', 'history') ? styles.active : ''}`}
        >
          Analysis History
        </button>
        
        {isAdmin && (
          <>
            <button 
              onClick={() => {
                if (location.pathname !== '/admin') {
                  navigate('/admin');
                }
                if (setActiveAdminSection) setActiveAdminSection('users');
              }} 
              className={`${styles.navLink} ${isActive('/admin', 'users') ? styles.active : ''}`}
            >
              User Accounts
            </button>
            <button 
              onClick={() => {
                if (location.pathname !== '/admin') {
                  navigate('/admin');
                }
                if (setActiveAdminSection) setActiveAdminSection('engines');
              }} 
              className={`${styles.navLink} ${isActive('/admin', 'engines') ? styles.active : ''}`}
            >
              Analysis Engines
            </button>
            <button 
              onClick={() => {
                if (location.pathname !== '/admin') {
                  navigate('/admin');
                }
                if (setActiveAdminSection) setActiveAdminSection('history');
              }} 
              className={`${styles.navLink} ${isActive('/admin', 'history') ? styles.active : ''}`}
            >
              All History
            </button>
          </>
        )}
        
        <button 
          onClick={handleLogout} 
          className={styles.navLink}
        >
          Logout
        </button>
      </div>
    </nav>
  );
};

export default SharedNavbar;
