import { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './Navbar.module.css';

// Lock Icon Component
const LockIcon = () => (
  <span className={styles.lockIcon}>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="currentColor">
      <path d="M12 1a5 5 0 0 0-5 5v3H4v12h16V9h-3V6a5 5 0 0 0-5-5zm0 2a3 3 0 0 1 3 3v3H9V6a3 3 0 0 1 3-3zm-6 7h12v8H6v-8z"/>
    </svg>
  </span>
);

export default function Navbar() {
    const { user, isAuthenticated, logout } = useAuth();
    const [isDarkMode, setIsDarkMode] = useState(true);
    const [activeSection, setActiveSection] = useState('home');
    const [isScrolled, setIsScrolled] = useState(false);
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    const mobileMenuRef = useRef(null);
    const [threatLevel, setThreatLevel] = useState('Medium');
    const navigate = useNavigate();
    const location = useLocation();

    useEffect(() => {
      // Apply theme on component mount and when theme changes
      document.documentElement.setAttribute('data-theme', isDarkMode ? 'dark' : 'light');
    }, [isDarkMode]);

    useEffect(() => {
      // Add scroll event listener to detect when page is scrolled
      const handleScroll = () => {
        const scrollPosition = window.scrollY;
        if (scrollPosition > 50) {
          setIsScrolled(true);
        } else {
          setIsScrolled(false);
        }
      };

      window.addEventListener('scroll', handleScroll);
      
      // Clean up the event listener
      return () => {
        window.removeEventListener('scroll', handleScroll);
      };
    }, []);

    useEffect(() => {
      // Close mobile menu when clicking outside
      const handleClickOutside = (event) => {
        if (mobileMenuRef.current && !mobileMenuRef.current.contains(event.target) && 
            !event.target.closest(`.${styles.hamburger}`)) {
          setIsMobileMenuOpen(false);
        }
      };

      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }, []);

    // Lock body scroll when mobile menu is open
    useEffect(() => {
      if (isMobileMenuOpen) {
        document.body.style.overflow = 'hidden';
      } else {
        document.body.style.overflow = '';
      }
      
      return () => {
        document.body.style.overflow = '';
      };
    }, [isMobileMenuOpen]);

    // Simulate random threat level changes (for cyberpunk effect)
    useEffect(() => {
      const threatLevels = ['Low', 'Medium', 'High', 'Critical'];
      const interval = setInterval(() => {
        const randomIndex = Math.floor(Math.random() * threatLevels.length);
        setThreatLevel(threatLevels[randomIndex]);
      }, 30000); // Change every 30 seconds
      
      return () => clearInterval(interval);
    }, []);

    const toggleTheme = () => {
      setIsDarkMode(!isDarkMode);
    };
    
    const handleNavClick = (event, sectionId) => {
      event.preventDefault();
      setActiveSection(sectionId);
      setIsMobileMenuOpen(false);
      
      if (sectionId === 'sign-in') {
        navigate('/signin');
        return;
      }
      
      if (sectionId === 'sign-up') {
        navigate('/signup');
        return;
      }
      
      if (sectionId === 'dashboard') {
        navigate('/dashboard');
        return;
      }
      
      if (sectionId === 'sign-out') {
        logout();
        return;
      }
      
      // For regular sections, navigate to home and scroll
      if (location.pathname !== '/') {
        navigate('/');
        // Let the DOM update before trying to scroll
        setTimeout(() => {
          const section = document.getElementById(sectionId);
          if (section) {
            section.scrollIntoView({ behavior: 'smooth' });
          }
        }, 100);
      } else {
      const section = document.getElementById(sectionId);
      if (section) {
        section.scrollIntoView({ behavior: 'smooth' });
      }
      }
    };

    const toggleMobileMenu = () => {
      setIsMobileMenuOpen(!isMobileMenuOpen);
    };

    const getNavItems = () => {
      // Base nav items that are always shown
      const baseItems = [
        { id: 'home', label: 'Home' },
        { id: 'about', label: 'About' },
        { id: 'features', label: 'Features' },
        { id: 'contact', label: 'Contact' }
      ];
      
      // Add dashboard item for authenticated users
      if (isAuthenticated) {
        baseItems.push({ id: 'dashboard', label: 'Dashboard' });
      }
      
      return baseItems;
    };
    
    const navItems = getNavItems();

    return (
      <nav className={`${styles.navbar} ${isScrolled ? styles.scrolled : ''}`}>
        {/* Animation scanner line */}
        <div className={styles.scanLine}></div>
        
        <div className={styles.navContent}>
          <div className={styles.logoContainer}>
            <Link to="/" className={styles.logo} onClick={(e) => handleNavClick(e, 'home')}>
              <div className={styles.logoWrapper}>
                <img src="/logo.png" alt="Matrisks Logo" className={styles.logoImage} />
              </div>
              <span className={styles.logoText}>Matrisks</span>
              <span className={styles.threatLevel}>Threat: {threatLevel}</span>
            </Link>
          </div>
          
          <ul className={styles.navLinks}>
            {navItems.map(item => (
              <li key={item.id} className={styles.navItem}>
                <a 
                  href={`#${item.id}`} 
                  className={`${styles.navLink} ${activeSection === item.id ? styles.active : ''}`}
                  onClick={(e) => handleNavClick(e, item.id)}
            >
                  {item.label}
            </a>
              </li>
            ))}
          </ul>
          
          <div className={styles.btnContainer}>
            <button 
              className={styles.themeToggle} 
              onClick={toggleTheme} 
              aria-label="Toggle theme"
            >
              {isDarkMode ? '🌙' : '☀️'}
            </button>
            
            {!isAuthenticated ? (
              // Show Sign In/Sign Up for non-authenticated users
              <>
                <Link 
                  to="/signin" 
                  className={`${styles.authButton} ${styles.signInBtn}`}
                  onClick={(e) => handleNavClick(e, 'sign-in')}
            >
                  <span>
                    <LockIcon />
                    Sign In
                  </span>
                </Link>
                
                <Link 
                  to="/signup" 
                  className={`${styles.authButton} ${styles.signUpBtn}`}
                  onClick={(e) => handleNavClick(e, 'sign-up')}
                >
                  <span>
                    <LockIcon />
                    Sign Up
                  </span>
                </Link>
              </>
            ) : (
              // Show user info and Sign Out for authenticated users
              <>
                <Link 
                  to="/dashboard" 
                  className={`${styles.authButton} ${styles.userBtn}`}
                  onClick={(e) => handleNavClick(e, 'dashboard')}
            >
                  <span className={styles.userInfo}>
                    {user?.username || 'User'}
                  </span>
                </Link>
                
                <button 
                  className={`${styles.authButton} ${styles.signOutBtn}`}
                  onClick={(e) => handleNavClick(e, 'sign-out')}
            >
                  <span>
                    <LockIcon />
                    Sign Out
                  </span>
                </button>
              </>
            )}
          </div>
          
          <button 
            className={`${styles.hamburger} ${isMobileMenuOpen ? styles.active : ''}`}
            onClick={toggleMobileMenu}
            aria-label="Toggle mobile menu"
            aria-expanded={isMobileMenuOpen}
          >
            <span></span>
            <span></span>
            <span></span>
          </button>
          
          <div 
            ref={mobileMenuRef}
            className={`${styles.mobileMenu} ${isMobileMenuOpen ? styles.open : ''}`}
            aria-hidden={!isMobileMenuOpen}
          >
            <ul className={styles.mobileNavLinks}>
              {navItems.map((item, index) => (
                <li 
                  key={item.id} 
                  className={styles.mobileNavItem}
                  style={{ '--item-index': index }}
                >
            <a 
                    href={`#${item.id}`} 
                    className={`${styles.mobileNavLink} ${activeSection === item.id ? styles.active : ''}`}
                    onClick={(e) => handleNavClick(e, item.id)}
                  >
                    {item.label}
                  </a>
                </li>
              ))}
            </ul>
            
            <div className={styles.mobileBtnContainer}>
              {!isAuthenticated ? (
                // Mobile auth buttons for non-authenticated users
                <>
                  <Link 
                    to="/signin" 
                    className={`${styles.authButton} ${styles.signInBtn}`}
                    onClick={(e) => handleNavClick(e, 'sign-in')}
                  >
                    <span>
                      <LockIcon />
                      Sign In
                    </span>
                  </Link>
                  
                  <Link 
                    to="/signup" 
                    className={`${styles.authButton} ${styles.signUpBtn}`}
                    onClick={(e) => handleNavClick(e, 'sign-up')}
                  >
                    <span>
                      <LockIcon />
                      Sign Up
                    </span>
                  </Link>
                </>
              ) : (
                // Mobile auth buttons for authenticated users
                <>
                  <Link 
                    to="/dashboard" 
                    className={`${styles.authButton} ${styles.userBtn}`}
                    onClick={(e) => handleNavClick(e, 'dashboard')}
            >
                    <span>
                      Dashboard
                    </span>
                  </Link>
                  
                  <button 
                    className={`${styles.authButton} ${styles.signOutBtn}`}
                    onClick={(e) => handleNavClick(e, 'sign-out')}
                  >
                    <span>
                      <LockIcon />
                      Sign Out
                    </span>
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>
    );
  }