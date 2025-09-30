import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import { aiApi } from '../services/api';
import styles from './Dashboard.module.css';

const Dashboard = () => {
  const { currentUser, logout } = useAuth();
  const navigate = useNavigate();
  const [date, setDate] = useState(new Date());
  const [activeButton, setActiveButton] = useState(null);
  const [showFooterTip, setShowFooterTip] = useState(false);
  const [isVisible, setIsVisible] = useState(false);
  const [aiStats, setAiStats] = useState(null);
  const [showAiStats, setShowAiStats] = useState(false);
  const dashboardRef = useRef(null);
  const buttonsRef = useRef([]);

  // Update date every minute
  useEffect(() => {
    const timer = setInterval(() => setDate(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  // Entrance animation on mount
  useEffect(() => {
    setIsVisible(true);
    // Load AI stats
    loadAIStats();
  }, []);

  // Load AI statistics
  const loadAIStats = async () => {
    try {
      const statsResponse = await aiApi.getStatistics();
      if (statsResponse.statistics && statsResponse.statistics.total_analyses > 0) {
        setAiStats(statsResponse.statistics);
        setShowAiStats(true);
      }
    } catch (error) {
      // If AI stats fail to load, just don't show the widget
      console.log('AI stats not available:', error.message);
    }
  };

  // Analysis options data
  const analysisOptions = [
    {
      id: 'basic',
      title: 'Basic Analysis',
      description: 'Run basic file scanning & metadata extraction',
      color: '#4a90e2',
      ariaLabel: 'Start basic analysis - Quick scan of APK files with basic categorization'
    },
    {
      id: 'advanced-static',
      title: 'Advanced Analysis',
      description: 'Perform in-depth code analysis & vulnerability scanning',
      color: '#9c27b0',
      ariaLabel: 'Begin advanced static analysis - Detailed code inspection and vulnerability detection'
    },
    {
      id: 'dynamic',
      title: 'Dynamic Analysis',
      description: 'Monitor real-time behavior & detect runtime threats',
      color: '#ff9800',
      ariaLabel: 'Launch dynamic analysis - Real-time application behavior monitoring'
    },
    {
      id: 'malware-detection',
      title: 'Malware Detection',
      description: 'Scan for malware using ML-powered detection',
      color: '#e53935',
      ariaLabel: 'Start malware detection - Machine learning based threat detection'
    }
  ];

  const handleButtonSelect = (id, e) => {
    // Create ripple effect
    const button = e.currentTarget;
    const rect = button.getBoundingClientRect();
    const ripple = document.createElement('div');
    ripple.className = styles.ripple;
    ripple.style.left = `${e.clientX - rect.left}px`;
    ripple.style.top = `${e.clientY - rect.top}px`;
    ripple.style.backgroundColor = analysisOptions.find(opt => opt.id === id).color + '40';
    button.appendChild(ripple);

    setTimeout(() => button.removeChild(ripple), 1000);
    
    // Get the selected analysis type
    const selectedOption = analysisOptions.find(opt => opt.id === id);
    
    // Navigate to the Analysis page with the selected analysis type
    let analysisType;
    if (id === 'malware-detection') {
      analysisType = 'Malware';
    } else {
      analysisType = selectedOption.title.split(' ')[0]; // Use the first word of the title (Basic, Advanced, Dynamic)
    }
    
    navigate('/analysis', { 
      state: { 
        analysisType: analysisType
      } 
    });
    console.log(`Navigating to analysis with type: ${selectedOption.title}`);
  };

  return (
    <div 
      ref={dashboardRef}
      className={`${styles.dashboardWrapper} ${isVisible ? styles.visible : ''}`}
    >
      {/* Particle Background */}
      <div className={styles.particleBackground} />
      
      {/* Dashboard Navbar */}
      <nav className={styles.navbar}>
        <div className={styles.navbarLeft}>
          {/* Empty div for spacing */}
        </div>
        <div className={styles.navbarCenter}>
          <h2 className={styles.dashboardTitle}>Dashboard</h2>
        </div>
        <div className={styles.navbarRight}>
          <Link to="/profile" className={styles.navLink}>Profile</Link>
          <Link to="/admin" className={styles.navLink}>Admin</Link>
          <button onClick={logout} className={styles.navLink}>Logout</button>
        </div>
      </nav>

      <main className={styles.dashboardContainer}>
        <header className={`${styles.dashboardHeader} ${isVisible ? styles.visible : ''}`}>
          <h1>Welcome to MatRisks</h1>
          <p className={styles.welcomeMessage}>
            Hello, <span className={styles.username}>{currentUser?.first_name || currentUser?.username}</span>! Choose your analysis type below:
          </p>
        </header>
        
        <div className={styles.analysisButtonsContainer}>
          {analysisOptions.map((option, index) => (
            <button 
              key={option.id}
              ref={el => buttonsRef.current[index] = el}
              className={`${styles.analysisButton} ${activeButton === option.id ? styles.activeButton : ''} ${isVisible ? styles.visible : ''}`}
              style={{
                '--button-color': option.color,
                '--button-index': index
              }}
              onMouseEnter={() => setActiveButton(option.id)}
              onMouseLeave={() => setActiveButton(null)}
              onClick={(e) => handleButtonSelect(option.id, e)}
              aria-label={option.ariaLabel}
            >
              <div className={styles.buttonGlow} />
              <div className={styles.buttonContent}>
                <h3 className={styles.buttonTitle}>{option.title}</h3>
                <div className={`${styles.buttonTooltip} ${activeButton === option.id ? styles.showTooltip : ''}`}>
                  {option.description}
                </div>
              </div>
            </button>
          ))}
        </div>

        {/* AI Stats Widget - only show if user has AI analysis history */}
        {showAiStats && aiStats && (
          <div className={`${styles.aiStatsWidget} ${isVisible ? styles.visible : ''}`}>
            <h3 className={styles.aiStatsTitle}>🤖 Your AI Analysis Summary</h3>
            <div className={styles.aiStatsGrid}>
              <div className={styles.aiStatItem}>
                <div className={styles.aiStatNumber}>{aiStats.total_analyses}</div>
                <div className={styles.aiStatLabel}>Total Scans</div>
              </div>
              <div className={styles.aiStatItem}>
                <div className={styles.aiStatNumber}>{aiStats.malware_detected}</div>
                <div className={styles.aiStatLabel}>Threats Found</div>
              </div>
              <div className={styles.aiStatItem}>
                <div className={styles.aiStatNumber}>
                  {(aiStats.average_confidence * 100).toFixed(0)}%
                </div>
                <div className={styles.aiStatLabel}>Avg Confidence</div>
              </div>
            </div>
          </div>
        )}
      </main>

      <footer 
        className={`${styles.dashboardFooter} ${showFooterTip ? styles.showTip : ''}`}
        onMouseEnter={() => setShowFooterTip(true)}
        onMouseLeave={() => setShowFooterTip(false)}
      >
        <div className={styles.footerContent}>
          <time className={styles.timeDisplay}>
            {date.toLocaleDateString()} | {date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </time>
          <p className={styles.securityTip}>
            Tip: Always scan APK files before installation to ensure security.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Dashboard;
