import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { Link, useNavigate } from 'react-router-dom';
import { aiApi } from '../services/api';
import SharedNavbar from './SharedNavbar';
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
  const [expandedCard, setExpandedCard] = useState(null);
  const [isTransitioning, setIsTransitioning] = useState(false);
  const dashboardRef = useRef(null);
  const buttonsRef = useRef([]);
  const originalTransforms = useRef([]);
  const originalPositions = useRef([]);

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
    
    // Initialize stacked card positions
    setTimeout(() => {
      initializeCardPositions();
    }, 100);
  }, []);

  // Initialize stacked card positions
  const initializeCardPositions = () => {
    const positions = [
      { top: '0', left: '0%', rotate: -5, zIndex: 4, shadow: '0 10px 40px rgba(0,0,0,0.3)' },
      { top: '20px', left: '25%', rotate: 4, zIndex: 3, shadow: '0 15px 45px rgba(0,0,0,0.3)' },
      { top: '10px', left: '50%', rotate: -4, zIndex: 2, shadow: '0 20px 50px rgba(0,0,0,0.3)' },
      { top: '30px', left: '75%', rotate: 5, zIndex: 1, shadow: '0 25px 55px rgba(0,0,0,0.3)' }
    ];

    buttonsRef.current.forEach((card, index) => {
      if (!card) return;
      
      const pos = positions[index % positions.length];
      
      card.style.top = pos.top;
      card.style.left = pos.left;
      
      let transform = `rotate(${pos.rotate}deg)`;
      
      originalTransforms.current[index] = transform;
      originalPositions.current[index] = pos;
      
      card.style.transform = transform;
      card.style.zIndex = pos.zIndex;
      card.style.boxShadow = pos.shadow;
    });
  };

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
      type: 'basic',
      title: 'Basic Static Analysis',
      description: 'Quick security scan of manifest and permissions',
      icon: '🔍',
      gradient: 'linear-gradient(135deg, rgba(26, 26, 26, 0.7) 0%, rgba(45, 45, 45, 0.7) 100%)',
      borderColor: '#FF5722',
      glowColor: 'rgba(255, 87, 34, 0.2)'
    },
    {
      type: 'advanced',
      title: 'Advanced Static Analysis',
      description: 'Deep code analysis with OWASP MASVS checks',
      icon: '🛡️',
      gradient: 'linear-gradient(135deg, rgba(26, 26, 26, 0.7) 0%, rgba(45, 45, 45, 0.7) 100%)',
      borderColor: '#FF8A65',
      glowColor: 'rgba(255, 138, 101, 0.2)'
    },
    {
      type: 'dynamic',
      title: 'Dynamic Analysis',
      description: 'Runtime behavior monitoring and testing',
      icon: '⚡',
      gradient: 'linear-gradient(135deg, rgba(26, 26, 26, 0.7) 0%, rgba(45, 45, 45, 0.7) 100%)',
      borderColor: '#BF360C',
      glowColor: 'rgba(191, 54, 12, 0.2)'
    },
    {
      type: 'ai_malware',
      title: 'AI Malware Detection',
      description: 'Machine learning-based threat detection',
      icon: '🤖',
      gradient: 'linear-gradient(135deg, rgba(26, 26, 26, 0.7) 0%, rgba(45, 45, 45, 0.7) 100%)',
      borderColor: '#E64A19',
      glowColor: 'rgba(230, 74, 25, 0.2)'
    }
  ];

  const handleButtonSelect = (type, e) => {
    // Navigate to the Analysis page with the selected analysis type
    let analysisType;
    if (type === 'ai_malware') {
      analysisType = 'Malware';
    } else if (type === 'basic') {
      analysisType = 'Basic';
    } else if (type === 'advanced') {
      analysisType = 'Advanced';
    } else if (type === 'dynamic') {
      analysisType = 'Dynamic';
    }
    
    navigate('/analysis', { 
      state: { 
        analysisType: analysisType
      } 
    });
    console.log(`Navigating to analysis with type: ${analysisType}`);
  };

  const handleMouseEnter = (index) => {
    if (isTransitioning || expandedCard === index) return;
    
    setIsTransitioning(true);
    setExpandedCard(index);
    const card = buttonsRef.current[index];
    if (!card) {
      setIsTransitioning(false);
      return;
    }
    
    const option = analysisOptions[index];
    
    // Smooth expansion to center
    card.style.zIndex = '1000';
    card.style.width = '85%';
    card.style.maxWidth = '1100px';
    card.style.minHeight = '280px';
    card.style.left = '50%';
    card.style.top = '50%';
    card.style.transform = 'translate(-50%, -50%) rotate(0deg)';
    card.style.boxShadow = `
      0 40px 80px rgba(0, 0, 0, 0.6),
      0 0 60px ${option.glowColor},
      0 0 100px ${option.glowColor}
    `;
    card.style.border = `2px solid ${option.borderColor}`;
    card.style.pointerEvents = 'auto';
    
    setTimeout(() => setIsTransitioning(false), 500);
  };

  const handleMouseLeave = (index) => {
    if (isTransitioning) return;
    
    setIsTransitioning(true);
    setExpandedCard(null);
    const card = buttonsRef.current[index];
    if (!card) {
      setIsTransitioning(false);
      return;
    }
    
    const pos = originalPositions.current[index];
    if (!pos) {
      setIsTransitioning(false);
      return;
    }
    
    // Return to original position smoothly
    card.style.transform = originalTransforms.current[index];
    card.style.zIndex = pos.zIndex;
    card.style.boxShadow = pos.shadow;
    card.style.width = '350px';
    card.style.minHeight = '260px';
    card.style.left = pos.left;
    card.style.top = pos.top;
    card.style.border = `2px solid rgba(255, 255, 255, 0.1)`;
    card.style.pointerEvents = 'auto';
    
    setTimeout(() => setIsTransitioning(false), 500);
  };

  return (
    <div 
      ref={dashboardRef}
      className={`${styles.dashboardWrapper} ${isVisible ? styles.visible : ''}`}
    >
      {/* Particle Background */}
      <div className={styles.particleBackground} />
      
      {/* Shared Navbar */}
      <SharedNavbar />

      <main className={styles.dashboardContainer}>
        <header className={`${styles.dashboardHeader} ${isVisible ? styles.visible : ''}`}>
          <h1>Welcome to MatRisks</h1>
          <p className={styles.welcomeMessage}>
            Hello, <span className={styles.username}>{currentUser?.first_name || currentUser?.username}</span>! Choose your analysis type below:
          </p>
        </header>
        
        <div className={styles.analysisStackContainer}>
          <div className={styles.analysisStack}>
            {analysisOptions.map((option, index) => (
              <button 
                key={option.type}
                ref={el => buttonsRef.current[index] = el}
                className={`${styles.analysisButton} ${expandedCard === index ? styles.expanded : ''} ${isVisible ? styles.visible : ''}`}
                style={{
                  '--button-color': option.color,
                  '--button-gradient': option.gradient,
                  '--glow-color': option.glowColor,
                  '--border-color': option.borderColor,
                  '--button-index': index,
                  background: option.gradient,
                  borderColor: option.borderColor
                }}
                onMouseEnter={() => handleMouseEnter(index)}
                onMouseLeave={() => handleMouseLeave(index)}
                onClick={(e) => handleButtonSelect(option.type, e)}
                aria-label={option.title}
              >
                <div className={styles.cardGlow} style={{ background: option.glowColor }}></div>
                <div className={styles.buttonContent}>
                  <h3 className={styles.buttonTitle}>{option.title}</h3>
                  <p className={`${styles.buttonDescription} ${expandedCard === index ? styles.expanded : ''}`}>
                    {option.description}
                  </p>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* History Navigation Section */}
        <div className={styles.historyNavigation}>
          <button 
            className={styles.historyButton}
            onClick={() => navigate('/profile')}
          >
            <svg className={styles.historyIcon} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span>My Analysis History</span>
          </button>
          
          {currentUser?.is_superuser && (
            <button 
              className={`${styles.historyButton} ${styles.adminButton}`}
              onClick={() => navigate('/admin')}
            >
              <svg className={styles.historyIcon} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <span>All History (Admin)</span>
            </button>
          )}
        </div>


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
