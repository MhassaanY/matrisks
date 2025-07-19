import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './Analysis.module.css';

const Analysis = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [isVisible, setIsVisible] = useState(false);
  const [analysisType, setAnalysisType] = useState('');
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState('');
  const fileInputRef = useRef(null);
  const progressIntervalRef = useRef(null);

  // Get analysis type from location state
  useEffect(() => {
    if (location.state?.analysisType) {
      setAnalysisType(location.state.analysisType);
    } else {
      // Redirect to dashboard if no analysis type provided
      navigate('/dashboard');
    }

    // Animation for page entrance
    const timer = setTimeout(() => {
      setIsVisible(true);
    }, 100);

    return () => {
      clearTimeout(timer);
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
      }
    };
  }, [location.state, navigate]);

  // Handle file selection
  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    processFile(selectedFile);
  };

  // Process the selected file
  const processFile = (selectedFile) => {
    if (!selectedFile) return;

    // Check if file is an APK
    if (!selectedFile.name.endsWith('.apk')) {
      setError('Please upload an APK file.');
      return;
    }

    // Check file size (limit to 100MB)
    if (selectedFile.size > 100 * 1024 * 1024) {
      setError('File size exceeds 100MB limit.');
      return;
    }

    setFile(selectedFile);
    setError('');

    // Create file preview (icon for APK)
    setFilePreview('/android-icon.png'); // Placeholder icon
  };

  // Handle drag events
  const handleDragEnter = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  // Trigger file input click
  const handleBrowseClick = () => {
    fileInputRef.current.click();
  };

  // Remove selected file
  const handleRemoveFile = () => {
    setFile(null);
    setFilePreview('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  // Handle form submission
  const handleSubmit = (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select an APK file to analyze.');
      return;
    }

    // Start analysis
    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setAnalysisResult(null);

    // Simulate analysis progress
    progressIntervalRef.current = setInterval(() => {
      setAnalysisProgress(prev => {
        if (prev >= 100) {
          clearInterval(progressIntervalRef.current);
          completeAnalysis();
          return 100;
        }
        return prev + Math.random() * 5;
      });
    }, 500);
  };

  // Complete the analysis (mock)
  const completeAnalysis = () => {
    // Generate mock analysis result based on analysis type
    const mockResults = {
      basic: {
        malwareScore: Math.floor(Math.random() * 100),
        permissions: [
          { name: 'READ_EXTERNAL_STORAGE', risk: 'Low' },
          { name: 'INTERNET', risk: 'Low' },
          { name: 'ACCESS_FINE_LOCATION', risk: 'Medium' },
          { name: 'READ_CONTACTS', risk: 'Medium' }
        ],
        riskyAPIs: Math.floor(Math.random() * 5),
        securityIssues: [
          'Unprotected data transmission',
          'Excessive permissions'
        ]
      },
      advanced: {
        malwareScore: Math.floor(Math.random() * 100),
        permissions: [
          { name: 'READ_EXTERNAL_STORAGE', risk: 'Low' },
          { name: 'INTERNET', risk: 'Low' },
          { name: 'ACCESS_FINE_LOCATION', risk: 'Medium' },
          { name: 'READ_CONTACTS', risk: 'Medium' },
          { name: 'CAMERA', risk: 'Medium' },
          { name: 'RECORD_AUDIO', risk: 'High' }
        ],
        riskyAPIs: Math.floor(Math.random() * 10),
        securityIssues: [
          'Unprotected data transmission',
          'Excessive permissions',
          'Known vulnerability in library',
          'Code obfuscation detected'
        ],
        networkCommunication: [
          { domain: 'api.example.com', risk: 'Low' },
          { domain: 'analytics.trackingservice.com', risk: 'Medium' },
          { domain: 'suspicious-domain.com', risk: 'High' }
        ]
      },
      dynamic: {
        malwareScore: Math.floor(Math.random() * 100),
        permissions: [
          { name: 'READ_EXTERNAL_STORAGE', risk: 'Low' },
          { name: 'INTERNET', risk: 'Low' },
          { name: 'ACCESS_FINE_LOCATION', risk: 'Medium' },
          { name: 'READ_CONTACTS', risk: 'Medium' },
          { name: 'CAMERA', risk: 'Medium' },
          { name: 'RECORD_AUDIO', risk: 'High' },
          { name: 'SEND_SMS', risk: 'High' }
        ],
        riskyAPIs: Math.floor(Math.random() * 15),
        securityIssues: [
          'Unprotected data transmission',
          'Excessive permissions',
          'Known vulnerability in library',
          'Code obfuscation detected',
          'Runtime permission abuse',
          'Data exfiltration detected'
        ],
        networkCommunication: [
          { domain: 'api.example.com', risk: 'Low' },
          { domain: 'analytics.trackingservice.com', risk: 'Medium' },
          { domain: 'suspicious-domain.com', risk: 'High' },
          { domain: 'malware-c2-server.net', risk: 'Critical' }
        ],
        behavioralAnalysis: [
          { behavior: 'Accessing contacts', risk: 'Medium' },
          { behavior: 'Location tracking', risk: 'Medium' },
          { behavior: 'Camera access', risk: 'Medium' },
          { behavior: 'Background SMS sending', risk: 'High' }
        ]
      },
      malware: {
        malwareScore: Math.floor(Math.random() * 100) + 50, // Higher probability of malware
        permissions: [
          { name: 'READ_EXTERNAL_STORAGE', risk: 'Low' },
          { name: 'INTERNET', risk: 'Low' },
          { name: 'ACCESS_FINE_LOCATION', risk: 'Medium' },
          { name: 'READ_CONTACTS', risk: 'Medium' },
          { name: 'CAMERA', risk: 'Medium' },
          { name: 'RECORD_AUDIO', risk: 'High' },
          { name: 'SEND_SMS', risk: 'High' },
          { name: 'RECEIVE_BOOT_COMPLETED', risk: 'High' }
        ],
        riskyAPIs: Math.floor(Math.random() * 20),
        securityIssues: [
          'Unprotected data transmission',
          'Excessive permissions',
          'Known vulnerability in library',
          'Code obfuscation detected',
          'Runtime permission abuse',
          'Data exfiltration detected',
          'Root detection evasion',
          'Anti-analysis techniques'
        ],
        networkCommunication: [
          { domain: 'api.example.com', risk: 'Low' },
          { domain: 'analytics.trackingservice.com', risk: 'Medium' },
          { domain: 'suspicious-domain.com', risk: 'High' },
          { domain: 'malware-c2-server.net', risk: 'Critical' }
        ],
        behavioralAnalysis: [
          { behavior: 'Accessing contacts', risk: 'Medium' },
          { behavior: 'Location tracking', risk: 'Medium' },
          { behavior: 'Camera access', risk: 'Medium' },
          { behavior: 'Background SMS sending', risk: 'High' },
          { behavior: 'Persistence after reboot', risk: 'High' },
          { behavior: 'Hidden activity execution', risk: 'Critical' }
        ],
        malwareFamily: [
          'BankBot',
          'FluBot',
          'Joker',
          'Cerberus',
          'BlackRock'
        ][Math.floor(Math.random() * 5)],
        malwareType: [
          'Banking Trojan',
          'Spyware',
          'SMS Stealer',
          'Adware',
          'Ransomware'
        ][Math.floor(Math.random() * 5)]
      }
    };

    // Set the result based on analysis type
    setTimeout(() => {
      setAnalysisResult(mockResults[analysisType.toLowerCase()]);
      setIsAnalyzing(false);
    }, 1000);
  };

  // Get risk color
  const getRiskColor = (score) => {
    if (score < 30) return styles.safe;
    if (score < 70) return styles.medium;
    return styles.dangerous;
  };

  // Function to render analysis results
  const renderAnalysisResults = () => {
    if (!analysisResult) return null;

    return (
      <div className={styles.resultsContainer}>
        <h2 className={styles.resultsTitle}>Analysis Results</h2>
        
        <div className={styles.scoreSection}>
          <div className={styles.scoreContainer}>
            <div 
              className={`${styles.scoreCircle} ${getRiskColor(analysisResult.malwareScore)}`}
              style={{ '--score': `${analysisResult.malwareScore}%` }}
            >
              <span className={styles.scoreValue}>{analysisResult.malwareScore}</span>
            </div>
            <div className={styles.scoreLabel}>
              Risk Score
            </div>
          </div>
          
          {analysisResult.malwareFamily && (
            <div className={styles.malwareInfo}>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Malware Family:</span>
                <span className={styles.infoValue}>{analysisResult.malwareFamily}</span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Malware Type:</span>
                <span className={styles.infoValue}>{analysisResult.malwareType}</span>
              </div>
            </div>
          )}
        </div>
        
        <div className={styles.detailsGrid}>
          <div className={styles.detailCard}>
            <h3>Permissions ({analysisResult.permissions.length})</h3>
            <ul className={styles.permissionsList}>
              {analysisResult.permissions.map((perm, index) => (
                <li key={index} className={`${styles.permissionItem} ${styles[perm.risk.toLowerCase()]}`}>
                  {perm.name}
                  <span className={styles.riskBadge}>{perm.risk}</span>
                </li>
              ))}
            </ul>
          </div>
          
          <div className={styles.detailCard}>
            <h3>Security Issues</h3>
            <ul className={styles.issuesList}>
              {analysisResult.securityIssues.map((issue, index) => (
                <li key={index} className={styles.issueItem}>{issue}</li>
              ))}
            </ul>
          </div>
          
          {analysisResult.networkCommunication && (
            <div className={styles.detailCard}>
              <h3>Network Communication</h3>
              <ul className={styles.networkList}>
                {analysisResult.networkCommunication.map((network, index) => (
                  <li key={index} className={`${styles.networkItem} ${styles[network.risk.toLowerCase()]}`}>
                    {network.domain}
                    <span className={styles.riskBadge}>{network.risk}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          
          {analysisResult.behavioralAnalysis && (
            <div className={styles.detailCard}>
              <h3>Behavioral Analysis</h3>
              <ul className={styles.behaviorList}>
                {analysisResult.behavioralAnalysis.map((behavior, index) => (
                  <li key={index} className={`${styles.behaviorItem} ${styles[behavior.risk.toLowerCase()]}`}>
                    {behavior.behavior}
                    <span className={styles.riskBadge}>{behavior.risk}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
        
        <div className={styles.analysisActions}>
          <button 
            className={styles.actionButton}
            onClick={() => navigate('/dashboard')}
          >
            Back to Dashboard
          </button>
          <button 
            className={`${styles.actionButton} ${styles.primaryButton}`}
            onClick={() => window.print()}
          >
            Export Report
          </button>
        </div>
      </div>
    );
  };

  return (
    <div className={`${styles.analysisWrapper} ${isVisible ? styles.visible : ''}`}>
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
          <button 
            onClick={() => navigate('/profile')} 
            className={styles.navLink}
          >
            Profile
          </button>
          <button 
            onClick={() => navigate('/admin')} 
            className={styles.navLink}
          >
            Admin
          </button>
          <button 
            onClick={() => navigate('/signin')} 
            className={styles.navLink}
          >
            Logout
          </button>
        </div>
      </nav>

      <main className={styles.analysisContainer}>
        <header className={styles.analysisHeader}>
          <h1 className={styles.analysisTitle}>
            MatRisks {analysisType} Analysis
          </h1>
          <p className={styles.analysisDescription}>
            Upload an APK file to analyze it for potential security risks and vulnerabilities.
          </p>
        </header>

        {!isAnalyzing && !analysisResult && (
          <form onSubmit={handleSubmit} className={styles.uploadForm}>
            <div 
              className={`${styles.dropZone} ${isDragging ? styles.dragging : ''} ${file ? styles.hasFile : ''}`}
              onDragEnter={handleDragEnter}
              onDragLeave={handleDragLeave}
              onDragOver={handleDragOver}
              onDrop={handleDrop}
            >
              {!file ? (
                <div className={styles.dropZoneContent}>
                  <div className={styles.uploadIcon}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="17 8 12 3 7 8"></polyline>
                      <line x1="12" y1="3" x2="12" y2="15"></line>
                    </svg>
                  </div>
                  <p className={styles.dropZoneText}>
                    Drag & drop your APK file here or <button type="button" className={styles.browseButton} onClick={handleBrowseClick}>browse</button>
                  </p>
                  <input 
                    type="file" 
                    ref={fileInputRef} 
                    onChange={handleFileChange} 
                    className={styles.fileInput} 
                    accept=".apk"
                  />
                </div>
              ) : (
                <div className={styles.filePreview}>
                  {filePreview && <img src={filePreview} alt="APK Preview" className={styles.fileIcon} />}
                  <div className={styles.fileInfo}>
                    <p className={styles.fileName}>{file.name}</p>
                    <p className={styles.fileSize}>{(file.size / (1024 * 1024)).toFixed(2)} MB</p>
                  </div>
                  <button 
                    type="button" 
                    className={styles.removeFileButton} 
                    onClick={handleRemoveFile}
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  </button>
                </div>
              )}
            </div>

            {error && (
              <div className={styles.errorMessage}>
                {error}
              </div>
            )}

            <div className={styles.formActions}>
              <button 
                type="button" 
                className={styles.cancelButton}
                onClick={() => navigate('/dashboard')}
              >
                Back
              </button>
              <button 
                type="submit" 
                className={styles.analyzeButton}
                disabled={!file}
              >
                Analyze APK
              </button>
            </div>
          </form>
        )}

        {isAnalyzing && (
          <div className={styles.analysisProgress}>
            <h2 className={styles.progressTitle}>Analyzing your APK...</h2>
            <div className={styles.progressBar}>
              <div 
                className={styles.progressFill} 
                style={{ width: `${Math.min(analysisProgress, 100)}%` }}
              ></div>
            </div>
            <p className={styles.progressText}>
              {Math.floor(analysisProgress)}% complete
            </p>
            <div className={styles.progressSteps}>
              <div className={`${styles.progressStep} ${analysisProgress >= 20 ? styles.completed : ''}`}>
                <div className={styles.stepIcon}></div>
                <span className={styles.stepLabel}>Unpacking APK</span>
              </div>
              <div className={`${styles.progressStep} ${analysisProgress >= 40 ? styles.completed : ''}`}>
                <div className={styles.stepIcon}></div>
                <span className={styles.stepLabel}>Analyzing Permissions</span>
              </div>
              <div className={`${styles.progressStep} ${analysisProgress >= 60 ? styles.completed : ''}`}>
                <div className={styles.stepIcon}></div>
                <span className={styles.stepLabel}>Code Analysis</span>
              </div>
              <div className={`${styles.progressStep} ${analysisProgress >= 80 ? styles.completed : ''}`}>
                <div className={styles.stepIcon}></div>
                <span className={styles.stepLabel}>Security Check</span>
              </div>
              <div className={`${styles.progressStep} ${analysisProgress >= 100 ? styles.completed : ''}`}>
                <div className={styles.stepIcon}></div>
                <span className={styles.stepLabel}>Generating Report</span>
              </div>
            </div>
          </div>
        )}

        {analysisResult && renderAnalysisResults()}
      </main>
    </div>
  );
};

export default Analysis;
