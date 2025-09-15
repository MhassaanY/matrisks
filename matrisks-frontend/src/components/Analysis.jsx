import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { uploadFileForAnalysis } from '../services/api';
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
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select an APK file to analyze.');
      return;
    }

    // Start analysis
    setIsAnalyzing(true);
    setAnalysisProgress(0);
    setAnalysisResult(null);
    setError('');

    try {
      // Simulate progress updates
      progressIntervalRef.current = setInterval(() => {
        setAnalysisProgress(prev => {
          if (prev >= 85) {
            return prev; // Stop at 85% until real analysis completes
          }
          return Math.min(prev + Math.random() * 4 + 1, 85); // More consistent progress
        });
      }, 400);

      // Call the real API
      const result = await uploadFileForAnalysis(file, analysisType.toLowerCase());
      
      // Clear progress interval first
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
        progressIntervalRef.current = null;
      }
      
      // Ensure progress reaches 100% before processing results
      setAnalysisProgress(100);
      
      // Small delay to ensure progress bar shows 100%
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // Process the real results
      if (result.success) {
        setAnalysisResult(processAnalysisResult(result));
      } else {
        setError(result.error || 'Analysis failed');
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      setError(error.message || 'Analysis failed. Please try again.');
    } finally {
      setIsAnalyzing(false);
      // Clear any remaining interval
      if (progressIntervalRef.current) {
        clearInterval(progressIntervalRef.current);
        progressIntervalRef.current = null;
      }
    }
  };

  // Process real analysis results from BasicStatic
  const processAnalysisResult = (apiResult) => {
    return {
      analysisType: apiResult.analysis_type,
      timestamp: apiResult.timestamp,
      fileInfo: apiResult.file_info || {},
      htmlReport: apiResult.report_content?.html_report || null,
      rawOutput: apiResult.raw_output || '',
      reportPath: apiResult.report_path || null // Store the report path for download
    };
  };

  // Download HTML report
  const handleDownloadReport = async () => {
    if (!analysisResult?.reportPath) {
      setError('Report path not available for download');
      return;
    }

    try {
      // Extract scan ID from the report path
      const scanId = analysisResult.reportPath.split('/').pop();
      
      // Get the token for authentication
      const token = localStorage.getItem('access_token');
      
      // Create a download link for the HTML report
      const response = await fetch(`http://localhost:8000/analysis/download/${scanId}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${scanId}.html`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
      } else {
        setError('Failed to download report');
      }
    } catch (error) {
      console.error('Download failed:', error);
      setError('Failed to download report');
    }
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
        
        {/* File Information */}
        {analysisResult.fileInfo && (
          <div className={styles.fileInfo}>
            <h3>Analysis Information</h3>
            <div className={styles.infoGrid}>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Filename:</span>
                <span className={styles.infoValue}>{analysisResult.fileInfo.filename}</span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Size:</span>
                <span className={styles.infoValue}>{(analysisResult.fileInfo.size / (1024 * 1024)).toFixed(2)} MB</span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Analysis Type:</span>
                <span className={styles.infoValue}>{analysisResult.analysisType}</span>
              </div>
              <div className={styles.infoItem}>
                <span className={styles.infoLabel}>Analyzed:</span>
                <span className={styles.infoValue}>{new Date(analysisResult.timestamp).toLocaleString()}</span>
              </div>
            </div>
          </div>
        )}
        
        {/* HTML Report */}
        {analysisResult.htmlReport && (
          <div className={styles.htmlReportSection}>
            <h3>Security Analysis Report</h3>
            <iframe 
              className={styles.htmlReportContent}
              srcDoc={analysisResult.htmlReport}
              title="Security Analysis Report"
              sandbox="allow-scripts allow-same-origin"
            />
          </div>
        )}
        
        <div className={styles.analysisActions}>
          <button 
            className={styles.actionButton}
            onClick={() => navigate('/dashboard')}
          >
            Back to Dashboard
          </button>
          <button 
            className={`${styles.actionButton} ${styles.primaryButton}`}
            onClick={handleDownloadReport}
            disabled={!analysisResult?.reportPath}
          >
            Download Report
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
