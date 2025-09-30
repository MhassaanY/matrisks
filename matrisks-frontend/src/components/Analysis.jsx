import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { uploadFileForAnalysis, buildApiUrl, API_BASE_URL } from '../services/api';
import styles from './Analysis.module.css';

const Analysis = () => {
  const { currentUser } = useAuth();
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
  const [reportFormat, setReportFormat] = useState('html');
  const fileInputRef = useRef(null);
  const progressIntervalRef = useRef(null);

  // Get analysis type from location state
  useEffect(() => {
    if (location.state?.analysisType) {
      setAnalysisType(location.state.analysisType);
      // Set default report format based on analysis type
      if (location.state.analysisType.toLowerCase() === 'advanced') {
        setReportFormat('html'); // Default to HTML for advanced
      } else {
        setReportFormat('html'); // Basic only supports HTML
      }
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

  // Process real analysis results from BasicStatic or AI
  const processAnalysisResult = (apiResult) => {
    // Check if this is an AI malware detection result
    if (apiResult.analysis_type === 'malware' || apiResult.results?.prediction) {
      return {
        analysisType: 'malware',
        timestamp: apiResult.timestamp || apiResult.results?.timestamp,
        fileInfo: apiResult.file_info || {},
        // AI-specific results
        aiResults: {
          prediction: apiResult.results?.prediction,
          confidence: apiResult.results?.confidence,
          risk_level: apiResult.results?.risk_level,
          active_features: apiResult.results?.active_features,
          total_features: apiResult.results?.total_features,
          feature_analysis: apiResult.results?.feature_analysis,
          model_info: apiResult.results?.model_info,
          file_size: apiResult.results?.file_size,
          analysis_id: apiResult.results?.analysis_id
        },
        htmlReport: null, // AI doesn't generate HTML reports
        jsonReport: JSON.stringify(apiResult.results || {}, null, 2),
        csvReport: null,
        rawOutput: JSON.stringify(apiResult, null, 2)
      };
    }
    
    // Standard static analysis results
    return {
      analysisType: apiResult.analysis_type,
      timestamp: apiResult.timestamp,
      fileInfo: apiResult.file_info || {},
      htmlReport: apiResult.report_content?.html_report || null,
      jsonReport: apiResult.report_content?.json_report || null,
      csvReport: apiResult.report_content?.csv_report || null,
      rawOutput: apiResult.raw_output || '',
      reportPath: apiResult.report_path || null
    };
  };

  // Download report in selected format
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
      
      // Create a download link for the selected format
      const downloadUrl = buildApiUrl(`/analysis/download/${scanId}?format=${reportFormat}`);
      const credentialsMode = (!API_BASE_URL || API_BASE_URL === '' || downloadUrl.startsWith(window.location.origin))
        ? 'same-origin'
        : 'include';

      const response = await fetch(downloadUrl, {
        headers: {
          'Authorization': `Bearer ${token}`
        },
        credentials: credentialsMode
      });
      
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security_report_${scanId}.${reportFormat}`;
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

  // Get available report formats based on analysis type
  const getAvailableFormats = () => {
    if (analysisType.toLowerCase() === 'advanced') {
      return ['html', 'json', 'csv'];
    } else {
      return ['html']; // Basic analysis only supports HTML
    }
  };

  // Function to render different report formats
  const renderReportContent = () => {
    if (!analysisResult) return null;

    switch (reportFormat) {
      case 'html':
        return analysisResult.htmlReport ? (
          <iframe 
            className={styles.htmlReportContent}
            srcDoc={analysisResult.htmlReport}
            title="Security Analysis Report"
            sandbox="allow-scripts allow-same-origin"
          />
        ) : (
          <div className={styles.noReportMessage}>HTML report not available</div>
        );
      
      case 'json':
        return analysisResult.jsonReport ? (
          <pre className={styles.jsonReportContent}>
            {JSON.stringify(JSON.parse(analysisResult.jsonReport), null, 2)}
          </pre>
        ) : (
          <div className={styles.noReportMessage}>JSON report not available</div>
        );
      
      case 'csv':
        return analysisResult.csvReport ? (
          <pre className={styles.csvReportContent}>
            {analysisResult.csvReport}
          </pre>
        ) : (
          <div className={styles.noReportMessage}>CSV report not available</div>
        );
      
      default:
        return <div className={styles.noReportMessage}>Report format not supported</div>;
    }
  };

  // Function to render AI malware detection results within existing design
  const renderAIAnalysisResults = () => {
    const aiResults = analysisResult.aiResults;
    
    const getRiskColor = (riskLevel) => {
      switch (riskLevel?.toLowerCase()) {
        case 'high': return '#dc3545';
        case 'medium': return '#fd7e14';
        case 'low': return '#ffc107';
        default: return '#6c757d';
      }
    };

    const getConfidenceColor = (confidence) => {
      if (confidence >= 0.8) return '#dc3545';
      if (confidence >= 0.6) return '#fd7e14';
      if (confidence >= 0.4) return '#ffc107';
      return '#28a745';
    };

    const formatFileSize = (bytes) => {
      if (!bytes) return 'Unknown';
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(1024));
      return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
    };

    return (
      <div className={styles.resultsContainer}>
        <h2 className={styles.resultsTitle}>🤖 AI Malware Detection Results</h2>
        
        {/* Main AI Result Card */}
        <div className={styles.aiMainResult}>
          <div className={styles.aiPredictionSection}>
            <div className={styles.aiPredictionLabel}>Classification:</div>
            <div 
              className={`${styles.aiPrediction} ${
                aiResults.prediction === 'malware' ? styles.aiMalware : styles.aiBenign
              }`}
            >
              {aiResults.prediction === 'malware' ? '🦠 MALWARE' : '✅ BENIGN'}
            </div>
          </div>

          <div className={styles.aiConfidenceSection}>
            <div className={styles.aiConfidenceLabel}>Confidence Score:</div>
            <div className={styles.aiConfidenceBar}>
              <div 
                className={styles.aiConfidenceFill}
                style={{ 
                  width: `${(aiResults.confidence * 100)}%`,
                  backgroundColor: getConfidenceColor(aiResults.confidence)
                }}
              ></div>
              <span className={styles.aiConfidenceText}>
                {(aiResults.confidence * 100).toFixed(1)}%
              </span>
            </div>
          </div>

          <div className={styles.aiRiskSection}>
            <div className={styles.aiRiskLabel}>Risk Level:</div>
            <div 
              className={styles.aiRiskBadge}
              style={{ backgroundColor: getRiskColor(aiResults.risk_level) }}
            >
              {aiResults.risk_level?.toUpperCase() || 'UNKNOWN'}
            </div>
          </div>
        </div>

        {/* File Information using existing design */}
        <div className={styles.fileInfo}>
          <h3>🔍 Analysis Information</h3>
          <div className={styles.infoGrid}>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>File Size:</span>
              <span className={styles.infoValue}>{formatFileSize(aiResults.file_size)}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Analysis ID:</span>
              <span className={styles.infoValue}>#{aiResults.analysis_id || 'N/A'}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Active Features:</span>
              <span className={styles.infoValue}>{aiResults.active_features || 0}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Total Features:</span>
              <span className={styles.infoValue}>{aiResults.total_features || 215}</span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Model Type:</span>
              <span className={styles.infoValue}>
                {aiResults.model_info?.model_type || 'RandomForest'}
              </span>
            </div>
            <div className={styles.infoItem}>
              <span className={styles.infoLabel}>Analyzed:</span>
              <span className={styles.infoValue}>
                {new Date(analysisResult.timestamp).toLocaleString()}
              </span>
            </div>
          </div>
        </div>

        {/* Recommendations using existing card style */}
        <div className={styles.aiRecommendations}>
          <h3>💡 Security Recommendations</h3>
          {aiResults.prediction === 'malware' ? (
            <div className={styles.aiMalwareRecommendation}>
              <p className={styles.aiWarning}>
                ⚠️ <strong>This APK has been classified as potentially malicious!</strong>
              </p>
              <ul className={styles.aiRecommendationsList}>
                <li>🚫 Do not install this application on your device</li>
                <li>🗑️ Delete the APK file from your system immediately</li>
                <li>📋 Report this file to your security team</li>
                <li>🔍 Run additional scans if you suspect system compromise</li>
                {aiResults.confidence > 0.8 && (
                  <li><strong>🎯 High confidence detection</strong> - This is very likely malware</li>
                )}
              </ul>
            </div>
          ) : (
            <div className={styles.aiBenignRecommendation}>
              <p className={styles.aiSuccess}>
                ✅ <strong>This APK appears to be clean.</strong>
              </p>
              <ul className={styles.aiRecommendationsList}>
                <li>✅ The file passed AI malware detection</li>
                <li>🔍 Consider running additional security scans for complete verification</li>
                <li>📦 Always download APKs from trusted sources</li>
                <li>🔄 Keep your device's security software updated</li>
                {aiResults.confidence < 0.6 && (
                  <li><strong>📊 Note:</strong> Low confidence score - consider additional analysis</li>
                )}
              </ul>
            </div>
          )}
        </div>

        {/* Report Format Dropdown - reusing existing design */}
        <div className={styles.reportFormatDropdown}>
          <label htmlFor="formatSelect" className={styles.formatLabel}>View Details:</label>
          <select
            id="formatSelect"
            value={reportFormat}
            onChange={(e) => setReportFormat(e.target.value)}
            className={styles.formatSelect}
          >
            <option value="summary">Summary</option>
            <option value="json">JSON Details</option>
          </select>
        </div>
        
        {/* Report Section - reusing existing design */}
        {reportFormat === 'json' && (
          <div className={styles.reportSection}>
            <h3>🔬 Detailed AI Analysis (JSON)</h3>
            <pre className={styles.jsonReportContent}>
              {JSON.stringify(aiResults, null, 2)}
            </pre>
          </div>
        )}
        
        {/* Action buttons - reusing existing design */}
        <div className={styles.analysisActions}>
          <button 
            className={styles.actionButton}
            onClick={() => navigate('/dashboard')}
          >
            🏠 Back to Dashboard
          </button>
          <button 
            className={`${styles.actionButton} ${styles.primaryButton}`}
            onClick={() => {
              // Create and download JSON report for AI analysis
              const dataStr = JSON.stringify(aiResults, null, 2);
              const dataBlob = new Blob([dataStr], {type: 'application/json'});
              const url = URL.createObjectURL(dataBlob);
              const link = document.createElement('a');
              link.href = url;
              link.download = `ai_malware_analysis_${aiResults.analysis_id || Date.now()}.json`;
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            📥 Download AI Report
          </button>
        </div>
      </div>
    );
  };

  // Function to render analysis results
  const renderAnalysisResults = () => {
    if (!analysisResult) return null;

    // Check if this is AI malware detection results
    if (analysisResult.analysisType === 'malware' && analysisResult.aiResults) {
      return renderAIAnalysisResults();
    }

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
        
        {/* Report Format Dropdown */}
        <div className={styles.reportFormatDropdown}>
          <label htmlFor="formatSelect" className={styles.formatLabel}>Format:</label>
          <select
            id="formatSelect"
            value={reportFormat}
            onChange={(e) => setReportFormat(e.target.value)}
            className={styles.formatSelect}
          >
            {getAvailableFormats().map((format) => (
              <option key={format} value={format}>
                {format.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
        
        {/* Report Content */}
        <div className={styles.reportSection}>
          <h3>Security Analysis Report ({reportFormat.toUpperCase()})</h3>
          {renderReportContent()}
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
            onClick={handleDownloadReport}
            disabled={!analysisResult?.reportPath}
          >
            Download {reportFormat.toUpperCase()} Report
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
            <h2 className={styles.progressTitle}>
              {analysisType.toLowerCase() === 'malware' ? 
                '🤖 AI Malware Detection in Progress...' : 
                'Analyzing your APK...'
              }
            </h2>
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
              {analysisType.toLowerCase() === 'malware' ? (
                // AI Malware Detection Steps
                <>
                  <div className={`${styles.progressStep} ${analysisProgress >= 20 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>🤖 Loading AI Model</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 40 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>🔍 Extracting Features</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 60 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>🧠 AI Analysis</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 80 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>⚡ Making Prediction</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 100 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>📊 Generating Results</span>
                  </div>
                </>
              ) : (
                // Standard Analysis Steps
                <>
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
                </>
              )}
            </div>
          </div>
        )}

        {analysisResult && renderAnalysisResults()}
      </main>
    </div>
  );
};

export default Analysis;
