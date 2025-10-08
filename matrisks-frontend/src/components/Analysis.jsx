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
        // AI-specific results with ALL available information
        aiResults: {
          prediction: apiResult.results?.prediction,
          confidence: apiResult.results?.confidence,
          risk_level: apiResult.results?.risk_level,
          active_features: apiResult.results?.active_features,
          total_features: apiResult.results?.total_features,
          feature_analysis: apiResult.results?.feature_analysis,
          model_info: apiResult.results?.model_info,
          file_size: apiResult.results?.file_size,
          analysis_id: apiResult.results?.analysis_id,
          scan_id: apiResult.results?.scan_id,  // Add scan_id for downloads
          // Additional detailed information
          probabilities: apiResult.results?.probabilities,
          model_prediction: apiResult.results?.model_prediction,
          model_confidence: apiResult.results?.model_confidence,
          heuristic_adjustment: apiResult.results?.heuristic_adjustment,
          active_feature_list: apiResult.results?.active_feature_list
        },
        htmlReport: null, // AI doesn't generate HTML reports
        jsonReport: JSON.stringify(apiResult.results || {}, null, 2),
        csvReport: null,
        rawOutput: JSON.stringify(apiResult, null, 2),
        reportPath: apiResult.report_path || apiResult.analysis_id  // Use report_path or analysis_id for downloads
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
    // For AI scans, only JSON format is available
    if (analysisResult?.analysisType === 'malware') {
      if (!analysisResult?.reportPath) {
        setError('Report not available for download');
        return;
      }

      try {
        const scanId = analysisResult.reportPath;
        const token = localStorage.getItem('access_token');
        
        // AI scans only have JSON format
        const downloadUrl = buildApiUrl(`/analysis/download/${scanId}?format=json`);
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
          a.download = `ai_malware_report_${scanId}.json`;
          document.body.appendChild(a);
          a.click();
          window.URL.revokeObjectURL(url);
          document.body.removeChild(a);
        } else {
          const errorText = await response.text();
          console.error('Download failed:', response.status, errorText);
          setError('Failed to download report. The report file may not exist yet.');
        }
      } catch (error) {
        console.error('Download failed:', error);
        setError('Failed to download report');
      }
      return;
    }

    // For static scans (basic/advanced)
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
        <h2 className={styles.resultsTitle}>AI Malware Detection Results</h2>
        
        {/* Main AI Result Card */}
        <div className={styles.aiMainResult}>
          <div className={styles.aiPredictionSection}>
            <div className={styles.aiPredictionLabel}>Classification:</div>
            <div 
              className={`${styles.aiPrediction} ${
                aiResults.prediction === 'malware' ? styles.aiMalware : styles.aiBenign
              }`}
            >
              {aiResults.prediction === 'malware' ? 'MALWARE' : 'BENIGN'}
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
          <h3>Analysis Information</h3>
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
          <h3>Security Recommendations</h3>
          {aiResults.prediction === 'malware' ? (
            <div className={styles.aiMalwareRecommendation}>
              <p className={styles.aiWarning}>
                <strong>This APK has been classified as potentially malicious!</strong>
              </p>
              
              {/* Risk Assessment Summary */}
              <div className={styles.riskSummary}>
                <div className={styles.riskSummaryItem}>
                  <span className={styles.riskSummaryLabel}>Threat Level:</span>
                  <span className={`${styles.riskSummaryValue} ${styles.threatHigh}`}>
                    {aiResults.risk_level?.toUpperCase() || 'HIGH'}
                  </span>
                </div>
                <div className={styles.riskSummaryItem}>
                  <span className={styles.riskSummaryLabel}>Detection Confidence:</span>
                  <span className={styles.riskSummaryValue}>
                    {(aiResults.confidence * 100).toFixed(1)}% 
                    {aiResults.confidence > 0.8 ? ' (Very High)' : aiResults.confidence > 0.6 ? ' (High)' : ' (Moderate)'}
                  </span>
                </div>
                <div className={styles.riskSummaryItem}>
                  <span className={styles.riskSummaryLabel}>Suspicious Features Found:</span>
                  <span className={styles.riskSummaryValue}>
                    {aiResults.active_features || 0} / {aiResults.total_features || 215}
                  </span>
                </div>
                {aiResults.heuristic_adjustment?.applied && (
                  <div className={styles.riskSummaryItem}>
                    <span className={styles.riskSummaryLabel}>High-Risk Patterns:</span>
                    <span className={`${styles.riskSummaryValue} ${styles.criticalMarker}`}>
                      {aiResults.heuristic_adjustment.triggered_features?.length || 0} Critical Indicators Detected
                    </span>
                  </div>
                )}
              </div>

              {/* Immediate Actions */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Immediate Actions Required</h4>
                <ul className={styles.aiRecommendationsList}>
                  <li><strong>DO NOT install</strong> this application on any device</li>
                  <li><strong>Quarantine or delete</strong> the APK file immediately from your system</li>
                  <li><strong>Scan your system</strong> if this file was already executed or installed</li>
                  <li><strong>Report to security team</strong> if this was received from an unknown source</li>
                  {aiResults.confidence > 0.8 && (
                    <li className={styles.criticalItem}>
                      <strong>CRITICAL:</strong> High confidence detection ({(aiResults.confidence * 100).toFixed(1)}%) - This is very likely malware
                    </li>
                  )}
                  {aiResults.heuristic_adjustment?.applied && (
                    <li className={styles.criticalItem}>
                      <strong>ALERT:</strong> Multiple high-risk security patterns detected in the APK
                    </li>
                  )}
                </ul>
              </div>

              {/* What This Means */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>What This Means</h4>
                <div className={styles.explanationText}>
                  <p>
                    Our AI-powered malware detection system has analyzed <strong>{aiResults.total_features || 215} security features</strong> 
                    {' '}extracted from this APK and found <strong>{aiResults.active_features || 0} suspicious indicators</strong>.
                  </p>
                  {aiResults.probabilities && (
                    <p>
                      The machine learning model calculated a <strong>{(aiResults.probabilities.malware * 100).toFixed(1)}% probability</strong> 
                      {' '}that this application contains malicious code, compared to only{' '}
                      <strong>{(aiResults.probabilities.benign * 100).toFixed(1)}%</strong> chance of being benign.
                    </p>
                  )}
                  {aiResults.heuristic_adjustment?.applied && aiResults.heuristic_adjustment.triggered_features?.length > 0 && (
                    <p className={styles.criticalExplanation}>
                      <strong>Critical Finding:</strong> The analysis detected {aiResults.heuristic_adjustment.triggered_features.length} 
                      {' '}high-risk security patterns including dangerous API calls commonly used by malware (such as{' '}
                      {aiResults.heuristic_adjustment.triggered_features.slice(0, 2).map(f => f.feature).join(', ')}).
                    </p>
                  )}
                </div>
              </div>

              {/* Why It's Dangerous */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Potential Threats</h4>
                <ul className={styles.aiRecommendationsList}>
                  <li>May steal personal information (contacts, messages, photos)</li>
                  <li>Could access sensitive data (passwords, banking details)</li>
                  <li>Might install additional malicious software</li>
                  <li>Could send premium SMS messages without permission</li>
                  <li>May track your location and activities</li>
                  <li>Could give attacker remote control of your device</li>
                </ul>
              </div>

              {/* Next Steps */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Recommended Next Steps</h4>
                <ul className={styles.aiRecommendationsList}>
                  <li>Run a full antivirus scan on your device if the APK was installed</li>
                  <li>Change passwords if you suspect data compromise</li>
                  <li>Monitor bank accounts and credit reports for suspicious activity</li>
                  <li>Report to Google Play Protect or relevant security authorities</li>
                  <li>Educate yourself about safe app download practices</li>
                  <li>Only download apps from official stores (Google Play, verified sources)</li>
                </ul>
              </div>
            </div>
          ) : (
            <div className={styles.aiBenignRecommendation}>
              <p className={styles.aiSuccess}>
                <strong>✓ This APK appears to be clean.</strong>
              </p>
              
              {/* Safety Summary */}
              <div className={styles.safetySummary}>
                <div className={styles.safetySummaryItem}>
                  <span className={styles.safetySummaryLabel}>Safety Rating:</span>
                  <span className={`${styles.safetySummaryValue} ${styles.safetyGood}`}>
                    {aiResults.confidence > 0.8 ? 'Excellent' : aiResults.confidence > 0.6 ? 'Good' : 'Fair'}
                  </span>
                </div>
                <div className={styles.safetySummaryItem}>
                  <span className={styles.safetySummaryLabel}>Detection Confidence:</span>
                  <span className={styles.safetySummaryValue}>
                    {(aiResults.confidence * 100).toFixed(1)}%
                  </span>
                </div>
                <div className={styles.safetySummaryItem}>
                  <span className={styles.safetySummaryLabel}>Features Analyzed:</span>
                  <span className={styles.safetySummaryValue}>
                    {aiResults.total_features || 215} security checks passed
                  </span>
                </div>
              </div>

              {/* What This Means */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Analysis Results</h4>
                <div className={styles.explanationText}>
                  <p>
                    Our AI model analyzed <strong>{aiResults.total_features || 215} security features</strong> and found 
                    {' '}<strong>{aiResults.active_features || 0} active features</strong>, with a{' '}
                    <strong>{(aiResults.probabilities?.benign * 100).toFixed(1)}% probability</strong> that this application is benign.
                  </p>
                  {aiResults.confidence < 0.6 && (
                    <p className={styles.cautionNote}>
                      <strong>Note:</strong> While the app appears clean, the confidence score is moderate ({(aiResults.confidence * 100).toFixed(1)}%). 
                      We recommend additional verification before installation.
                    </p>
                  )}
                </div>
              </div>

              {/* Best Practices */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Security Best Practices</h4>
                <ul className={styles.aiRecommendationsList}>
                  <li>The file passed AI malware detection successfully</li>
                  <li>Review app permissions before installing - deny unnecessary access</li>
                  <li>Consider running additional security scans for complete verification</li>
                  <li>Always download APKs from trusted, verified sources</li>
                  <li>Keep your device's security software and OS updated</li>
                  <li>Monitor app behavior after installation for unusual activity</li>
                  {aiResults.confidence < 0.6 && (
                    <li className={styles.cautionItem}>
                      <strong>Recommended:</strong> Run supplementary static/dynamic analysis for thorough verification
                    </li>
                  )}
                </ul>
              </div>

              {/* General Tips */}
              <div className={styles.recommendationSection}>
                <h4 className={styles.sectionHeading}>Additional Security Tips</h4>
                <ul className={styles.aiRecommendationsList}>
                  <li>Read app reviews and ratings before installation</li>
                  <li>Check developer reputation and credentials</li>
                  <li>Be cautious with apps requesting excessive permissions</li>
                  <li>Enable Google Play Protect on Android devices</li>
                  <li>Regular backup important data</li>
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Detection Details - NEW SECTION */}
        {(aiResults.probabilities || aiResults.heuristic_adjustment) && (
          <div className={styles.detectionDetails}>
            <h3>Detection Details</h3>
            
            {/* Probability Breakdown */}
            {aiResults.probabilities && (
              <div className={styles.probabilitySection}>
                <h4>Probability Analysis</h4>
                <div className={styles.probabilityGrid}>
                  <div className={styles.probabilityItem}>
                    <span className={styles.probabilityLabel}>Benign Probability:</span>
                    <div className={styles.probabilityBar}>
                      <div 
                        className={styles.probabilityFillBenign}
                        style={{ width: `${(aiResults.probabilities.benign * 100)}%` }}
                      ></div>
                      <span className={styles.probabilityText}>
                        {(aiResults.probabilities.benign * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>
                  <div className={styles.probabilityItem}>
                    <span className={styles.probabilityLabel}>Malware Probability:</span>
                    <div className={styles.probabilityBar}>
                      <div 
                        className={styles.probabilityFillMalware}
                        style={{ width: `${(aiResults.probabilities.malware * 100)}%` }}
                      ></div>
                      <span className={styles.probabilityText}>
                        {(aiResults.probabilities.malware * 100).toFixed(2)}%
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Heuristic Analysis */}
            {aiResults.heuristic_adjustment?.applied && (
              <div className={styles.heuristicSection}>
                <h4>Heuristic Rule Analysis</h4>
                <div className={styles.heuristicInfo}>
                  <div className={styles.heuristicStatus}>
                    <span className={styles.heuristicBadge}>Heuristics Applied</span>
                    {aiResults.model_prediction && aiResults.model_prediction !== aiResults.prediction && (
                      <div className={styles.predictionChange}>
                        <span className={styles.changeLabel}>Prediction Changed:</span>
                        <span className={styles.oldPrediction}>{aiResults.model_prediction}</span>
                        <span className={styles.arrow}>→</span>
                        <span className={styles.newPrediction}>{aiResults.prediction}</span>
                      </div>
                    )}
                  </div>
                  
                  {aiResults.heuristic_adjustment.triggered_features?.length > 0 && (
                    <div className={styles.triggeredFeatures}>
                      <h5>High-Risk Features Detected:</h5>
                      <div className={styles.featuresList}>
                        {aiResults.heuristic_adjustment.triggered_features.map((feat, idx) => (
                          <div key={idx} className={styles.featureItem}>
                            <span className={styles.featureName}>{feat.feature}</span>
                            <span className={styles.featureWeight}>
                              Weight: {(feat.weight * 100).toFixed(0)}%
                            </span>
                          </div>
                        ))}
                      </div>
                      <div className={styles.heuristicScore}>
                        <span>Total Heuristic Score:</span>
                        <span className={styles.scoreValue}>
                          {(aiResults.heuristic_adjustment.score * 100).toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Model vs Final Prediction Comparison */}
            {aiResults.model_confidence && aiResults.model_confidence !== aiResults.confidence && (
              <div className={styles.comparisonSection}>
                <h4>Prediction Comparison</h4>
                <div className={styles.comparisonGrid}>
                  <div className={styles.comparisonItem}>
                    <span className={styles.comparisonLabel}>Original Model:</span>
                    <span className={styles.comparisonValue}>
                      {aiResults.model_prediction} ({(aiResults.model_confidence * 100).toFixed(1)}%)
                    </span>
                  </div>
                  <div className={styles.comparisonItem}>
                    <span className={styles.comparisonLabel}>Final Result:</span>
                    <span className={styles.comparisonValue}>
                      {aiResults.prediction} ({(aiResults.confidence * 100).toFixed(1)}%)
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Active Features - NEW SECTION */}
        {aiResults.active_feature_list && aiResults.active_feature_list.length > 0 && (
          <div className={styles.activeFeaturesSection}>
            <h3>Detected Features</h3>
            <p className={styles.featuresDescription}>
              The following suspicious features were detected in the APK (showing top {aiResults.active_feature_list.length} of {aiResults.active_features}):
            </p>
            <div className={styles.featuresGrid}>
              {aiResults.active_feature_list.map((feature, idx) => (
                <div key={idx} className={styles.featureChip}>
                  {feature}
                </div>
              ))}
            </div>
          </div>
        )}

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
            <h3>Comprehensive AI Analysis Report (JSON)</h3>
            <div className={styles.jsonExplanation}>
              <p>This report contains all technical details including probabilities, heuristic analysis, feature detection, and security recommendations.</p>
            </div>
            <pre className={styles.jsonReportContent}>
              {JSON.stringify({
                report_metadata: {
                  report_title: "AI Malware Detection Analysis Report",
                  generated_at: new Date().toISOString(),
                  analysis_id: aiResults.analysis_id || "N/A",
                  apk_name: analysisResult.fileInfo?.name || "Unknown"
                },
                
                executive_summary: {
                  classification: aiResults.prediction,
                  confidence_score: aiResults.confidence,
                  confidence_percentage: `${(aiResults.confidence * 100).toFixed(2)}%`,
                  risk_level: aiResults.risk_level || "unknown",
                  threat_assessment: aiResults.prediction === 'malware' 
                    ? (aiResults.confidence > 0.8 ? "CRITICAL - High confidence malware detection" 
                      : aiResults.confidence > 0.6 ? "HIGH - Moderate confidence malware detection"
                      : "MEDIUM - Low confidence malware detection")
                    : (aiResults.confidence > 0.8 ? "SAFE - High confidence benign classification"
                      : aiResults.confidence > 0.6 ? "LIKELY SAFE - Moderate confidence benign classification"
                      : "UNCERTAIN - Low confidence benign classification")
                },

                detection_details: {
                  probabilities: {
                    benign_percentage: `${((aiResults.probabilities?.benign || 0) * 100).toFixed(2)}%`,
                    malware_percentage: `${((aiResults.probabilities?.malware || 0) * 100).toFixed(2)}%`
                  },
                  model_analysis: {
                    original_prediction: aiResults.model_prediction || aiResults.prediction,
                    final_prediction: aiResults.prediction,
                    prediction_modified: aiResults.model_prediction !== aiResults.prediction
                  },
                  heuristic_analysis: {
                    heuristics_applied: aiResults.heuristic_adjustment?.applied || false,
                    high_risk_features_count: aiResults.heuristic_adjustment?.triggered_features?.length || 0,
                    triggered_features: aiResults.heuristic_adjustment?.triggered_features || []
                  }
                },

                feature_analysis: {
                  total_features_analyzed: aiResults.total_features || 215,
                  active_features_detected: aiResults.active_features || 0,
                  feature_activation_rate: `${((aiResults.active_features / (aiResults.total_features || 215)) * 100).toFixed(1)}%`,
                  top_suspicious_features: aiResults.active_feature_list || []
                },

                file_information: {
                  file_size_mb: ((aiResults.file_size || 0) / (1024 * 1024)).toFixed(2),
                  analysis_timestamp: aiResults.timestamp || analysisResult.timestamp
                },

                full_technical_data: aiResults
              }, null, 2)}
            </pre>
          </div>
        )}
        
        {/* Action buttons - reusing existing design */}
        <div className={styles.analysisActions}>
          <button 
            className={styles.actionButton}
            onClick={() => navigate('/dashboard')}
          >
            Back to Dashboard
          </button>
          <button 
            className={`${styles.actionButton} ${styles.primaryButton}`}
            onClick={() => {
              // Create comprehensive JSON report for AI analysis
              const comprehensiveReport = {
                report_metadata: {
                  report_title: "AI Malware Detection Analysis Report",
                  generated_at: new Date().toISOString(),
                  report_version: "2.0",
                  analysis_id: aiResults.analysis_id || Date.now(),
                  apk_name: analysisResult.fileInfo?.name || "Unknown"
                },
                
                executive_summary: {
                  classification: aiResults.prediction,
                  confidence_score: aiResults.confidence,
                  confidence_percentage: `${(aiResults.confidence * 100).toFixed(2)}%`,
                  risk_level: aiResults.risk_level || "unknown",
                  threat_assessment: aiResults.prediction === 'malware' 
                    ? (aiResults.confidence > 0.8 ? "CRITICAL - High confidence malware detection" 
                      : aiResults.confidence > 0.6 ? "HIGH - Moderate confidence malware detection"
                      : "MEDIUM - Low confidence malware detection")
                    : (aiResults.confidence > 0.8 ? "SAFE - High confidence benign classification"
                      : aiResults.confidence > 0.6 ? "LIKELY SAFE - Moderate confidence benign classification"
                      : "UNCERTAIN - Low confidence benign classification"),
                  recommendation: aiResults.prediction === 'malware'
                    ? "DO NOT INSTALL - Quarantine or delete this APK immediately"
                    : "Appears safe, but verify permissions before installation"
                },

                detection_details: {
                  probabilities: {
                    benign: aiResults.probabilities?.benign || 0,
                    benign_percentage: `${((aiResults.probabilities?.benign || 0) * 100).toFixed(2)}%`,
                    malware: aiResults.probabilities?.malware || 0,
                    malware_percentage: `${((aiResults.probabilities?.malware || 0) * 100).toFixed(2)}%`
                  },
                  
                  model_analysis: {
                    original_prediction: aiResults.model_prediction || aiResults.prediction,
                    original_confidence: aiResults.model_confidence || aiResults.confidence,
                    final_prediction: aiResults.prediction,
                    final_confidence: aiResults.confidence,
                    prediction_modified: aiResults.model_prediction !== aiResults.prediction,
                    model_type: aiResults.model_info?.model_type || "RandomForestClassifier"
                  },

                  heuristic_analysis: {
                    heuristics_applied: aiResults.heuristic_adjustment?.applied || false,
                    heuristic_score: aiResults.heuristic_adjustment?.score || 0,
                    heuristic_impact: aiResults.heuristic_adjustment?.score 
                      ? `${(aiResults.heuristic_adjustment.score * 100).toFixed(1)}% boost to malware probability`
                      : "No heuristic adjustments applied",
                    high_risk_features_detected: aiResults.heuristic_adjustment?.triggered_features || [],
                    risk_feature_count: aiResults.heuristic_adjustment?.triggered_features?.length || 0,
                    explanation: aiResults.heuristic_adjustment?.applied
                      ? "High-risk security patterns detected that commonly indicate malicious behavior"
                      : "No critical security patterns detected"
                  }
                },

                feature_analysis: {
                  total_features_analyzed: aiResults.total_features || 215,
                  active_features_detected: aiResults.active_features || 0,
                  feature_activation_rate: `${((aiResults.active_features / (aiResults.total_features || 215)) * 100).toFixed(1)}%`,
                  suspicious_features: aiResults.active_feature_list || [],
                  feature_categories: {
                    permissions: aiResults.active_feature_list?.filter(f => f.includes('PERMISSION') || f.includes('_')).length || 0,
                    api_calls: aiResults.active_feature_list?.filter(f => f.includes('.') && !f.includes('_')).length || 0,
                    security_indicators: aiResults.heuristic_adjustment?.triggered_features?.length || 0
                  }
                },

                file_information: {
                  file_name: analysisResult.fileInfo?.name || "Unknown",
                  file_size_bytes: aiResults.file_size || 0,
                  file_size_mb: ((aiResults.file_size || 0) / (1024 * 1024)).toFixed(2),
                  analysis_timestamp: aiResults.timestamp || analysisResult.timestamp,
                  scan_id: aiResults.scan_id || analysisResult.reportPath || aiResults.analysis_id
                },

                security_recommendations: aiResults.prediction === 'malware' ? {
                  immediate_actions: [
                    "DO NOT install this application on any device",
                    "Quarantine or delete the APK file immediately",
                    "Scan your system if the file was already executed",
                    "Report to security team if received from unknown source",
                    "Change passwords if data compromise is suspected"
                  ],
                  potential_threats: [
                    "May steal personal information (contacts, messages, photos)",
                    "Could access sensitive data (passwords, banking details)",
                    "Might install additional malicious software",
                    "Could send premium SMS messages without permission",
                    "May track location and activities",
                    "Could give attacker remote control of device"
                  ],
                  next_steps: [
                    "Run full antivirus scan if APK was installed",
                    "Monitor bank accounts for suspicious activity",
                    "Report to Google Play Protect or security authorities",
                    "Educate yourself about safe app download practices",
                    "Only download apps from official verified sources"
                  ]
                } : {
                  verification_steps: [
                    "Review app permissions before installation",
                    "Consider running additional security scans",
                    "Download only from trusted, verified sources",
                    "Monitor app behavior after installation",
                    "Keep device security software updated"
                  ],
                  best_practices: [
                    "Read app reviews and ratings",
                    "Check developer reputation",
                    "Be cautious with excessive permissions",
                    "Enable Google Play Protect",
                    "Regular backup important data"
                  ]
                },

                technical_details: {
                  model_information: {
                    model_type: aiResults.model_info?.model_type || "RandomForestClassifier",
                    feature_count: aiResults.model_info?.feature_count || 215,
                    model_version: "1.0"
                  },
                  analysis_metrics: {
                    confidence_score: aiResults.confidence,
                    probability_distribution: aiResults.probabilities,
                    feature_activation_ratio: (aiResults.active_features || 0) / (aiResults.total_features || 215)
                  }
                },

                disclaimer: {
                  notice: "This is an automated AI-based analysis and should be used as one factor in security decision-making.",
                  recommendations: [
                    "This analysis should be supplemented with additional security scans",
                    "No detection system is 100% accurate - use multiple verification methods",
                    "Keep your security software and databases updated",
                    "Report suspected malware to appropriate authorities"
                  ],
                  liability: "Results are provided as-is for informational purposes only"
                }
              };

              const dataStr = JSON.stringify(comprehensiveReport, null, 2);
              const dataBlob = new Blob([dataStr], {type: 'application/json'});
              const url = URL.createObjectURL(dataBlob);
              const link = document.createElement('a');
              link.href = url;
              link.download = `comprehensive_ai_malware_report_${aiResults.analysis_id || Date.now()}.json`;
              link.click();
              URL.revokeObjectURL(url);
            }}
          >
            Download AI Report
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
                'AI Malware Detection in Progress...' : 
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
                    <span className={styles.stepLabel}>Loading AI Model</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 40 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>Extracting Features</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 60 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>AI Analysis</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 80 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>Making Prediction</span>
                  </div>
                  <div className={`${styles.progressStep} ${analysisProgress >= 100 ? styles.completed : ''}`}>
                    <div className={styles.stepIcon}></div>
                    <span className={styles.stepLabel}>Generating Results</span>
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
