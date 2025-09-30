import React from 'react';
import styles from './AIAnalysisResult.module.css';

const AIAnalysisResult = ({ result, onNewAnalysis }) => {
  if (!result) return null;

  const getRiskColor = (riskLevel) => {
    switch (riskLevel?.toLowerCase()) {
      case 'high':
        return '#dc3545'; // Red
      case 'medium':
        return '#fd7e14'; // Orange
      case 'low':
        return '#ffc107'; // Yellow
      default:
        return '#6c757d'; // Gray
    }
  };

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.8) return '#dc3545'; // High confidence - Red
    if (confidence >= 0.6) return '#fd7e14'; // Medium confidence - Orange
    if (confidence >= 0.4) return '#ffc107'; // Low-medium confidence - Yellow
    return '#28a745'; // Low confidence - Green
  };

  const formatTimestamp = (timestamp) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch (e) {
      return timestamp || 'Unknown';
    }
  };

  const formatFileSize = (bytes) => {
    if (!bytes) return 'Unknown';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  return (
    <div className={styles.resultContainer}>
      <div className={styles.header}>
        <h2 className={styles.title}>
          🤖 AI Malware Detection Results
        </h2>
        <button 
          className={styles.newAnalysisBtn}
          onClick={onNewAnalysis}
        >
          📊 New Analysis
        </button>
      </div>

      {/* Main Result Card */}
      <div className={styles.mainResult}>
        <div className={styles.predictionSection}>
          <div className={styles.predictionLabel}>Classification:</div>
          <div 
            className={`${styles.prediction} ${
              result.prediction === 'malware' ? styles.malware : styles.benign
            }`}
          >
            {result.prediction === 'malware' ? '🦠 MALWARE' : '✅ BENIGN'}
          </div>
        </div>

        <div className={styles.confidenceSection}>
          <div className={styles.confidenceLabel}>Confidence Score:</div>
          <div className={styles.confidenceBar}>
            <div 
              className={styles.confidenceFill}
              style={{ 
                width: `${(result.confidence * 100)}%`,
                backgroundColor: getConfidenceColor(result.confidence)
              }}
            ></div>
            <span className={styles.confidenceText}>
              {(result.confidence * 100).toFixed(1)}%
            </span>
          </div>
        </div>

        <div className={styles.riskSection}>
          <div className={styles.riskLabel}>Risk Level:</div>
          <div 
            className={styles.riskBadge}
            style={{ backgroundColor: getRiskColor(result.risk_level) }}
          >
            {result.risk_level?.toUpperCase() || 'UNKNOWN'}
          </div>
        </div>
      </div>

      {/* Detailed Information */}
      <div className={styles.detailsGrid}>
        {/* File Information */}
        <div className={styles.detailCard}>
          <h3 className={styles.cardTitle}>📱 File Information</h3>
          <div className={styles.infoRow}>
            <span className={styles.label}>File Size:</span>
            <span className={styles.value}>{formatFileSize(result.file_size)}</span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Analysis Time:</span>
            <span className={styles.value}>{formatTimestamp(result.timestamp)}</span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Analysis ID:</span>
            <span className={styles.value}>#{result.analysis_id || 'N/A'}</span>
          </div>
        </div>

        {/* Feature Analysis */}
        <div className={styles.detailCard}>
          <h3 className={styles.cardTitle}>🔍 Feature Analysis</h3>
          <div className={styles.infoRow}>
            <span className={styles.label}>Active Features:</span>
            <span className={styles.value}>{result.active_features || 0}</span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Total Features:</span>
            <span className={styles.value}>{result.total_features || 215}</span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Feature Coverage:</span>
            <span className={styles.value}>
              {result.total_features ? 
                ((result.active_features / result.total_features) * 100).toFixed(1) + '%' : 
                '0%'
              }
            </span>
          </div>
        </div>

        {/* Model Information */}
        <div className={styles.detailCard}>
          <h3 className={styles.cardTitle}>🤖 Model Information</h3>
          <div className={styles.infoRow}>
            <span className={styles.label}>Model Type:</span>
            <span className={styles.value}>
              {result.model_info?.model_type || 'RandomForest'}
            </span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Model Status:</span>
            <span className={styles.value}>
              {result.model_info?.model_loaded ? '✅ Loaded' : '❌ Not Loaded'}
            </span>
          </div>
          <div className={styles.infoRow}>
            <span className={styles.label}>Features Supported:</span>
            <span className={styles.value}>
              {result.model_info?.feature_count || 215}
            </span>
          </div>
        </div>
      </div>

      {/* Recommendation Section */}
      <div className={styles.recommendationCard}>
        <h3 className={styles.cardTitle}>💡 Recommendations</h3>
        {result.prediction === 'malware' ? (
          <div className={styles.malwareRecommendation}>
            <p className={styles.warning}>
              ⚠️ <strong>This APK has been classified as potentially malicious!</strong>
            </p>
            <ul className={styles.recommendations}>
              <li>Do not install this application on your device</li>
              <li>Delete the APK file from your system</li>
              <li>Report this file to your security team if downloaded from company resources</li>
              <li>Run additional scans if you suspect system compromise</li>
              {result.confidence > 0.8 && (
                <li><strong>High confidence detection</strong> - This is very likely malware</li>
              )}
            </ul>
          </div>
        ) : (
          <div className={styles.benignRecommendation}>
            <p className={styles.success}>
              ✅ <strong>This APK appears to be clean.</strong>
            </p>
            <ul className={styles.recommendations}>
              <li>The file passed AI malware detection</li>
              <li>Consider running additional security scans for complete verification</li>
              <li>Always download APKs from trusted sources</li>
              <li>Keep your device's security software updated</li>
              {result.confidence < 0.6 && (
                <li><strong>Note:</strong> Low confidence score - consider additional analysis</li>
              )}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};

export default AIAnalysisResult;