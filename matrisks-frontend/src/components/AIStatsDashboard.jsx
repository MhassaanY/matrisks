import React, { useState, useEffect } from 'react';
import { aiApi } from '../services/api';
import styles from './AIStatsDashboard.module.css';

const AIStatsDashboard = () => {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [aiHealth, setAiHealth] = useState(null);

  useEffect(() => {
    fetchAIData();
  }, []);

  const fetchAIData = async () => {
    setLoading(true);
    setError('');
    
    try {
      // Fetch all AI data in parallel
      const [statsResponse, historyResponse, healthResponse] = await Promise.all([
        aiApi.getStatistics().catch(e => ({ statistics: null, error: e.message })),
        aiApi.getHistory(10).catch(e => ({ data: [], error: e.message })),
        aiApi.getHealth().catch(e => ({ ai_service: null, error: e.message }))
      ]);

      // Handle statistics
      if (statsResponse.statistics) {
        setStats(statsResponse.statistics);
      }

      // Handle history
      if (historyResponse.data) {
        setHistory(historyResponse.data);
      }

      // Handle health
      if (healthResponse.ai_service || healthResponse.status) {
        setAiHealth(healthResponse);
      }

    } catch (err) {
      setError(`Failed to load AI data: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp) => {
    try {
      return new Date(timestamp).toLocaleDateString();
    } catch (e) {
      return 'Unknown';
    }
  };

  const getHealthStatusColor = (status) => {
    switch (status) {
      case 'healthy':
        return '#28a745';
      case 'unavailable':
        return '#dc3545';
      case 'unhealthy':
        return '#fd7e14';
      default:
        return '#6c757d';
    }
  };

  if (loading) {
    return (
      <div className={styles.dashboard}>
        <div className={styles.loadingContainer}>
          <div className={styles.spinner}></div>
          <p>Loading AI statistics...</p>
        </div>
      </div>
    );
  }

  if (error && !stats) {
    return (
      <div className={styles.dashboard}>
        <div className={styles.errorContainer}>
          <h3>⚠️ Unable to Load AI Statistics</h3>
          <p>{error}</p>
          <button onClick={fetchAIData} className={styles.retryBtn}>
            🔄 Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={styles.dashboard}>
      <div className={styles.header}>
        <h2 className={styles.title}>🤖 AI Malware Detection Dashboard</h2>
        <button onClick={fetchAIData} className={styles.refreshBtn}>
          🔄 Refresh
        </button>
      </div>

      {/* AI Health Status */}
      <div className={styles.healthCard}>
        <h3 className={styles.cardTitle}>🏥 AI Service Health</h3>
        {aiHealth ? (
          <div className={styles.healthStatus}>
            <div 
              className={styles.statusIndicator}
              style={{ backgroundColor: getHealthStatusColor(aiHealth.status) }}
            ></div>
            <div className={styles.healthInfo}>
              <div className={styles.statusText}>
                Status: <strong>{aiHealth.status || 'Unknown'}</strong>
              </div>
              <div className={styles.healthDetails}>
                <span>AI Available: {aiHealth.ai_available ? '✅' : '❌'}</span>
                <span>Model Loaded: {aiHealth.predictor_loaded ? '✅' : '❌'}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className={styles.healthUnavailable}>
            <span>❓ Health status unavailable</span>
          </div>
        )}
      </div>

      {/* Statistics Cards */}
      <div className={styles.statsGrid}>
        {stats ? (
          <>
            <div className={styles.statCard}>
              <div className={styles.statNumber}>{stats.total_analyses}</div>
              <div className={styles.statLabel}>Total Analyses</div>
              <div className={styles.statIcon}>📊</div>
            </div>

            <div className={styles.statCard}>
              <div className={styles.statNumber}>{stats.malware_detected}</div>
              <div className={styles.statLabel}>Malware Detected</div>
              <div className={styles.statIcon}>🦠</div>
            </div>

            <div className={styles.statCard}>
              <div className={styles.statNumber}>{stats.benign_detected}</div>
              <div className={styles.statLabel}>Benign Files</div>
              <div className={styles.statIcon}>✅</div>
            </div>

            <div className={styles.statCard}>
              <div className={styles.statNumber}>
                {(stats.average_confidence * 100).toFixed(1)}%
              </div>
              <div className={styles.statLabel}>Avg Confidence</div>
              <div className={styles.statIcon}>🎯</div>
            </div>

            <div className={styles.statCard}>
              <div className={styles.statNumber}>{stats.malware_percentage.toFixed(1)}%</div>
              <div className={styles.statLabel}>Malware Rate</div>
              <div className={styles.statIcon}>⚠️</div>
            </div>

            <div className={styles.statCard}>
              <div className={styles.statNumber}>{stats.analysis_errors}</div>
              <div className={styles.statLabel}>Analysis Errors</div>
              <div className={styles.statIcon}>❌</div>
            </div>
          </>
        ) : (
          <div className={styles.noStatsMessage}>
            <h3>📈 No Analysis Data Yet</h3>
            <p>Upload and analyze some APK files to see statistics here.</p>
          </div>
        )}
      </div>

      {/* Recent Analysis History */}
      <div className={styles.historyCard}>
        <h3 className={styles.cardTitle}>📜 Recent AI Analyses</h3>
        {history.length > 0 ? (
          <div className={styles.historyList}>
            {history.map((analysis, index) => (
              <div key={analysis.id || index} className={styles.historyItem}>
                <div className={styles.historyMain}>
                  <div className={styles.fileName}>
                    📱 {analysis.apk_name}
                  </div>
                  <div className={styles.analysisDate}>
                    {formatTimestamp(analysis.timestamp)}
                  </div>
                </div>
                <div className={styles.historyDetails}>
                  <div 
                    className={`${styles.prediction} ${
                      analysis.prediction === 'malware' ? styles.malware : styles.benign
                    }`}
                  >
                    {analysis.prediction === 'malware' ? '🦠 Malware' : '✅ Benign'}
                  </div>
                  <div className={styles.confidence}>
                    {(analysis.confidence * 100).toFixed(1)}% confidence
                  </div>
                  <div className={styles.features}>
                    {analysis.active_features || 0} features
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className={styles.noHistoryMessage}>
            <p>📭 No analysis history available yet.</p>
            <p>Start analyzing APK files to see your history here.</p>
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className={styles.actionsCard}>
        <h3 className={styles.cardTitle}>⚡ Quick Actions</h3>
        <div className={styles.actionButtons}>
          <button className={styles.actionBtn} onClick={() => window.location.href = '/analysis'}>
            📤 Upload New APK
          </button>
          <button className={styles.actionBtn} onClick={() => window.location.href = '/dashboard'}>
            📊 View All Analyses
          </button>
          <button className={styles.actionBtn} onClick={fetchAIData}>
            🔄 Refresh Data
          </button>
        </div>
      </div>
    </div>
  );
};

export default AIStatsDashboard;