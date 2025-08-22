/**
 * API service for Matrisks platform
 * This file will interface with the FastAPI backend in the future
 */

// Base URL for API calls
const API_BASE_URL = (() => {
  if (import.meta.env?.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  return 'http://localhost:8000';
})();

// Check if we should use mock data
const USE_MOCK_DATA = (() => {
  if (import.meta.env?.VITE_USE_MOCK_DATA === 'false') return false;
  if (import.meta.env?.VITE_USE_MOCK_DATA === 'true') return true;
  return false; // default to false to use actual API
})();

console.log('API Configuration:', {
  API_BASE_URL,
  USE_MOCK_DATA,
  NODE_ENV: import.meta.env?.MODE,
  DEV: import.meta.env?.DEV
});

/**
 * Handles API requests with proper error handling
 * @param {string} endpoint - API endpoint
 * @param {Object} options - Fetch options
 * @returns {Promise<Object>} - Response data
 */
async function apiRequest(endpoint, options = {}) {
  // If using mock data, return mock responses for all endpoints
  if (USE_MOCK_DATA) {
    console.log('Using mock data for endpoint:', endpoint);
    return getMockResponse(endpoint, options);
  }
  
  const url = `${API_BASE_URL}${endpoint}`;
  console.log(`Making API request to: ${url}`, { options });
  
  try {
    const token = localStorage.getItem('access_token');
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        ...options.headers,
      },
      credentials: 'include', // Include cookies for authentication
    });

    console.log(`API response status: ${response.status}`, { url });
    
    // Try to parse the response as JSON, but fall back to text if it fails
    let responseData;
    const contentType = response.headers.get('content-type');
    
    if (contentType && contentType.includes('application/json')) {
      responseData = await response.json().catch(() => ({
        message: 'Failed to parse JSON response'
      }));
    } else {
      const text = await response.text();
      responseData = { message: text || 'No content' };
    }

    if (!response.ok) {
      console.error('API request failed:', {
        status: response.status,
        statusText: response.statusText,
        url,
        response: responseData
      });
      
      // If we get a 401, the user might need to log in
      if (response.status === 401) {
        // You might want to handle authentication here
        console.warn('Authentication required');
      }
      
      throw new Error(
        responseData.message || 
        responseData.detail || 
        `API request failed with status ${response.status}`
      );
    }

    return responseData;
  } catch (error) {
    console.error('API request error:', {
      error,
      endpoint,
      url,
      message: error.message,
      stack: error.stack
    });
    
    // If we're in development or the error is network-related, provide more details
    const isNetworkError = !navigator.onLine || error.message.includes('Failed to fetch');
    const enhancedError = new Error(
      isNetworkError 
        ? 'Network error. Please check your connection.'
        : `API request failed: ${error.message}`
    );
    enhancedError.originalError = error;
    enhancedError.isNetworkError = isNetworkError;
    
    throw enhancedError;
  }
}

// Helper to generate a random date within the last 30 days
const randomDate = () => {
  const now = new Date();
  const pastDate = new Date();
  pastDate.setDate(now.getDate() - 30);
  return new Date(pastDate.getTime() + Math.random() * (now.getTime() - pastDate.getTime()));
};

// Generate mock analysis history with recent timestamps
const generateMockHistory = () => {
  const analysisTypes = [
    'Basic Analysis',
    'Advanced Analysis',
    'Malware Detection',
    'Static Analysis',
    'Dynamic Analysis'
  ];

  const apkNames = [
    'app-release.apk',
    'game-beta.apk',
    'utility-app.apk',
    'social-media.apk',
    'shopping-app.apk',
    'fitness-tracker.apk'
  ];

  return Array.from({ length: 10 }, (_, i) => ({
    id: `analysis-${Date.now()}-${i}`,
    apkName: apkNames[Math.floor(Math.random() * apkNames.length)],
    analysisType: analysisTypes[Math.floor(Math.random() * analysisTypes.length)],
    timestamp: randomDate().toISOString(),
    status: 'completed',
    riskScore: Math.floor(Math.random() * 100)
  })).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
};



function getMockResponse(endpoint, options) {
  throw new Error(`Mock data is disabled. Attempted to use mock data for endpoint: ${endpoint}`);
}

/**
 * Upload a file for analysis
 * @param {File} file - File to analyze
 * @param {string} analysisType - Type of analysis to perform
 * @returns {Promise<Object>} - Analysis result
 */
export async function uploadFileForAnalysis(file, analysisType) {
  // This will be replaced with an actual API call when FastAPI is implemented
  const formData = new FormData();
  formData.append('file', file);
  formData.append('analysisType', analysisType);

  // For now, return mock response
  return apiRequest('/analyze', {
    method: 'POST', 
    body: formData,
    headers: {
      // Remove Content-Type header so boundary is set automatically for FormData
      'Content-Type': undefined
    }
  });
}

/**
 * Get analysis result by ID
 * @param {string} analysisId - Analysis ID
 * @returns {Promise<Object>} - Analysis result
 */
export async function getAnalysisResult(analysisId) {
  return apiRequest(`/analysis/result/${analysisId}`);
}

/**
 * Get analysis history for the current user
 * @returns {Promise<Array>} - User's analysis history
 */
export async function getAnalysisHistory() {
  try {
    const response = await apiRequest('/analysis/history');
    // Ensure the response is an array
    if (Array.isArray(response)) {
      return response;
    }
    // If response is not an array but has a data property that is an array
    if (response && Array.isArray(response.data)) {
      return response.data;
    }
    // If we get here, the response format is unexpected
    console.warn('Unexpected response format, using mock data instead');
    throw new Error('Unexpected response format');
  } catch (error) {
    console.error('Error fetching analysis history:', error);
    // Re-throw to be handled by the caller
    throw error;
  }
}

/**
 * Get available analysis types
 * @returns {Promise<Array>} - Available analysis types
 */
export async function getAnalysisTypes() {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 800));
  
  // Return mock data
  return [
    { 
      id: 'intelligent-defense', 
      name: 'Intelligent Defense', 
      description: 'Our advanced AI-powered security engine identifies potential vulnerabilities and evolves with each scan, providing continuous protection.',
      icon: '/shield-icon.svg'
    },
    { 
      id: 'lightning-analysis', 
      name: 'Lightning Analysis', 
      description: 'Experience unprecedented speed with our optimized scanning technology that seamlessly integrates into your CI/CD pipeline.',
      icon: '/lightning-icon.svg'
    },
    { 
      id: 'actionable-insights', 
      name: 'Actionable Insights', 
      description: 'Transform complex security data into clear, prioritized recommendations with our intuitive dashboards and detailed reports.',
      icon: '/magnify-icon.svg'
    }
  ];
}

/**
 * Get all users (admin only)
 * @returns {Promise<Array>} - List of users
 */
export async function getUsers() {
  try {
    const response = await apiRequest('/admin/users');
    if (Array.isArray(response)) {
      return response;
    }
    if (response && Array.isArray(response.data)) {
      return response.data;
    }
    throw new Error('Unexpected response format');
  } catch (error) {
    console.error('Error fetching users:', error);
    throw error;
  }
}

/**
 * Delete a user (admin only)
 * @param {string|number} userId - ID of the user to delete
 * @returns {Promise<Object>} - Response data
 */
export async function deleteUser(userId) {
  try {
    return await apiRequest(`/admin/users/${userId}`, {
      method: 'DELETE',
    });
  } catch (error) {
    console.error(`Error deleting user ${userId}:`, error);
    throw error;
  }
}

/**
 * Get all analysis engines (admin only)
 * @returns {Promise<Array>} - List of analysis engines
 */
export async function getAnalysisEngines() {
  try {
    const response = await apiRequest('/admin/engines');
    if (Array.isArray(response)) {
      return response;
    }
    if (response && Array.isArray(response.data)) {
      return response.data;
    }
    throw new Error('Unexpected response format');
  } catch (error) {
    console.error('Error fetching analysis engines:', error);
    throw error;
  }
}

// Auth API methods
export const authApi = {
  login(credentials) {
    return apiRequest('/auth/login', { method: 'POST', body: JSON.stringify(credentials) });
  },
  register(userData) {
    return apiRequest('/auth/register', { method: 'POST', body: JSON.stringify(userData) });
  },
  getMe() {
    return apiRequest('/auth/me');
  },
  logout() {
    return apiRequest('/auth/logout', { method: 'POST' });
  },
  updateProfile(userData) {
    return apiRequest('/auth/update-profile', { method: 'PUT', body: JSON.stringify(userData) });
  }
};