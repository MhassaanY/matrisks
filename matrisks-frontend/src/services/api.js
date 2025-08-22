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
  return true; // default to true so non-auth features still work via mock
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

// Mock user storage for development
const USERS_STORAGE_KEY = 'matrisks_mock_users';

// Initialize mock user database if it doesn't exist
const initMockStorage = () => {
  if (!localStorage.getItem(USERS_STORAGE_KEY)) {
    // Create default admin user
    const defaultAdmin = {
      id: 1,
      username: 'admin',
      email: 'admin@example.com',
      password_hash: 'mock_hash_admin123',
      first_name: 'Admin',
      last_name: 'User',
      is_admin: true,
      is_superuser: true,
      is_active: true,
      created_at: new Date().toISOString()
    };
    
    localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify([defaultAdmin]));
    console.log('Created default admin user');
  }
};

// Call init on script load
initMockStorage();

/**
 * Get mock response for development
 * @param {string} endpoint - API endpoint
 * @param {Object} options - Request options
 * @returns {Object} - Mock response
 */
function getMockResponse(endpoint, options) {
  // Initialize mock storage if needed
  initMockStorage();
  
  console.log('Using mock data for endpoint:', endpoint);
  
  return new Promise((resolve, reject) => {
    // Add a small delay to simulate network latency
    const delay = Math.random() * 300 + 200; // 200-500ms
    
    setTimeout(() => {
      // Handle authentication endpoints
      if (endpoint === '/auth/login') {
        const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || '[]');
        const credentials = JSON.parse(options.body || '{}');
        
        // Find user by email or username
        const user = users.find(u => 
          u.email === credentials.email || 
          u.username === credentials.email ||
          u.username === credentials.username_or_email ||
          u.email === credentials.username_or_email
        );
        
        if (!user || ('mock_hash_' + credentials.password) !== user.password_hash) {
          return reject({
            message: 'Invalid credentials',
            response: { status: 401, data: { detail: 'Invalid credentials' } }
          });
        }
        
        // Generate tokens
        const token = `mock_token_${user.id}_${Date.now()}`;
        const refreshToken = `mock_refresh_${user.id}_${Date.now()}`;
        
        // Return plain object like backend would
        return resolve({
          access_token: token,
          refresh_token: refreshToken,
          user: { ...user, password_hash: undefined }
        });
      }
      
      if (endpoint === '/auth/register') {
        const userData = JSON.parse(options.body || '{}');
        const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || '[]');
        
        // Check if username already exists
        if (users.some(user => user.username === userData.username)) {
          return reject({
            message: 'Username already registered',
            response: { status: 400, data: { detail: 'Username already registered' } }
          });
        }
        
        // Check if email already exists
        if (users.some(user => user.email === userData.email)) {
          return reject({
            message: 'Email already registered',
            response: { status: 400, data: { detail: 'Email already registered' } }
          });
        }
        
        // Create new user
        const newUser = {
          id: users.length + 1,
          is_admin: userData.email === 'admin@example.com',
          is_superuser: userData.email === 'admin@example.com',
          ...userData,
          password_hash: 'mock_hash_' + userData.password,
          is_active: true,
          created_at: new Date().toISOString()
        };
        
        // Remove password from stored user
        delete newUser.password;
        
        // Save to storage
        users.push(newUser);
        localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(users));
        
        // Return created user like backend would
        return resolve({ ...newUser, password_hash: undefined });
      }
      
      if (endpoint === '/auth/me') {
        const token = localStorage.getItem('access_token');
        if (!token) {
          return reject({
            message: 'Not authenticated',
            response: { status: 401, data: { detail: 'Not authenticated' } }
          });
        }
        
        // Extract user ID from token
        const match = token.match(/mock_token_(\d+)_/); 
        if (!match) return reject({ 
          message: 'Invalid token',
          response: { status: 401, data: { detail: 'Invalid token' } }
        });
        
        const userId = parseInt(match[1]);
        const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || '[]');
        const user = users.find(u => u.id === userId);
        
        if (!user) {
          return reject({
            message: 'User not found',
            response: { status: 404, data: { detail: 'User not found' } }
          });
        }
        
        return resolve({ ...user, password_hash: undefined });
      }
      
      if (endpoint === '/auth/logout') {
        return resolve({ message: 'Logged out successfully' });
      }
      
      let response;
      
      if (endpoint.includes('analysis-types')) {
        response = [
          { id: 'basic', name: 'Basic Analysis', description: 'Quick security scan' },
          { id: 'extended', name: 'Extended Analysis', description: 'Thorough security assessment' },
          { id: 'static', name: 'Advanced Static', description: 'Deep code analysis' },
          { id: 'dynamic', name: 'Dynamic Analysis', description: 'Runtime behavior analysis' }
        ];
      } else if (endpoint.includes('analyze') && options.method === 'POST') {
        response = {
          status: 'success',
          message: 'File submitted for analysis',
          id: `analysis-${Date.now()}`,
        };
      } else if (endpoint.includes('result')) {
        response = {
          id: endpoint.split('/').pop(),
          status: 'completed',
          result: {
            riskScore: Math.floor(Math.random() * 100),
            findings: [
              { level: 'warning', message: 'Potential security vulnerability detected' },
              { level: 'info', message: 'Code quality issues found' }
            ]
          }
        };
      } else if (endpoint.includes('analysis/history')) {
        // Generate fresh mock data each time to simulate new analyses
        response = generateMockHistory();
      } else if (endpoint.includes('admin/users')) {
        // Check if it's a DELETE request for a specific user
        if (options.method === 'DELETE') {
          // Get the user ID from the endpoint URL
          const userId = parseInt(endpoint.split('/').pop());
          
          // Get current users from storage
          const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || '[]');
          
          // Filter out the user to delete
          const updatedUsers = users.filter(user => user.id !== userId);
          
          // Save updated users list
          localStorage.setItem(USERS_STORAGE_KEY, JSON.stringify(updatedUsers));
          
          response = { success: true, message: 'User deleted successfully' };
        } else {
          // Return real users from local storage
          const users = JSON.parse(localStorage.getItem(USERS_STORAGE_KEY) || '[]');
          
          // Map users to remove sensitive information like password_hash
          response = users.map(user => ({
            id: user.id,
            username: user.username,
            email: user.email,
            first_name: user.first_name || '',
            last_name: user.last_name || '',
            is_admin: user.is_admin || false,
            is_superuser: user.is_superuser || false,
            created_at: user.created_at || new Date().toISOString()
          }));
        }
      } else if (endpoint.includes('admin/engines')) {
        // Return mock analysis engines
        response = [
          {
            id: 1,
            name: 'Static Analysis Engine',
            description: 'Performs static code analysis on APK files',
            status: 'active',
            version: '2.1.0',
            last_updated: '2025-04-15T08:30:00Z'
          },
          {
            id: 2,
            name: 'Dynamic Analysis Engine',
            description: 'Executes APK in sandbox environment for runtime analysis',
            status: 'active',
            version: '1.8.5',
            last_updated: '2025-05-10T14:20:00Z'
          },
          {
            id: 3,
            name: 'Malware Detection Engine',
            description: 'Identifies known malware patterns and signatures',
            status: 'maintenance',
            version: '3.0.2',
            last_updated: '2025-05-22T09:45:00Z'
          },
          {
            id: 4,
            name: 'Privacy Analysis Engine',
            description: 'Detects privacy issues and data leakage risks',
            status: 'active',
            version: '1.5.0',
            last_updated: '2025-03-30T11:15:00Z'
          },
          {
            id: 5,
            name: 'Network Traffic Analyzer',
            description: 'Analyzes network traffic patterns for suspicious activity',
            status: 'inactive',
            version: '0.9.8',
            last_updated: '2025-02-18T16:40:00Z'
          }
        ];
      } else {
        response = { error: 'Unknown endpoint' };
      }
      
      resolve(response);
    }, delay);
  });
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