import axios from 'axios';

// Create axios instance with base URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

// Custom timeout - increase if needed
const REQUEST_TIMEOUT = 10000; // 10 seconds

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for cookies
  timeout: REQUEST_TIMEOUT,
});

// Request interceptor to add auth token to requests
client.interceptors.request.use(
  (config) => {
    // Get token from auth context or localStorage if needed
    const token = window.sessionStorage.getItem('accessToken');
    
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token refresh
let isRefreshing = false;
let failedQueue = [];

// Custom error handling helper
const handleApiError = (error) => {
  // Network errors
  if (!error.response) {
    return Promise.reject({
      ...error,
      message: 'Network error. Please check your connection.',
      isNetworkError: true
    });
  }
  
  // Server errors (500s)
  if (error.response.status >= 500) {
    return Promise.reject({
      ...error,
      message: 'Server error. Please try again later.',
      isServerError: true
    });
  }
  
  // Client errors (400s)
  if (error.response.status >= 400 && error.response.status < 500) {
    // If no detailed error message is available, provide a generic one
    if (!error.response.data?.detail) {
      error.response.data = {
        ...error.response.data,
        detail: error.response.status === 401 
          ? 'Authentication failed' 
          : 'Request failed. Please try again.'
      };
    }
  }
  
  return Promise.reject(error);
};

const processQueue = (error, token = null) => {
  failedQueue.forEach(prom => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  
  failedQueue = [];
};

client.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    // Handle request timeout
    if (error.code === 'ECONNABORTED') {
      return handleApiError({
        ...error,
        response: { status: 408 },
        message: 'Request timeout. Please try again.'
      });
    }
    
    const originalRequest = error.config;
    
    // If error is 401 Unauthorized and not already retrying
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // If already refreshing, queue this request
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(token => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            return client(originalRequest);
          })
          .catch(err => {
            return Promise.reject(err);
          });
      }
      
      originalRequest._retry = true;
      isRefreshing = true;
      
      try {
        // Try to refresh token
        const { data } = await client.post('/auth/refresh');
        const { access_token } = data;
        
        // Store new token
        window.sessionStorage.setItem('accessToken', access_token);
        
        // Update authorization header
        client.defaults.headers.common.Authorization = `Bearer ${access_token}`;
        originalRequest.headers.Authorization = `Bearer ${access_token}`;
        
        // Process queue with new token
        processQueue(null, access_token);
        
        // Retry original request
        return client(originalRequest);
      } catch (refreshError) {
        // Refresh failed, process queue with error
        processQueue(refreshError, null);
        
        // Redirect to login or handle based on your auth flow
        window.location.href = '/signin';
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    
    return handleApiError(error);
  }
);

// Export custom methods for convenience
const api = {
  ...client,
  // Method to check backend connectivity
  checkConnection: async () => {
    try {
      await client.get('/health', { timeout: 5000 });
      return true;
    } catch (error) {
      return false;
    }
  }
};

export default api;
