import React, { createContext, useState, useEffect, useCallback } from 'react';
import { authApi } from '../services/api';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Check if user is logged in on initial load
  const checkAuth = useCallback(async () => {
    try {
      const token = localStorage.getItem('access_token');
      if (token) {
        const response = await authApi.getMe();
        setCurrentUser(response);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      // Only clear tokens if it's a 401 error (invalid token)
      if (error.message && error.message.includes('401')) {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  // Ensure loading is always set to false after a reasonable time
  useEffect(() => {
    const timer = setTimeout(() => {
      setLoading(false);
    }, 2000); // 2 second timeout

    return () => clearTimeout(timer);
  }, []);

  const login = async (username_or_email, password) => {
    try {
      console.log('Attempting login with:', { username_or_email, password });
      
      // Call the auth API with the correct parameter structure
      const response = await authApi.login({ 
        username_or_email,
        password 
      });
      
      console.log('Login response:', response);
      const { access_token, user } = response;
      
      localStorage.setItem('access_token', access_token);
      
      setCurrentUser(user);
      return { success: true, data: response };
    } catch (error) {
      console.error('Login failed:', error);
      return { 
        success: false, 
        error: error.message || error.response?.data?.detail || 'Login failed' 
      };
    }
  };

  const register = async (userData) => {
    try {
      const response = await authApi.register(userData);
      return { success: true, data: response };
    } catch (error) {
      console.error('Registration failed:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Registration failed' 
      };
    }
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch (error) {
      console.error('Logout failed:', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setCurrentUser(null);
    }
  };

  const updateProfile = async (userData) => {
    try {
      const response = await authApi.updateProfile(userData);
      // Update the current user with the new data
      setCurrentUser(prev => ({ ...prev, ...response.data }));
      return { success: true, data: response.data };
    } catch (error) {
      console.error('Profile update failed:', error);
      return { 
        success: false, 
        error: error.response?.data?.detail || 'Profile update failed' 
      };
    }
  };

  const value = {
    currentUser,
    isAuthenticated: !!currentUser,
    isAdmin: currentUser?.is_superuser || currentUser?.is_admin || false,
    loading,
    login,
    register,
    logout,
    updateProfile,
  };

  return (
    <AuthContext.Provider value={value}>
      {!loading && children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = React.useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};