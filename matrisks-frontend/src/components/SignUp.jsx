import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './SignUp.module.css';

const SignUp = () => {
  const { register, error: contextError } = useAuth();
  const [formData, setFormData] = useState({
    first_name: '',
    last_name: '',
    username: '',
    email: '',
    gender: 'Male',
    password: '',
    confirm_password: '',
  });
  const [formErrors, setFormErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [apiError, setApiError] = useState(null);

  // Reset API error when auth context error changes
  useEffect(() => {
    if (contextError) {
      setApiError(contextError);
    }
  }, [contextError]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });

    // Clear errors when field is edited
    if (formErrors[name]) {
      setFormErrors({
        ...formErrors,
        [name]: ''
      });
    }
    // Clear API error when any field changes
    if (apiError) {
      setApiError(null);
    }
  };

  const validateForm = () => {
    const errors = {};
    let isValid = true;

    // Required fields validation
    const requiredFields = ['username', 'email', 'password', 'confirm_password'];
    requiredFields.forEach(field => {
      if (!formData[field]?.trim()) {
        errors[field] = `${field.replace('_', ' ')} is required`;
        isValid = false;
      }
    });

    // Skip other validations if required fields are empty
    if (!isValid) {
      setFormErrors(errors);
      return false;
    }

    // Username validation - at least 3 characters, alphanumeric
    if (formData.username.length < 3) {
      errors.username = 'Username must be at least 3 characters';
      isValid = false;
    } else if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
      errors.username = 'Username can only contain letters, numbers, and underscores';
      isValid = false;
    }

    // Email validation with more comprehensive regex
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(formData.email)) {
      errors.email = 'Please enter a valid email address';
      isValid = false;
    }

    // Password validation - at least 8 characters with complexity
    if (formData.password.length < 8) {
      errors.password = 'Password must be at least 8 characters';
      isValid = false;
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      errors.password = 'Password must contain at least one uppercase letter, one lowercase letter, and one number';
      isValid = false;
    }

    // Confirm password validation
    if (formData.password !== formData.confirm_password) {
      errors.confirm_password = 'Passwords do not match';
      isValid = false;
    }

    setFormErrors(errors);
    return isValid;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Clear any previous API errors
    setApiError(null);
    
    // Validate form
    if (!validateForm()) {
      return;
    }
    
    setIsSubmitting(true);
    
    try {
      // Call register function from AuthContext
      await register(formData);
      // Redirect is handled in the register function
    } catch (err) {
      console.error('Registration error:', err);
      
      // Handle API validation errors
      if (err.response?.data?.detail) {
        if (typeof err.response.data.detail === 'string') {
          setApiError(err.response.data.detail);
        } else if (Array.isArray(err.response.data.detail)) {
          // Handle detailed validation errors from FastAPI
          const apiErrors = {};
          err.response.data.detail.forEach(error => {
            const field = error.loc[error.loc.length - 1];
            apiErrors[field] = error.msg;
          });
          setFormErrors(apiErrors);
        }
      } else if (err.message === 'Network Error') {
        setApiError('Cannot connect to server. Please check your internet connection or try again later.');
      } else {
        setApiError('Registration failed. Please try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={styles.signUpContainer}>
      <div className={styles.formWrapper}>
        <h2>Register</h2>
        
        {apiError && (
          <div className={styles.errorMessage}>
            {apiError}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className={styles.signUpForm}>
          <div className={styles.formGroup}>
            <label htmlFor="first_name">First Name</label>
            <input
              type="text"
              id="first_name"
              name="first_name"
              value={formData.first_name}
              onChange={handleChange}
              placeholder="Enter your first name"
              disabled={isSubmitting}
            />
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="last_name">Last Name</label>
            <input
              type="text"
              id="last_name"
              name="last_name"
              value={formData.last_name}
              onChange={handleChange}
              placeholder="Enter your last name"
              disabled={isSubmitting}
            />
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="Enter your username"
              required
              disabled={isSubmitting}
            />
            {formErrors.username && (
              <span className={styles.fieldError}>{formErrors.username}</span>
            )}
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="email">Email</label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              onChange={handleChange}
              placeholder="Enter your email"
              required
              disabled={isSubmitting}
            />
            {formErrors.email && (
              <span className={styles.fieldError}>{formErrors.email}</span>
            )}
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="gender">Gender</label>
            <select
              id="gender"
              name="gender"
              value={formData.gender}
              onChange={handleChange}
              required
              disabled={isSubmitting}
            >
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
            </select>
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Enter your password"
              required
              disabled={isSubmitting}
            />
            {formErrors.password && (
              <span className={styles.fieldError}>{formErrors.password}</span>
            )}
          </div>
          
          <div className={styles.formGroup}>
            <label htmlFor="confirm_password">Confirm Password</label>
            <input
              type="password"
              id="confirm_password"
              name="confirm_password"
              value={formData.confirm_password}
              onChange={handleChange}
              placeholder="Confirm your password"
              required
              disabled={isSubmitting}
            />
            {formErrors.confirm_password && (
              <span className={styles.fieldError}>{formErrors.confirm_password}</span>
            )}
          </div>
          
          <button 
            type="submit" 
            className={styles.signUpButton}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Registering...' : 'Sign Up'}
          </button>
        </form>
        
        <div className={styles.signInLink}>
          Already have an account? <Link to="/signin">Sign In</Link>
        </div>
      </div>
      
      <div className={styles.decorativePanel}>
        <div className={styles.overlay}></div>
      </div>
    </div>
  );
};

export default SignUp; 