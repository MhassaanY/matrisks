import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './SignUp.module.css';

const SignUp = () => {
  const { register, error: contextError } = useAuth();
  const navigate = useNavigate();
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
      const result = await register(formData);
      if (result?.success) {
        navigate('/signin');
        return;
      }
      // If not success, surface error
      setApiError(result?.error || 'Registration failed. Please try again.');
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
        <div className={styles.infoContent}>
          <div className={styles.heroImageWrapper}>
            <img 
              src="/hero-image.png" 
              alt="Matrisks Security" 
              className={styles.heroImage}
              loading="eager"
            />
          </div>
          <div className={styles.infoText}>
            <h3 className={styles.infoTitle}>Matrisks – Your Security Companion</h3>
            <p className={styles.infoDescription}>
              Take control of your application security with our revolutionary framework. 
              Matrisks empowers developers to proactively identify, analyze, and neutralize 
              threats before they become vulnerabilities.
            </p>
            <div className={styles.features}>
              <div className={styles.feature}>
                <svg className={styles.featureIcon} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span>Advanced Threat Detection</span>
              </div>
              <div className={styles.feature}>
                <svg className={styles.featureIcon} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <span>Real-time Analysis</span>
              </div>
              <div className={styles.feature}>
                <svg className={styles.featureIcon} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
                <span>Comprehensive Reports</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SignUp; 