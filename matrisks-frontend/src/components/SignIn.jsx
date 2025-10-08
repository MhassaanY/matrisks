import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import styles from './SignIn.module.css';

const SignIn = () => {
  const { login, error, isAdmin } = useAuth();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username_or_email: '',
    password: '',
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Basic validation
    if (!formData.username_or_email || !formData.password) {
      setFormError('Please fill in all fields');
      return;
    }
    
    setIsSubmitting(true);
    setFormError('');
    
    try {
      // Call login function from AuthContext with appropriate credentials
      // We need to transform the formData to match what the auth API expects
      const result = await login(formData.username_or_email, formData.password);
      
      console.log('Login result:', result);
      
      if (!result || !result.success) {
        throw new Error((result && result.error) || 'Login failed');
      }
      
      // Get user information from the result
      const userInfo = result.data?.user;
      console.log('User info:', userInfo);
      
      // Redirect based on user role
      if (userInfo?.is_admin || userInfo?.is_superuser) {
        navigate('/admin');
      } else {
        navigate('/dashboard');
      }
    } catch (err) {
      console.error('Login error:', err);
      setFormError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={styles.signInContainer}>
      <div className={styles.formWrapper}>
        <h2>Sign In</h2>
        
        {(formError || error) && (
          <div className={styles.errorMessage}>
            {formError || error}
          </div>
        )}
        
        <form onSubmit={handleSubmit} className={styles.signInForm}>
          <div className={styles.formGroup}>
            <input
              type="text"
              id="username_or_email"
              name="username_or_email"
              value={formData.username_or_email}
              onChange={handleChange}
              placeholder="Username or Email"
              required
              disabled={isSubmitting}
            />
          </div>
          
          <div className={styles.formGroup}>
            <input
              type="password"
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Password"
              required
              disabled={isSubmitting}
            />
          </div>
          
          <div className={styles.forgotPassword}>
            <a href="#">Forgot password?</a>
          </div>
          
          <button 
            type="submit" 
            className={styles.signInButton}
            disabled={isSubmitting}
          >
            {isSubmitting ? 'Signing In...' : 'Sign In'}
          </button>
        </form>
        
        <div className={styles.signUpLink}>
          Don't have an account? <Link to="/signup">Sign Up</Link>
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

export default SignIn; 