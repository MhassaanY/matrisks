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
      </div>
    </div>
  );
};

export default SignIn; 