import React from 'react';
import styles from './Contact.module.css';

export default function Contact() {
  return (
    <footer className={styles.footer} id="contact">
      <div className={styles.footerContainer}>
        <div className={styles.contactSection}>
          <h2 className={styles.contactHeading}>Get in Touch</h2>
          <p className={styles.contactSubtext}>Have questions about Matrisks? We're here to help.</p>
          
          <div className={styles.socialLinks}>
            <a href="https://facebook.com" className={styles.socialLink} target="_blank" rel="noopener noreferrer" aria-label="Facebook">
              <div className={styles.socialIcon}>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="24" height="24">
                  <path d="M22 12c0-5.52-4.48-10-10-10S2 6.48 2 12c0 4.84 3.44 8.87 8 9.8V15H8v-3h2V9.5C10 7.57 11.57 6 13.5 6H16v3h-2c-.55 0-1 .45-1 1v2h3v3h-3v6.95c5.05-.5 9-4.76 9-9.95z" />
                </svg>
              </div>
            </a>
            
            <a href="https://linkedin.com" className={styles.socialLink} target="_blank" rel="noopener noreferrer" aria-label="LinkedIn">
              <div className={styles.socialIcon}>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="24" height="24">
                  <path d="M19 3a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h14m-.5 15.5v-5.3a3.26 3.26 0 0 0-3.26-3.26c-.85 0-1.84.52-2.32 1.3v-1.11h-2.79v8.37h2.79v-4.93c0-.77.62-1.4 1.39-1.4a1.4 1.4 0 0 1 1.4 1.4v4.93h2.79M6.88 8.56a1.68 1.68 0 0 0 1.68-1.68c0-.93-.75-1.69-1.68-1.69a1.69 1.69 0 0 0-1.69 1.69c0 .93.76 1.68 1.69 1.68m1.39 9.94v-8.37H5.5v8.37h2.77z" />
                </svg>
              </div>
            </a>
            
            <a href="mailto:contact@matrisks.com" className={styles.socialLink} aria-label="Email">
              <div className={styles.socialIcon}>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="24" height="24">
                  <path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z" />
                </svg>
              </div>
            </a>
          </div>
        </div>
        
        <div className={styles.questionsSection}>
          <h3 className={styles.questionsHeading}>Have Questions?</h3>
          <p className={styles.questionsText}>Reach out to us for any queries about our services.</p>
        </div>
        
        <div className={styles.copyright}>
          <p>Matrisks All Rights Reserved</p>
        </div>
      </div>
    </footer>
  );
} 