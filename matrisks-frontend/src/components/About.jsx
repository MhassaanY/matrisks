import { useEffect, useState, memo } from 'react';
import styles from './About.module.css';

// Memoize the About component to prevent unnecessary re-renders
const About = memo(function About() {
  const [visible, setVisible] = useState(false);
  
  useEffect(() => {
    // Use Intersection Observer to detect when the element enters viewport
    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        setVisible(true);
        observer.disconnect(); // Once visible, no need to observe anymore
      }
    }, { threshold: 0.1 }); // Trigger when at least 10% of the element is visible
    
    const element = document.getElementById('about');
    if (element) {
      observer.observe(element);
    }
    
    return () => {
      if (element) {
        observer.unobserve(element);
      }
      observer.disconnect();
    };
  }, []);

  return (
    <section className={styles.aboutSection} id="about">
      <div className={styles.aboutBackground}></div>
      
      <div className={`${styles.aboutContent} ${visible ? styles.visible : ''}`}>
        <div className={styles.aboutHeader}>
          <div className={styles.aboutHeaderContent}>
            <h3 className={styles.aboutLabel}>OUR MISSION</h3>
            <h2 className={styles.aboutTitle}>Enhancing Android Security Through Innovation</h2>
          </div>
        </div>
        
        <div className={styles.aboutBody}>
          <div className={styles.aboutMission}>
            <p className={styles.aboutDescription}>
              Our mission is to enhance Android application security by delivering a robust 
              framework that enables security professionals, developers, and both technical and 
              non-technical users to proactively identify, analyze, and address security 
              vulnerabilities effectively.
            </p>
          </div>
          
          <div className={styles.aboutColumns}>
            <div className={styles.aboutColumn}>
              <h3 className={styles.columnTitle}>Our Approach</h3>
              <p>
              We integrate advanced machine learning with proven security analysis techniques
              to deliver a comprehensive protection framework. Our solution continuously adapts 
              to emerging threats, safeguarding Android applications throughout every stage of development.
              </p>
            </div>
            
            <div className={styles.aboutColumn}>
              <h3 className={styles.columnTitle}>Who We Serve</h3>
              <h4 className={styles.userTypeTitle}>Technical Users</h4>
              <p className={styles.userDescription}>
              Security engineers, Android developers, and penetration testers can leverage our platform's 
              deep code inspection, behavioral analysis. Access detailed technical reports, 
              permission audits, API misuse detection, and decompiled code views to expedite vulnerability
              remediation with precision.
              </p>
              
              <h4 className={styles.userTypeTitle}>Non-Technical Users</h4>
              <p className={styles.userDescription}>
              Product managers and business stakeholders benefit from a user-friendly dashboard that delivers 
              high-level risk, visual summaries, and intuitive insights no security expertise required. 
              Understand your application's security posture at a glance and make well-informed product or 
              compliance decisions.
              </p>
            </div>
            
            <div className={styles.aboutColumn}>
              <h3 className={styles.columnTitle}>Key Features</h3>
              <ul className={styles.aboutList}>
                <li>Automated vulnerability detection with detailed explanations</li>
                <li>Real-time alerts for emerging security threats</li>
                <li>Comprehensive reporting with both technical and business views</li>
                <li>Seamless integration with your existing development workflow</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
});

export default About; 