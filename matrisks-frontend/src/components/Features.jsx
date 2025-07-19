import { useEffect, useState, memo, useRef } from 'react';

// Memoized FeatureCard component to improve rendering performance
const FeatureCard = memo(({ title, description, emoji, type, index, totalCards, isMobile }) => {
  const cardRef = useRef(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const originalTransform = useRef('');
  const originalLeft = useRef('');
  const originalRotation = useRef(0);
  
  // Calculate initial position for stacked effect
  useEffect(() => {
    const card = cardRef.current;
    if (!card || isMobile) return;
    
    // Initial positions for each card - wider spread for better access
    const positions = [
      { top: '0', left: '-25%', rotate: -2, zIndex: 4, shadow: '0 8px 30px rgba(0,0,0,0.12)' },
      { top: '30px', left: '20%', rotate: 1, zIndex: 1, shadow: '0 12px 35px rgba(0,0,0,0.15)' },
      { top: '15px', left: '45%', rotate: -1, zIndex: 2, shadow: '0 16px 40px rgba(0,0,0,0.18)' },
      { top: '40px', left: '70%', rotate: 2, zIndex: 3, shadow: '0 20px 45px rgba(0,0,0,0.2)' }
    ];
    
    // Get position for this card
    const pos = positions[index % positions.length];
    
    // Apply initial styles
    card.style.top = pos.top;
    card.style.left = pos.left;
    originalLeft.current = pos.left;
    originalRotation.current = pos.rotate;
    
    // Set base rotation
    let transform = `rotate(${pos.rotate}deg)`;
    
    // Add explicit translations for wider separation based on your current setup
    if (index === 3) transform += ' translateX(-500px)';
    if (index === 0) transform += ' translateX(-300px)';
    if (index === 2) transform += ' translateX(20px)'; 
    if (index === 1) transform += ' translateX(200px)';
    
    // Store this transform for later
    originalTransform.current = transform;
    
    card.style.transform = transform;
    card.style.zIndex = pos.zIndex;
    card.style.boxShadow = pos.shadow;
    card.style.width = '360px';
    card.style.position = 'absolute';
    card.style.transformOrigin = 'center bottom';
    
    // Remove the red border
    card.style.border = '';
    
    // Add an additional margin adjustment to better center the cards
    if (index === positions.length - 1) {
      card.style.marginLeft = '-100px'; // Adjust rightmost card to be fully visible
    }
    
  }, [index, isMobile]);
  
  // Handle mouse enter for expansion effect
  const handleMouseEnter = () => {
    if (isMobile) return;
    setIsExpanded(true);
    
    const card = cardRef.current;
    if (!card) return;
    
    // Extract the translateX from the original transform
    const translateMatch = originalTransform.current.match(/translateX\([^)]+\)/);
    const translateX = translateMatch ? translateMatch[0] : '';
    
    // Make card larger, straight, and bring to front while keeping X position
    card.style.zIndex = 1000;
    card.style.width = '450px'; // Make wider to fit more text
    card.style.boxShadow = '0 30px 60px rgba(0, 0, 0, 0.4), 0 15px 30px rgba(255, 87, 34, 0.3)';
    card.style.filter = 'drop-shadow(0 20px 40px rgba(255,87,34,0.15))';
    
    // Make card straight (0 rotation) but keep translateX
    card.style.transform = `rotate(0deg) scale(1.25) ${translateX}`;
    
    // Add more height if needed to fit description
    card.style.minHeight = '280px'; 
  };
  
  // Handle mouse leave to return to stacked position
  const handleMouseLeave = () => {
    if (isMobile) return;
    setIsExpanded(false);
    
    const card = cardRef.current;
    if (!card) return;
    
    // Calculate initial position for this card to restore it
    const positions = [
      { top: '0', left: '-25%', rotate: -2, zIndex: 4, shadow: '0 8px 30px rgba(0,0,0,0.12)' },
      { top: '30px', left: '20%', rotate: 1, zIndex: 1, shadow: '0 12px 35px rgba(0,0,0,0.15)' },
      { top: '15px', left: '45%', rotate: -1, zIndex: 2, shadow: '0 16px 40px rgba(0,0,0,0.18)' },
      { top: '40px', left: '70%', rotate: 2, zIndex: 3, shadow: '0 20px 45px rgba(0,0,0,0.2)' }
    ];
    
    // Get position for this card
    const pos = positions[index % positions.length];
    
    // Reset to original transform - don't recalculate it
    card.style.transform = originalTransform.current;
    card.style.zIndex = pos.zIndex;
    card.style.boxShadow = pos.shadow;
    card.style.filter = 'none';
    card.style.width = '360px';
    card.style.minHeight = '';
    
    // Don't change left position or margin
  };

  return (
    <div 
      className={`feature-card ${type}`}
      ref={cardRef}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      style={{
        // Set transition here to ensure consistent animation
        transition: 'all 0.4s cubic-bezier(0.18, 0.89, 0.32, 1.28)'
      }}
    >
      <div className="feature-card-content">
        <div className="feature-emoji-container">
          <div className={`feature-emoji ${type}-emoji`}>
            <span role="img" aria-label={title} className="feature-emoji-icon">
              {emoji}
            </span>
          </div>
        </div>
        <div className="feature-content">
          <h3 className="feature-card-title">{title}</h3>
          <p className={`feature-card-description ${isExpanded ? 'expanded' : ''}`}>
            {description}
          </p>
        </div>
      </div>
    </div>
  );
});

// Memoize the Features component to prevent unnecessary re-renders
const Features = memo(function Features() {
  const [visible, setVisible] = useState(false);
  const [isMobile, setIsMobile] = useState(false);
  
  useEffect(() => {
    // Check if the screen is mobile size
    const checkMobile = () => {
      setIsMobile(window.innerWidth <= 768);
    };
    
    // Initial check
    checkMobile();
    
    // Add resize listener
    window.addEventListener('resize', checkMobile);
    
    // Use Intersection Observer to detect when the element enters viewport
    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        setVisible(true);
        observer.disconnect(); // Once visible, no need to observe anymore
      }
    }, { threshold: 0.1 }); // Trigger when at least 10% of the element is visible
    
    const element = document.getElementById('features');
    if (element) {
      observer.observe(element);
    }
    
    return () => {
      if (element) {
        observer.unobserve(element);
      }
      observer.disconnect();
      window.removeEventListener('resize', checkMobile);
    };
  }, []);

  // Feature data array to avoid repetitive code
  const featureData = [
    {
      type: "basic",
      title: "Basic Analysis",
      description: "Quickly scans APK files via API for basic analysis, categorizes findings as \"malicious\" or \"harmless,\" and generates graphs, reports, and summaries based on detection results.",
      emoji: "🔍"
    },
    {
      type: "extended",
      title: "Malware Detection",
      description: "Leveraging machine learning and threat intelligence, Utilize pre-trained machine learning models to analyze APK characteristics and classify potential malware.",
      emoji: "🛡️"
    },
    {
      type: "advanced",
      title: "Advanced Static",
      description: "Performs in-depth APK analysis using JADX to decompile Android applications. Uncovers hidden logic, analyzes codebase, and identifies vulnerabilities for enhanced security.",
      emoji: "🔬"
    },
    {
      type: "dynamic",
      title: "Dynamic Analysis",
      description: "Provides real-time behavior analysis that detects threats before they become problems, keeping your applications secure under all conditions.",
      emoji: "⚡"
    }
  ];

  return (
    <section className="features-section" id="features">
      <div className="features-background"></div>
      
      <div className={`features-content ${visible ? 'visible' : ''}`}>
        <div className="features-header">
          <h2 className="features-title">Features</h2>
          <p className="features-subtitle">
            {isMobile ? 'Explore our analysis types' : 'Hover over each card to learn more about our analysis types'}
          </p>
        </div>
        
        <div className="features-stack-container">
          <div className="features-stack">
            {featureData.map((feature, index) => (
              <FeatureCard
                key={index}
                type={feature.type}
                title={feature.title}
                description={feature.description}
                emoji={feature.emoji}
                index={index}
                totalCards={featureData.length}
                isMobile={isMobile}
              />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
});

export default Features;