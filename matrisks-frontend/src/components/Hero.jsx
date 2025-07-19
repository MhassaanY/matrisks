import { useState, useEffect, memo } from 'react';

// Memoize the Hero component to prevent unnecessary re-renders
const Hero = memo(function Hero() {
    const [text, setText] = useState('');
    const [isDeleting, setIsDeleting] = useState(false);
    const [loopNum, setLoopNum] = useState(0);
    const [typingSpeed, setTypingSpeed] = useState(150);
    
    const phrases = ['Security', 'Protection', 'Defense'];
    
    useEffect(() => {
        let timer;
        const handleTyping = () => {
            const currentPhraseIndex = loopNum % phrases.length;
            const fullText = phrases[currentPhraseIndex];
            
            setText(prevText => 
                isDeleting
                ? fullText.substring(0, prevText.length - 1)
                : fullText.substring(0, prevText.length + 1)
            );
            
            if (!isDeleting && text === fullText) {
                // After typing full word, pause before deleting
                timer = setTimeout(() => setIsDeleting(true), 1500);
                setTypingSpeed(100);
            } else if (isDeleting && text === '') {
                // After deleting, move to next word
                setIsDeleting(false);
                setLoopNum(prevLoopNum => prevLoopNum + 1);
                setTypingSpeed(150);
            } else {
                // Schedule next typing step
                timer = setTimeout(handleTyping, typingSpeed);
            }
        };
        
        timer = setTimeout(() => {
            handleTyping();
        }, typingSpeed);
        
        return () => clearTimeout(timer);
    }, [text, isDeleting, loopNum, typingSpeed, phrases]);
    
    return (
      <section className="hero-section" id="home">
        <div className="hero-content">
          <div className="hero-text">
            <h1 className="hero-title">
              Matrisks – Your<br />
              <span className="hero-typewriter" style={{ color: '#FF5722' }}>{text}</span><br />
              Companion
            </h1>
            <p className="hero-description">
              Take control of your application security with our revolutionary framework. 
              Matrisks empowers developers to proactively identify, analyze, and neutralize 
              threats before they become vulnerabilities. Experience peace of mind with our 
              cutting-edge protection that evolves alongside emerging security challenges.
            </p>
          </div>
          <div className="hero-image">
            <img 
              src="/hero-image.png" 
              alt="Security Innovation" 
              className="security-image" 
              loading="eager" 
              width="700" 
              height="500"
            />
          </div>
        </div>
      </section>
    );
});

export default Hero;