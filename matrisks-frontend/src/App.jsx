import React, { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './contexts/AuthContext';
import Navbar from './components/Navbar';
import Contact from './components/Contact';
import PrivateRoute from './components/PrivateRoute';

// Lazy load components for better performance
const Hero = lazy(() => import('./components/Hero'));
const About = lazy(() => import('./components/About'));
const Features = lazy(() => import('./components/Features'));
const SignIn = lazy(() => import('./components/SignIn'));
const SignUp = lazy(() => import('./components/SignUp'));
const Dashboard = lazy(() => import('./components/Dashboard'));
const Profile = lazy(() => import('./components/Profile'));
const Analysis = lazy(() => import('./components/Analysis'));
const Admin = lazy(() => import('./components/Admin'));

// Loading placeholder
const LoadingPlaceholder = () => (
  <div style={{ 
    minHeight: '100vh', 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center',
    color: 'var(--accent-color)',
    fontSize: '1.5rem'
  }}>
    Loading...
  </div>
);

// HomePage component that combines all landing page sections
const HomePage = () => (
  <>
    <Hero />
    <About />
    <Features />
  </>
);

function App() {
  return (
    <AuthProvider>
      <div className="App">
        <Navbar />
        <main className="main-content">
          <Suspense fallback={<LoadingPlaceholder />}>
            <Routes>
              {/* Public routes */}
              <Route path="/" element={<HomePage />} />
              <Route path="/signin" element={<SignIn />} />
              <Route path="/signup" element={<SignUp />} />
              
              {/* Protected routes */}
              <Route element={<PrivateRoute />}>
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/profile" element={<Profile />} />
                <Route path="/analysis" element={<Analysis />} />
                <Route path="/admin" element={<Admin />} />
              </Route>

              {/* Catch all other routes */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </main>
        <Contact />
      </div>
    </AuthProvider>
  );
}

export default App;