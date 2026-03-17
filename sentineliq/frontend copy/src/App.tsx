import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { Navbar, Footer } from './components/Navigation';
import Background from './components/Background';
import Dashboard from './pages/Dashboard';
import Hero from './pages/Hero';
import ScanTools from './pages/ScanTools';
import ThreatAnalysis from './components/dashboard/ThreatAnalysis';
import Auth from './pages/Auth';

// Placeholder components for routes
const Incidents = () => (
  <div className="flex-1 flex items-center justify-center text-zinc-500 font-bold uppercase tracking-[0.3em]">
    Incident Repository // Coming Soon
  </div>
);

const Settings = () => (
  <div className="flex-1 flex items-center justify-center text-zinc-500 font-bold uppercase tracking-[0.3em]">
    System Configuration // Coming Soon
  </div>
);

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  return (
    <div className="relative flex h-screen w-full flex-col overflow-hidden text-white font-sans selection:bg-cyan-500/30">
      <Background />
      
      {/* Top Navigation Bar */}
      <Navbar />

      {/* Main Content Area */}
      <main className="relative flex flex-1 flex-col overflow-hidden min-h-0">
        {children}
      </main>

      {/* Status Footer */}
      <Footer />
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/auth" element={<Auth />} />
        
        {/* All other routes get the Layout with Navbar */}
        <Route path="*" element={
          <Layout>
            <Routes>
              <Route path="/" element={<Hero />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/scan-tools" element={<ScanTools />} />
              <Route path="/analysis" element={<ThreatAnalysis />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/settings" element={<Settings />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Layout>
        } />
      </Routes>
    </Router>
  );
};

export default App;