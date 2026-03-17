import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  ShieldAlert,
  Activity,
  TrendingUp,
  LayoutDashboard,
  ShieldCheck,
  History,
  Settings,
  Cpu
} from 'lucide-react';
import CyberRiskOrb from '../components/CyberRiskOrb';
import { IncidentFeed } from '../components/IncidentFeed';
import { securityService } from '../services/securityService';
import { ChatInterface, UploadBox, ShapChart } from '../components/CyberDashboard';
import { Threat } from '../types/security';
import { useFirebaseIncidents } from '../hooks/useFirebaseIncidents';

// Sectional dashboard components
import ThreatAnalysis from '../components/dashboard/ThreatAnalysis';
import IncidentsView from '../components/dashboard/IncidentsView';
import SettingsView from '../components/dashboard/SettingsView';
import ScanToolsView from '../components/dashboard/ScanToolsView';

const Dashboard: React.FC = () => {
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [threats, setThreats] = useState<Threat[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const { incidents } = useFirebaseIncidents();
  const currentRiskScore = threats.length > 0 ? threats[0].riskScore : 24;




  const handleUpload = async (file: File) => {
    setIsAnalyzing(true);
    try {
      const newThreat = await securityService.analyzeFile(file);
      setThreats(prev => [newThreat, ...prev]);
    } catch (error) {
      console.error("Analysis failed:", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const navItems = [
    { icon: LayoutDashboard, label: 'Dashboard' },
    { icon: ShieldCheck, label: 'Scan Tools' },
    { icon: ShieldAlert, label: 'Threat Analysis' },
    { icon: History, label: 'Incidents' },
    { icon: Settings, label: 'Settings' },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'Scan Tools':
        return <ScanToolsView />;
      case 'Threat Analysis':
        return <ThreatAnalysis />;
      case 'Incidents':
        return <IncidentsView />;
      case 'Settings':
        return <SettingsView />;
      case 'Dashboard':
      default:
        return (
          <div className="flex-1 overflow-hidden grid grid-cols-12">
            {/* MIDDLE: CHAT & UPLOAD */}
            <div className="col-span-8 flex flex-col border-r border-white/5">
              <div className="flex-1 overflow-hidden">
                <ChatInterface threats={threats} isAnalyzing={isAnalyzing} />
              </div>
              <div className="p-8 border-t border-white/5 bg-black/20">
                <UploadBox onUpload={handleUpload} />
              </div>
            </div>

            {/* RIGHT PANEL: ORB & SHAP & FEED */}
            <div className="col-span-4 flex flex-col overflow-y-auto custom-scrollbar p-6 space-y-6">
              
              {/* Risk Orb — Canvas 2D */}
              <div className="relative aspect-square rounded-[32px] border border-white/10 bg-black/60 overflow-hidden shadow-2xl">
                <div className="absolute top-4 left-4 z-10">
                  <h3 className="text-[10px] font-black text-cyan-400 uppercase tracking-[0.3em] flex items-center gap-2">
                    <Activity className="h-4 w-4" />
                    Risk Monitor
                  </h3>
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <CyberRiskOrb riskScore={currentRiskScore} className="w-full h-full" />
                </div>
              </div>

              {/* SHAP Chart */}
              <AnimatePresence mode="wait">
                {threats.length > 0 ? (
                  <motion.div
                    key="shap"
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                  >
                    <ShapChart data={threats[0].shapData || []} />
                  </motion.div>
                ) : (
                  <div className="p-8 rounded-2xl border border-dashed border-white/10 text-center">
                    <Cpu className="h-8 w-8 text-zinc-700 mx-auto mb-4" />
                    <p className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest">Awaiting Analysis Data</p>
                  </div>
                )}
              </AnimatePresence>

              {/* Live Incidents Feed */}
              <div className="flex-1 flex flex-col rounded-[32px] border border-white/5 bg-white/5 backdrop-blur-xl overflow-hidden min-h-[400px]">
                <div className="p-6 border-b border-white/5 flex items-center justify-between bg-white/5">
                  <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em]">Heuristic Stream</h3>
                  <TrendingUp className="h-4 w-4 text-cyan-400" />
                </div>
                <div className="flex-1 overflow-hidden">
                  <IncidentFeed incidents={incidents} />
                </div>
              </div>

            </div>
          </div>
        );
    }
  };

  return (
    <div className="flex h-screen w-full bg-black/20 backdrop-blur-3xl overflow-hidden">
      
      {/* LEFT SIDEBAR */}
      <aside className="w-64 border-r border-white/5 flex flex-col bg-black/40 backdrop-blur-xl">
        <div 
          onClick={() => window.location.href = '/'} 
          className="p-6 flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity"
        >
          <div className="h-10 w-10 flex items-center justify-center rounded-xl bg-cyan-500/20 shadow-[0_0_20px_rgba(6,182,212,0.3)] border border-cyan-500/20">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
          </div>
          <span className="text-xl font-black tracking-tighter text-white">
            Cyber<span className="text-cyan-400">Shield</span>
          </span>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2">
          {navItems.map((item, i) => (
            <button
              key={i}
              onClick={() => setActiveTab(item.label)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold uppercase tracking-widest transition-all duration-300 group ${
                activeTab === item.label
                  ? 'bg-cyan-500/10 text-cyan-400 shadow-[inset_0_0_20px_rgba(6,182,212,0.1)] border border-cyan-500/20' 
                  : 'text-zinc-500 hover:text-white hover:bg-white/5'
              }`}
            >
              <item.icon className={`h-5 w-5 ${activeTab === item.label ? 'text-cyan-400' : 'group-hover:text-cyan-400'}`} />
              {item.label}
            </button>
          ))}
        </nav>

        <div className="p-6 mt-auto">
          <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-white/10 backdrop-blur-xl">
            <div className="text-[10px] font-black text-white uppercase tracking-widest mb-2">Alpha Node V4.2</div>
            <div className="h-1.5 w-full bg-white/5 rounded-full overflow-hidden">
              <motion.div animate={{ width: ['20%', '80%', '40%'] }} transition={{ duration: 5, repeat: Infinity }} className="h-full bg-cyan-400" />
            </div>
            <div className="mt-2 text-[8px] font-bold text-zinc-500 uppercase tracking-tighter">System Integrity: 98.2%</div>
          </div>
        </div>
      </aside>

      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col min-w-0">
        
        {/* TOP HEADER */}
        <header className="h-20 border-b border-white/5 flex items-center justify-between px-8 bg-black/20">
          <div className="flex items-center gap-4">
            <h2 className="text-xs font-black text-white uppercase tracking-[0.4em]">Node Cluster: Alpha-1</h2>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <div className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_10px_rgba(16,185,129,0.8)]" />
              <span className="text-[10px] font-black text-emerald-400 uppercase tracking-widest">Live Monitoring</span>
            </div>
          </div>
        </header>

        {/* MAIN INTERFACE AREA */}
        <div className="flex-1 overflow-hidden">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeTab}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              className="h-full"
            >
              {renderContent()}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;