import { useState, useCallback } from 'react';
import type { ViewType, ScanResult, ScanConfig } from './types';
import Navbar from './components/Navbar';
import Dashboard from './components/Dashboard';
import ScanForm from './components/ScanForm';
import ScanProgress from './components/ScanProgress';
import ScanResults from './components/ScanResults';
import ScanHistory from './components/ScanHistory';
import './App.css';

function App() {
  const [view, setView] = useState<ViewType>('home');
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [scanConfig, setScanConfig] = useState<ScanConfig | null>(null);

  const handleStartScan = useCallback((config: ScanConfig) => {
    setScanConfig(config);
    setView('running');
  }, []);

  const handleScanComplete = useCallback((result: ScanResult) => {
    setCurrentResult(result);
    setView('results');
  }, []);

  const handleViewResult = useCallback((result: ScanResult) => {
    setCurrentResult(result);
    setView('results');
  }, []);

  const renderView = () => {
    switch (view) {
      case 'home':
        return <Dashboard onNewScan={() => setView('scan')} onViewHistory={() => setView('history')} />;
      case 'scan':
        return <ScanForm onStartScan={handleStartScan} onBack={() => setView('home')} />;
      case 'running':
        return scanConfig ? (
          <ScanProgress config={scanConfig} onComplete={handleScanComplete} onBack={() => setView('home')} />
        ) : null;
      case 'results':
        return currentResult ? (
          <ScanResults result={currentResult} onBack={() => setView('home')} onNewScan={() => setView('scan')} />
        ) : null;
      case 'history':
        return <ScanHistory onViewResult={handleViewResult} onBack={() => setView('home')} />;
      default:
        return <Dashboard onNewScan={() => setView('scan')} onViewHistory={() => setView('history')} />;
    }
  };

  return (
    <>
      <Navbar currentView={view} onNavigate={setView} />
      <main style={{ flex: 1, paddingTop: '72px' }}>
        {renderView()}
      </main>
    </>
  );
}

export default App;
