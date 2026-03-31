import type { ViewType } from '../types';
import './Navbar.css';

interface NavbarProps {
  currentView: ViewType;
  onNavigate: (view: ViewType) => void;
}

export default function Navbar({ currentView, onNavigate }: NavbarProps) {
  return (
    <nav className="navbar">
      <div className="navbar-inner container">
        <button className="navbar-brand" onClick={() => onNavigate('home')}>
          <span className="brand-icon">⚡</span>
          <span className="brand-text">ReconBolt</span>
          <span className="brand-badge">v1.0</span>
        </button>

        <div className="navbar-links">
          <button
            className={`nav-link ${currentView === 'home' ? 'active' : ''}`}
            onClick={() => onNavigate('home')}
          >
            Dashboard
          </button>
          <button
            className={`nav-link ${currentView === 'scan' ? 'active' : ''}`}
            onClick={() => onNavigate('scan')}
          >
            New Scan
          </button>
          <button
            className={`nav-link ${currentView === 'history' ? 'active' : ''}`}
            onClick={() => onNavigate('history')}
          >
            History
          </button>
        </div>

        <div className="navbar-status">
          <span className="status-dot"></span>
          <span className="status-text">System Online</span>
        </div>
      </div>
    </nav>
  );
}
