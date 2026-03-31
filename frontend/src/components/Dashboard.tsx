import { useState, useEffect } from 'react';
import type { ScanListItem } from '../types';
import { listScans } from '../services/api';
import './Dashboard.css';

interface DashboardProps {
  onNewScan: () => void;
  onViewHistory: () => void;
}

export default function Dashboard({ onNewScan, onViewHistory }: DashboardProps) {
  const [recentScans, setRecentScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadScans();
  }, []);

  async function loadScans() {
    try {
      const scans = await listScans();
      setRecentScans(scans.slice(0, 5));
    } catch {
      // API not running yet, that's ok
    } finally {
      setLoading(false);
    }
  }

  const totalScans = recentScans.length;
  const criticalScans = recentScans.filter(s => s.risk_level === 'critical' || s.risk_level === 'high').length;

  return (
    <div className="dashboard container animate-in">
      {/* Hero Section */}
      <section className="hero">
        <div className="hero-content">
          <h1 className="hero-title">
            <span className="hero-icon">⚡</span>
            ReconBolt
          </h1>
          <p className="hero-subtitle">
            AI-Powered Cybersecurity Reconnaissance Platform
          </p>
          <p className="hero-desc">
            Automated attack surface discovery, network enumeration, vulnerability assessment,
            and AI-driven security analysis — all in one platform.
          </p>
          <div className="hero-actions">
            <button className="btn btn-primary btn-lg" onClick={onNewScan}>
              🔍 Launch New Scan
            </button>
            <button className="btn btn-secondary btn-lg" onClick={onViewHistory}>
              📋 View History
            </button>
          </div>
        </div>
        <div className="hero-visual">
          <div className="hero-ring ring-1"></div>
          <div className="hero-ring ring-2"></div>
          <div className="hero-ring ring-3"></div>
          <div className="hero-center">
            <span>⚡</span>
          </div>
        </div>
      </section>

      {/* Stats Cards */}
      <section className="stats-section">
        <div className="stat-card glass-card">
          <div className="stat-icon">🔎</div>
          <div className="stat-value">{totalScans}</div>
          <div className="stat-label">Total Scans</div>
        </div>
        <div className="stat-card glass-card">
          <div className="stat-icon">⚠️</div>
          <div className="stat-value">{criticalScans}</div>
          <div className="stat-label">High Risk</div>
        </div>
        <div className="stat-card glass-card">
          <div className="stat-icon">🤖</div>
          <div className="stat-value">AI</div>
          <div className="stat-label">Analysis Ready</div>
        </div>
        <div className="stat-card glass-card">
          <div className="stat-icon">📊</div>
          <div className="stat-value">6</div>
          <div className="stat-label">Scan Modules</div>
        </div>
      </section>

      {/* Features */}
      <section className="features-section">
        <h2 className="section-title">Reconnaissance Modules</h2>
        <div className="features-grid">
          {[
            { icon: '🌐', title: 'Subdomain Discovery', desc: 'crt.sh, VirusTotal, OTX, URLScan, DNS brute-force' },
            { icon: '🔓', title: 'Port Scanning', desc: 'Concurrent nmap with service version detection' },
            { icon: '🛡️', title: 'Vulnerability Scanning', desc: 'Headers, CORS, SQL injection, Nikto web scanner' },
            { icon: '🕵️', title: 'Threat Intelligence', desc: 'Shodan host intel, VirusTotal domain reputation' },
            { icon: '⚠️', title: 'Takeover Detection', desc: 'Subdomain takeover vulnerability scanning via subzy' },
            { icon: '🤖', title: 'AI Analysis', desc: 'Gemini / OpenAI powered executive security briefings' },
          ].map((f, i) => (
            <div key={i} className="feature-card glass-card" style={{ animationDelay: `${i * 80}ms` }}>
              <div className="feature-icon">{f.icon}</div>
              <h3 className="feature-title">{f.title}</h3>
              <p className="feature-desc">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Recent Scans */}
      {!loading && recentScans.length > 0 && (
        <section className="recent-section">
          <h2 className="section-title">Recent Scans</h2>
          <div className="glass-card" style={{ overflow: 'hidden' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map(scan => (
                  <tr key={scan.scan_id}>
                    <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{scan.target}</td>
                    <td><span className={`badge badge-${scan.status === 'completed' ? 'low' : 'running'}`}>{scan.status}</span></td>
                    <td><span className={`badge badge-${scan.risk_level}`}>{scan.risk_level}</span></td>
                    <td>{new Date(scan.started_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
