import { useState } from 'react';
import type { ScanConfig } from '../types';
import './ScanForm.css';

interface ScanFormProps {
  onStartScan: (config: ScanConfig) => void;
  onBack: () => void;
}

const defaultConfig: ScanConfig = {
  target: '',
  intensity: 'normal',
  enable_subdomain_enum: true,
  enable_port_scan: true,
  enable_vuln_scan: true,
  enable_osint: true,
  enable_takeover_check: true,
  enable_ai_analysis: true,
  enable_bruteforce: false,
  top_ports: 100,
};

export default function ScanForm({ onStartScan, onBack }: ScanFormProps) {
  const [config, setConfig] = useState<ScanConfig>(defaultConfig);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const target = config.target.trim();
    if (!target) {
      setError('Please enter a target domain or IP address');
      return;
    }
    // Basic validation
    if (target.includes(' ') || !(target.includes('.') || target.match(/^\d+\.\d+\.\d+\.\d+$/))) {
      setError('Enter a valid domain (e.g., example.com) or IP address');
      return;
    }
    setError('');
    onStartScan({ ...config, target });
  };

  const toggleModule = (key: keyof ScanConfig) => {
    setConfig(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const modules = [
    { key: 'enable_subdomain_enum' as const, icon: '🌐', title: 'Subdomain Discovery', desc: 'crt.sh, VirusTotal, OTX, URLScan' },
    { key: 'enable_port_scan' as const, icon: '🔓', title: 'Port Scanning', desc: 'Nmap service detection' },
    { key: 'enable_vuln_scan' as const, icon: '🛡️', title: 'Vulnerability Scan', desc: 'Headers, CORS, SQLi, Nikto' },
    { key: 'enable_osint' as const, icon: '🕵️', title: 'OSINT / Intel', desc: 'Shodan, VirusTotal reputation' },
    { key: 'enable_takeover_check' as const, icon: '⚠️', title: 'Takeover Check', desc: 'Subdomain takeover detection' },
    { key: 'enable_ai_analysis' as const, icon: '🤖', title: 'AI Analysis', desc: 'Gemini / OpenAI security briefing' },
  ];

  return (
    <div className="scan-form-page container animate-in">
      <button className="btn btn-secondary btn-sm" onClick={onBack} style={{ marginBottom: 24 }}>
        ← Back to Dashboard
      </button>

      <div className="scan-form-header">
        <h1>⚡ Configure Scan</h1>
        <p>Set your target and choose which reconnaissance modules to run.</p>
      </div>

      <form onSubmit={handleSubmit} className="scan-form">
        {/* Target Input */}
        <div className="form-section glass-card">
          <h2 className="form-section-title">🎯 Target</h2>
          <div className="form-group">
            <label className="form-label">Domain or IP Address</label>
            <input
              className={`input input-lg ${error ? 'input-error' : ''}`}
              type="text"
              placeholder="example.com"
              value={config.target}
              onChange={e => { setConfig(prev => ({ ...prev, target: e.target.value })); setError(''); }}
              autoFocus
            />
            {error && <div className="form-error">{error}</div>}
          </div>

          <div className="form-row">
            <div className="form-group">
              <label className="form-label">Scan Intensity</label>
              <select
                className="input"
                value={config.intensity}
                onChange={e => setConfig(prev => ({ ...prev, intensity: e.target.value as ScanConfig['intensity'] }))}
              >
                <option value="low">🟢 Low — Stealthy, slower</option>
                <option value="normal">🟡 Normal — Balanced</option>
                <option value="aggressive">🔴 Aggressive — Fast, noisy</option>
              </select>
            </div>
            <div className="form-group">
              <label className="form-label">Top Ports</label>
              <input
                className="input"
                type="number"
                min={1}
                max={65535}
                value={config.top_ports}
                onChange={e => setConfig(prev => ({ ...prev, top_ports: Number(e.target.value) }))}
              />
            </div>
          </div>
        </div>

        {/* Module Toggles */}
        <div className="form-section glass-card">
          <h2 className="form-section-title">🔧 Modules</h2>
          <div className="modules-grid">
            {modules.map(m => (
              <button
                key={m.key}
                type="button"
                className={`module-toggle ${config[m.key] ? 'active' : ''}`}
                onClick={() => toggleModule(m.key)}
              >
                <span className="module-icon">{m.icon}</span>
                <div className="module-info">
                  <span className="module-title">{m.title}</span>
                  <span className="module-desc">{m.desc}</span>
                </div>
                <span className={`module-check ${config[m.key] ? 'checked' : ''}`}>
                  {config[m.key] ? '✓' : ''}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Advanced Options */}
        <div className="form-section glass-card">
          <h2 className="form-section-title">⚙️ Advanced</h2>
          <label className="toggle-row">
            <input
              type="checkbox"
              checked={config.enable_bruteforce}
              onChange={() => toggleModule('enable_bruteforce')}
            />
            <span className="toggle-text">
              <strong>DNS Brute-Force</strong>
              <span className="toggle-desc">Try ~100 common subdomain prefixes</span>
            </span>
          </label>
        </div>

        {/* Submit */}
        <button type="submit" className="btn btn-primary btn-lg submit-btn">
          🚀 Launch Scan
        </button>
      </form>
    </div>
  );
}
