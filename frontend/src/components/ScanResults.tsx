import { useState } from 'react';
import type { ScanResult } from '../types';
import './ScanResults.css';

interface ScanResultsProps {
  result: ScanResult;
  onBack: () => void;
  onNewScan: () => void;
}

type TabType = 'overview' | 'subdomains' | 'ports' | 'vulns' | 'headers' | 'osint' | 'ai';

export default function ScanResults({ result, onBack, onNewScan }: ScanResultsProps) {
  const [tab, setTab] = useState<TabType>('overview');
  const s = result.summary;

  const riskColors: Record<string, string> = {
    info: 'var(--blue)', low: 'var(--green)', medium: 'var(--yellow)',
    high: 'var(--red)', critical: 'var(--red-critical)',
  };
  const riskColor = riskColors[s.risk_level] || 'var(--text-muted)';

  const tabs: { key: TabType; label: string; count?: number }[] = [
    { key: 'overview', label: '📊 Overview' },
    { key: 'subdomains', label: '🌐 Subdomains', count: result.subdomains.length },
    { key: 'ports', label: '🔓 Ports', count: result.ports.length },
    { key: 'vulns', label: '🛡️ Vulnerabilities', count: result.vulnerabilities.length + result.cors_findings.length },
    { key: 'headers', label: '📋 Headers', count: result.headers.length },
    { key: 'osint', label: '🕵️ Intel', count: result.osint.length },
    { key: 'ai', label: '🤖 AI Analysis' },
  ];

  return (
    <div className="results-page container animate-in">
      <div className="results-topbar">
        <button className="btn btn-secondary btn-sm" onClick={onBack}>← Dashboard</button>
        <button className="btn btn-primary btn-sm" onClick={onNewScan}>+ New Scan</button>
      </div>

      {/* Header */}
      <div className="results-header">
        <div className="results-header-info">
          <h1>Results: <span style={{ color: 'var(--cyan)' }}>{result.target}</span></h1>
          <p className="results-meta">
            Scan ID: <code>{result.scan_id}</code> •
            Duration: {result.duration_seconds}s •
            {result.started_at && new Date(result.started_at).toLocaleString()}
          </p>
        </div>
        <div className="risk-gauge" style={{ borderColor: riskColor, color: riskColor }}>
          <div className="risk-score">{s.risk_score}</div>
          <div className="risk-label">{s.risk_level.toUpperCase()}</div>
        </div>
      </div>

      {/* Stat cards */}
      <div className="result-stats">
        <div className="result-stat glass-card">
          <div className="result-stat-val">{s.total_subdomains}</div>
          <div className="result-stat-lbl">Subdomains</div>
        </div>
        <div className="result-stat glass-card">
          <div className="result-stat-val">{s.total_open_ports}</div>
          <div className="result-stat-lbl">Open Ports</div>
        </div>
        <div className="result-stat glass-card">
          <div className="result-stat-val">{s.total_vulnerabilities}</div>
          <div className="result-stat-lbl">Vulnerabilities</div>
        </div>
        <div className="result-stat glass-card">
          <div className="result-stat-val">{s.total_takeovers}</div>
          <div className="result-stat-lbl">Takeovers</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="results-tabs">
        {tabs.map(t => (
          <button
            key={t.key}
            className={`result-tab ${tab === t.key ? 'active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
            {t.count !== undefined && t.count > 0 && <span className="tab-count">{t.count}</span>}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="results-content glass-card animate-in" key={tab}>
        {tab === 'overview' && <OverviewTab result={result} />}
        {tab === 'subdomains' && <SubdomainsTab result={result} />}
        {tab === 'ports' && <PortsTab result={result} />}
        {tab === 'vulns' && <VulnsTab result={result} />}
        {tab === 'headers' && <HeadersTab result={result} />}
        {tab === 'osint' && <OSINTTab result={result} />}
        {tab === 'ai' && <AITab result={result} />}
      </div>

      {/* Errors */}
      {result.errors.length > 0 && (
        <div className="results-errors glass-card">
          <h3>⚠️ Errors Encountered</h3>
          <ul>
            {result.errors.map((err, i) => <li key={i}>{err}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}

// --- Sub-components for each tab ---

function OverviewTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Scan Overview</h3>
      <div className="overview-grid">
        <div className="overview-item">
          <span className="ov-lbl">Target</span>
          <span className="ov-val">{result.target}</span>
        </div>
        <div className="overview-item">
          <span className="ov-lbl">Status</span>
          <span className={`badge badge-${result.status === 'completed' ? 'low' : 'high'}`}>{result.status}</span>
        </div>
        <div className="overview-item">
          <span className="ov-lbl">Duration</span>
          <span className="ov-val">{result.duration_seconds}s</span>
        </div>
        <div className="overview-item">
          <span className="ov-lbl">Scan ID</span>
          <span className="ov-val mono">{result.scan_id}</span>
        </div>
      </div>
      {result.takeovers.length > 0 && (
        <>
          <h3 style={{ marginTop: 24 }}>⚠️ Subdomain Takeover Risks</h3>
          <table className="data-table">
            <thead><tr><th>Subdomain</th><th>Service</th><th>Confidence</th></tr></thead>
            <tbody>
              {result.takeovers.map((t, i) => (
                <tr key={i}>
                  <td style={{ color: 'var(--red)' }}>{t.subdomain}</td>
                  <td>{t.service}</td>
                  <td><span className={`badge badge-${t.confidence === 'high' ? 'high' : 'medium'}`}>{t.confidence}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  );
}

function SubdomainsTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Discovered Subdomains ({result.subdomains.length})</h3>
      {result.subdomains.length === 0 ? (
        <p className="empty-state">No subdomains discovered or module was skipped.</p>
      ) : (
        <table className="data-table">
          <thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead>
          <tbody>
            {result.subdomains.map((s, i) => (
              <tr key={i}>
                <td style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{s.subdomain}</td>
                <td className="mono">{s.ip_address || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function PortsTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Open Ports ({result.ports.length})</h3>
      {result.ports.length === 0 ? (
        <p className="empty-state">No open ports found or module was skipped.</p>
      ) : (
        <table className="data-table">
          <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
          <tbody>
            {result.ports.map((p, i) => (
              <tr key={i}>
                <td>{p.host}</td>
                <td><strong>{p.port}</strong>/{p.protocol}</td>
                <td>{p.service_name || '—'}</td>
                <td>{p.product || '—'}</td>
                <td className="mono">{p.version || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function VulnsTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Vulnerabilities</h3>
      {result.vulnerabilities.length > 0 && (
        <table className="data-table" style={{ marginBottom: 24 }}>
          <thead><tr><th>Host</th><th>Type</th><th>Severity</th><th>Title</th></tr></thead>
          <tbody>
            {result.vulnerabilities.map((v, i) => (
              <tr key={i}>
                <td>{v.host}</td>
                <td className="mono">{v.vuln_type}</td>
                <td><span className={`badge badge-${v.severity}`}>{v.severity}</span></td>
                <td>{v.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {result.cors_findings.length > 0 && (
        <>
          <h3>CORS Misconfigurations</h3>
          <table className="data-table">
            <thead><tr><th>Host</th><th>Tested Origin</th><th>Credentials</th><th>Severity</th></tr></thead>
            <tbody>
              {result.cors_findings.map((c, i) => (
                <tr key={i}>
                  <td>{c.host}</td>
                  <td className="mono">{c.tested_origin}</td>
                  <td>{c.credentials_allowed ? '✅ Yes' : 'No'}</td>
                  <td><span className={`badge badge-${c.severity}`}>{c.severity}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {result.vulnerabilities.length === 0 && result.cors_findings.length === 0 && (
        <p className="empty-state">No vulnerabilities found or module was skipped.</p>
      )}
    </div>
  );
}

function HeadersTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Security Headers</h3>
      {result.headers.length === 0 ? (
        <p className="empty-state">No header data available.</p>
      ) : (
        <table className="data-table">
          <thead><tr><th>Header</th><th>Status</th><th>Host</th><th>Recommendation</th></tr></thead>
          <tbody>
            {result.headers.map((h, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 600 }}>{h.header_name}</td>
                <td>
                  <span className={`badge ${h.present ? 'badge-low' : 'badge-high'}`}>
                    {h.present ? '✓ Present' : '✗ Missing'}
                  </span>
                </td>
                <td>{h.host}</td>
                <td style={{ fontSize: '0.82rem' }}>{h.recommendation || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function OSINTTab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>Threat Intelligence</h3>
      {result.osint.length === 0 ? (
        <p className="empty-state">No OSINT data available. Configure API keys for Shodan/VirusTotal.</p>
      ) : (
        <div className="osint-list">
          {result.osint.map((o, i) => (
            <div key={i} className="osint-card">
              <div className="osint-source">
                <span className="badge badge-info">{o.intel_source}</span>
                <span className="osint-category">{o.category}</span>
              </div>
              <p className="osint-summary">{o.summary}</p>
              {o.data && Object.keys(o.data).length > 0 && (
                <details className="osint-details">
                  <summary>View Raw Data</summary>
                  <pre>{JSON.stringify(o.data, null, 2)}</pre>
                </details>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AITab({ result }: { result: ScanResult }) {
  return (
    <div className="tab-content">
      <h3>🤖 AI Security Analysis</h3>
      {result.ai_summary ? (
        <div className="ai-content">
          {result.ai_summary.split('\n').map((line, i) => {
            if (line.startsWith('# ')) return <h2 key={i}>{line.slice(2)}</h2>;
            if (line.startsWith('## ')) return <h3 key={i}>{line.slice(3)}</h3>;
            if (line.startsWith('### ')) return <h4 key={i}>{line.slice(4)}</h4>;
            if (line.startsWith('- ') || line.startsWith('* ')) return <li key={i}>{line.slice(2)}</li>;
            if (line.startsWith('**') && line.endsWith('**')) return <p key={i}><strong>{line.slice(2, -2)}</strong></p>;
            if (line.trim() === '') return <br key={i} />;
            return <p key={i}>{line}</p>;
          })}
        </div>
      ) : (
        <p className="empty-state">
          AI analysis not available. Configure a Gemini or OpenAI API key and enable the AI module.
        </p>
      )}
    </div>
  );
}
