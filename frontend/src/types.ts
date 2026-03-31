/* ========================================================================
   ReconBolt — TypeScript Types
   ======================================================================== */

// --- Scan Configuration ---

export interface ScanConfig {
  target: string;
  intensity: 'low' | 'normal' | 'aggressive';
  enable_subdomain_enum: boolean;
  enable_port_scan: boolean;
  enable_vuln_scan: boolean;
  enable_osint: boolean;
  enable_takeover_check: boolean;
  enable_ai_analysis: boolean;
  enable_bruteforce: boolean;
  wordlist_path?: string;
  top_ports: number;
}

// --- Scan Status ---

export type ScanStatusType = 'pending' | 'running' | 'analyzing' | 'completed' | 'failed' | 'cancelled';
export type RiskLevel = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

// --- Findings ---

export interface SubdomainFinding {
  subdomain: string;
  ip_address: string | null;
  host: string;
  source: string;
}

export interface PortFinding {
  host: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string;
  product: string;
  version: string;
  extra_info: string;
  source: string;
}

export interface VulnerabilityFinding {
  host: string;
  vuln_type: string;
  severity: Severity;
  title: string;
  description: string;
  url?: string;
  parameter?: string;
  evidence?: string;
  remediation?: string;
  source: string;
}

export interface HeaderFinding {
  host: string;
  header_name: string;
  present: boolean;
  value?: string;
  description: string;
  recommendation: string;
  source: string;
}

export interface CORSFinding {
  host: string;
  tested_origin: string;
  reflected_origin: string | null;
  credentials_allowed: boolean;
  severity: Severity;
  source: string;
}

export interface OSINTFinding {
  host: string;
  intel_source: string;
  category: string;
  data: Record<string, unknown>;
  summary: string;
  source: string;
}

export interface TakeoverFinding {
  host: string;
  subdomain: string;
  service: string;
  confidence: 'low' | 'medium' | 'high';
  source: string;
}

// --- Scan Summary ---

export interface ScanSummary {
  total_subdomains: number;
  total_open_ports: number;
  total_vulnerabilities: number;
  total_takeovers: number;
  risk_score: number;
  risk_level: RiskLevel;
}

// --- Scan Result ---

export interface ScanResult {
  scan_id: string;
  target: string;
  config: ScanConfig;
  status: ScanStatusType;
  started_at: string;
  completed_at: string | null;
  duration_seconds: number | null;
  subdomains: SubdomainFinding[];
  ports: PortFinding[];
  vulnerabilities: VulnerabilityFinding[];
  headers: HeaderFinding[];
  cors_findings: CORSFinding[];
  osint: OSINTFinding[];
  takeovers: TakeoverFinding[];
  ai_summary: string | null;
  summary: ScanSummary;
  errors: string[];
}

// --- Scan List Item ---

export interface ScanListItem {
  scan_id: string;
  target: string;
  status: ScanStatusType;
  started_at: string;
  risk_score: number;
  risk_level: RiskLevel;
}

// --- WebSocket Events ---

export interface ScanEvent {
  phase: string;
  level: 'debug' | 'info' | 'success' | 'warning' | 'error' | 'command';
  message: string;
  progress: number;
  timestamp: string;
  data?: Record<string, unknown>;
  result?: ScanResult;
}

// --- App View State ---

export type ViewType = 'home' | 'scan' | 'running' | 'results' | 'history';
