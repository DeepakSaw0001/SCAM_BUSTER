/**
 * ScamBuster Frontend API Service
 */

export interface HealthResponse {
  status: string;
  service: string;
}

export interface ThreatIndicator {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
  evidence?: string;
}

export interface MLMetadata {
  model_name?: string;
  model_version?: string;
  prediction?: string;
  probability?: number;
  target_probability?: number;
  features_used?: number;
  details?: Record<string, any>;
}

export interface ScanResult {
  id: string;
  scan_type: 'url' | 'text' | 'email' | 'phone' | 'apk';
  target: string;
  timestamp: string;
  composite_risk_score: number;
  risk_level: 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS';
  summary: string;
  heuristic_score: number;
  indicators: ThreatIndicator[];
  recommendations: string[];
  ml_metadata?: MLMetadata;
  technical_details?: Record<string, any>;
}

export interface ScanHistoryItem {
  id: string;
  scan_type: string;
  target: string;
  timestamp: string;
  composite_risk_score: number;
  risk_level: string;
  summary: string;
}

const API_BASE = '/api/v1';

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...(options.headers || {}),
    },
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with HTTP status ${response.status}`);
  }

  return response.json();
}

export async function checkBackendHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export async function scanUrl(url: string): Promise<ScanResult> {
  return request<ScanResult>('/scan/url', {
    method: 'POST',
    body: JSON.stringify({ url }),
  });
}

export async function scanText(text: string, sender?: string): Promise<ScanResult> {
  return request<ScanResult>('/scan/text', {
    method: 'POST',
    body: JSON.stringify({ text, sender: sender || undefined }),
  });
}

export async function scanEmail(payload: {
  sender: string;
  subject: string;
  body: string;
  reply_to?: string;
  attachments?: string[];
}): Promise<ScanResult> {
  return request<ScanResult>('/scan/email', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function scanPhone(phoneNumber: string, context?: string): Promise<ScanResult> {
  return request<ScanResult>('/scan/phone', {
    method: 'POST',
    body: JSON.stringify({ phone_number: phoneNumber, context: context || undefined }),
  });
}

export async function scanApk(payload: {
  package_name: string;
  permissions: string[];
  app_name?: string;
}): Promise<ScanResult> {
  return request<ScanResult>('/scan/apk', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function getScanHistory(limit: number = 50): Promise<ScanHistoryItem[]> {
  return request<ScanHistoryItem[]>(`/scan/history?limit=${limit}`);
}

export async function getScanById(scanId: string): Promise<ScanResult> {
  return request<ScanResult>(`/scan/${scanId}`);
}
