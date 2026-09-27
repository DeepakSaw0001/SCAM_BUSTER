/**
 * ScamBuster Frontend API Service
 */

export interface HealthResponse {
  status: string;
  service: string;
}

export interface ThreatIndicator {
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  evidence?: string;
  rule_id?: string;
}

export interface MLMetadata {
  learning_type?: string;
  category?: string;
  algorithm?: string;
  features_used?: number | string[] | any;
  confidence?: number;
  is_deterministic?: boolean;

  model_name?: string;
  model_version?: string;
  prediction?: string;
  probability?: number;
  target_probability?: number;
  details?: Record<string, any>;
}

export interface RuleDetectionDetails {
  risk_score: number;
  indicators: ThreatIndicator[];
}

export interface MLDetectionDetails {
  prediction: string;
  model_score: number;
  model_version: string;
  model_probability?: number;
  features_used?: number;
  top_contributing_features?: Array<{
    feature: string;
    value?: number;
    weight?: number;
    global_importance?: number;
  }>;
}

export interface DetectionSources {
  rules: RuleDetectionDetails;
  ml?: MLDetectionDetails;
  embedded_urls?: Array<{
    url?: string;
    original_url?: string;
    normalized_url?: string;
    hostname?: string;
    displayed_text?: string;
    is_anchor_mismatch?: boolean;
    mismatch_details?: string;
    risk_score: number;
    risk_level: string;
    rule_indicators?: string[];
    indicators?: string[];
    ml_prediction?: string;
  }>;
  headers?: Record<string, any>;
  attachments?: Array<{
    filename: string;
    extension: string;
    mime_type: string;
    size_bytes: number;
    is_suspicious_extension: boolean;
    is_double_extension: boolean;
  }>;
  intelligence?: Record<string, any>;
  permissions?: Record<string, any>;
  certificate?: Record<string, any>;
  components?: Record<string, any>;
}

export interface ScanResult {
  id: string;
  scan_id?: string;
  scan_type: 'url' | 'text' | 'email' | 'phone' | 'apk' | string;
  input_type?: string;
  status?: string;
  target: string;
  timestamp: string;
  created_at?: string;
  composite_risk_score: number;
  risk_score?: number;
  score?: number;
  risk_level: string;
  category?: string[];
  confidence?: number;
  summary: string;
  heuristic_score?: number;
  indicators: ThreatIndicator[];
  detection?: DetectionSources;
  recommendation?: string;
  recommendations: string[];
  reasons?: string[];
  model_version?: string;
  normalized_url?: string;
  features?: Record<string, any>;
  ml_metadata?: MLMetadata;
  technical_details?: Record<string, any>;
  privacy_analysis?: Record<string, any>;
  web_analysis?: Record<string, any>;
  social_engineering?: {
    detected_categories?: string[];
    findings?: Array<{
      name: string;
      category: string;
      severity: string;
      why_it_matters: string;
      evidence?: string;
      rule_id?: string;
      safe_recommendations?: string[];
    }>;
    language?: string;
    language_confidence?: number;
    obfuscation_detected?: boolean;
    obfuscation_details?: string[];
    phone_analysis?: Array<Record<string, any>>;
    why_this_matters?: Array<{ category: string; explanation: string }>;
    safe_recommendations?: string[];
    sender_analysis?: Record<string, any>;
    anchor_mismatches?: Array<Record<string, any>>;
    attachments?: Array<Record<string, any>>;
  };
  threat_intelligence?: Record<string, any>;
  threat_graph?: {
    nodes: Array<{
      id: string;
      type: string;
      label: string;
      risk_level: string;
      details?: Record<string, any>;
    }>;
    edges: Array<{
      source: string;
      target: string;
      relation: string;
      relationship?: string;
    }>;
  };
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

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: string;
}

export interface ChatExtractedIndicator {
  type: string;
  value: string;
  risk_score?: number;
  risk_level?: string;
}

export interface ChatTriageResult {
  has_threat_detected: boolean;
  risk_level?: string;
  scam_category?: string;
  confidence?: number;
  emergency_actions?: string[];
  red_flags?: string[];
}

export interface ChatSuggestedAction {
  label: string;
  action_type: 'navigate' | 'scan';
  target: string;
}

export interface ChatResponse {
  reply: string;
  indicators: ChatExtractedIndicator[];
  triage?: ChatTriageResult;
  suggested_prompts: string[];
  suggested_actions: ChatSuggestedAction[];
}

export interface User {
  id: string;
  email: string;
  username?: string;
  full_name?: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface RegisterPayload {
  email: string;
  password: string;
  full_name?: string;
  username?: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

const AUTH_TOKEN_KEY = 'scambuster_auth_token';

export function getStoredAuthToken(): string | null {
  try {
    return localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setStoredAuthToken(token: string): void {
  try {
    localStorage.setItem(AUTH_TOKEN_KEY, token);
  } catch {}
}

export function clearStoredAuthToken(): void {
  try {
    localStorage.removeItem(AUTH_TOKEN_KEY);
  } catch {}
}

const API_BASE = import.meta.env.VITE_API_URL
  ? `${String(import.meta.env.VITE_API_URL).replace(/\/+$/, '')}/api/v1`
  : '/api/v1';

/**
 * Defensively normalize raw scan responses to ensure:
 * - Arrays (indicators, recommendations, category, reasons) are guaranteed to be real arrays.
 * - Score fields are numerical and fall back to each other.
 * - Text fields are strings with reasonable defaults.
 * - IDs are safe strings for slicing.
 */
export function normalizeScanResult(raw: any): ScanResult {
  const data = raw?.data?.data ?? raw?.data ?? raw ?? {};

  // Extract primary risk score safely
  const compositeScore = Number(data?.composite_risk_score ?? data?.risk_score ?? data?.score ?? 0);
  const riskScore = Number(data?.risk_score ?? data?.composite_risk_score ?? compositeScore);

  // Extract indicators safely
  const rawIndicators = data?.indicators || data?.threat_indicators || [];
  const indicators: ThreatIndicator[] = Array.isArray(rawIndicators)
    ? rawIndicators.map((ind: any) => ({
        name: String(ind?.name || 'Detected Signal'),
        severity: String(ind?.severity || 'LOW').toUpperCase() as any,
        description: String(ind?.description || ''),
        evidence: ind?.evidence !== undefined && ind?.evidence !== null ? String(ind.evidence) : undefined,
        rule_id: ind?.rule_id ? String(ind.rule_id) : undefined,
      }))
    : [];

  // Extract recommendations safely
  const rawRecs = data?.recommendations || (data?.recommendation ? [data.recommendation] : []);
  const recommendations: string[] = Array.isArray(rawRecs)
    ? rawRecs.map((r: any) => String(r))
    : [];

  // Extract categories safely
  const rawCategories = data?.category || data?.categories || [];
  const category: string[] = Array.isArray(rawCategories)
    ? rawCategories.map((c: any) => String(c))
    : typeof rawCategories === 'string'
    ? [rawCategories]
    : [];

  // Extract reasons safely
  const rawReasons = data?.reasons || [];
  const reasons: string[] = Array.isArray(rawReasons)
    ? rawReasons.map((r: any) => String(r))
    : [];

  const normalized: ScanResult = {
    id: String(data?.id || data?.scan_id || `scan_${Date.now()}`),
    scan_id: data?.scan_id ? String(data.scan_id) : undefined,
    scan_type: data?.scan_type || 'url',
    input_type: data?.input_type,
    status: data?.status || 'completed',
    target: String(data?.target || data?.url || data?.message || data?.phone_number || data?.package_name || 'Target'),
    timestamp: data?.timestamp || data?.created_at || new Date().toISOString(),
    created_at: data?.created_at,
    composite_risk_score: isNaN(compositeScore) ? 0 : compositeScore,
    risk_score: isNaN(riskScore) ? 0 : riskScore,
    risk_level: String(data?.risk_level || 'UNKNOWN').toUpperCase(),
    category,
    confidence: typeof data?.confidence === 'number' ? data.confidence : 0.85,
    summary: String(data?.summary || 'Analysis completed.'),
    heuristic_score: typeof data?.heuristic_score === 'number' ? data.heuristic_score : 0,
    indicators,
    detection: data?.detection || undefined,
    recommendation: data?.recommendation || recommendations[0] || 'Review analysis findings carefully.',
    recommendations,
    reasons,
    model_version: data?.model_version || 'v1.0',
    normalized_url: data?.normalized_url,
    features: data?.features && typeof data.features === 'object' ? data.features : {},
    ml_metadata: data?.ml_metadata,
    technical_details: data?.technical_details && typeof data.technical_details === 'object' ? data.technical_details : {},
    privacy_analysis: data?.privacy_analysis || null,
    web_analysis: data?.web_analysis || null,
    social_engineering: data?.social_engineering || null,
    threat_intelligence: data?.threat_intelligence || null,
    threat_graph: data?.threat_graph || null,
  };

  return normalized;
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredAuthToken();
  const authHeaders: Record<string, string> = token ? { 'Authorization': `Bearer ${token}` } : {};

  const headers: Record<string, string> = {
    'Accept': 'application/json',
    ...authHeaders,
    ...(options.headers as Record<string, string> || {}),
  };

  if (!(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Request failed with HTTP status ${response.status}`);
  }

  const rawJson = await response.json();
  console.log(`[Scan Debug] Raw API Response (${endpoint}):`, rawJson);
  const resultData = rawJson?.data?.data ?? rawJson?.data ?? rawJson ?? null;
  return resultData as T;
}

export async function checkBackendHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export async function scanUrl(url: string, deep_analysis: boolean = true): Promise<ScanResult> {
  const res = await request<any>('/scan/url', {
    method: 'POST',
    body: JSON.stringify({ url, deep_analysis }),
  });
  return normalizeScanResult(res);
}

export async function scanMessage(message: string, sender?: string): Promise<ScanResult> {
  const res = await request<any>('/scan/message', {
    method: 'POST',
    body: JSON.stringify({ message, sender: sender || undefined }),
  });
  return normalizeScanResult(res);
}

export async function scanText(text: string, sender?: string): Promise<ScanResult> {
  const res = await request<any>('/scan/text', {
    method: 'POST',
    body: JSON.stringify({ text, sender: sender || undefined }),
  });
  return normalizeScanResult(res);
}

export async function scanEmail(payload: {
  raw_email?: string;
  sender?: string;
  subject?: string;
  body?: string;
  reply_to?: string;
  attachments?: string[];
}): Promise<ScanResult> {
  const res = await request<any>('/scan/email', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return normalizeScanResult(res);
}

export async function uploadEmail(file: File): Promise<ScanResult> {
  const token = getStoredAuthToken();
  const headers: Record<string, string> = token ? { 'Authorization': `Bearer ${token}` } : {};
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE}/scan/email/upload`, {
    method: 'POST',
    headers,
    body: formData,
  });
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Upload failed with status ${response.status}`);
  }
  const rawJson = await response.json();
  console.log('[Scan Debug] Raw API Response (/scan/email/upload):', rawJson);
  return normalizeScanResult(rawJson);
}

export async function scanPhone(phoneNumber: string, country: string = 'IN', context?: string): Promise<ScanResult> {
  const res = await request<any>('/scan/phone', {
    method: 'POST',
    body: JSON.stringify({ phone_number: phoneNumber, country, context: context || undefined }),
  });
  return normalizeScanResult(res);
}

export async function scanApk(payload: {
  package_name: string;
  permissions: string[];
  app_name?: string;
  category?: string;
}): Promise<ScanResult> {
  const res = await request<any>('/scan/apk', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return normalizeScanResult(res);
}

export async function uploadApk(file: File, category?: string): Promise<ScanResult> {
  const token = getStoredAuthToken();
  const headers: Record<string, string> = token ? { 'Authorization': `Bearer ${token}` } : {};
  const formData = new FormData();
  formData.append('file', file);
  if (category) {
    formData.append('category', category);
  }
  const response = await fetch(`${API_BASE}/scan/apk/upload`, {
    method: 'POST',
    headers,
    body: formData,
  });
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `APK upload failed with status ${response.status}`);
  }
  const rawJson = await response.json();
  console.log('[Scan Debug] Raw API Response (/scan/apk/upload):', rawJson);
  return normalizeScanResult(rawJson);
}

export async function getScanHistory(limit: number = 50, user_only: boolean = false): Promise<ScanHistoryItem[]> {
  const query = user_only ? `?limit=${limit}&user_only=true` : `?limit=${limit}`;
  return request<ScanHistoryItem[]>(`/scan/history${query}`);
}

export async function deleteScanApi(scanId: string): Promise<void> {
  await request(`/scan/${scanId}`, { method: 'DELETE' });
}

export async function registerApi(payload: RegisterPayload): Promise<AuthResponse> {
  const res = await request<AuthResponse>('/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (res.access_token) {
    setStoredAuthToken(res.access_token);
  }
  return res;
}

export async function loginApi(payload: LoginPayload): Promise<AuthResponse> {
  const res = await request<AuthResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  if (res.access_token) {
    setStoredAuthToken(res.access_token);
  }
  return res;
}

export async function getMeApi(): Promise<User> {
  return request<User>('/auth/me');
}

export async function updateProfileApi(payload: { full_name?: string }): Promise<User> {
  return request<User>('/auth/profile', {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function changePasswordApi(payload: { current_password: string; new_password: string }): Promise<{ message: string }> {
  return request<{ message: string }>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function logoutApi(): Promise<void> {
  clearStoredAuthToken();
  try {
    await request('/auth/logout', { method: 'POST' });
  } catch {}
}

export async function getScanById(scanId: string): Promise<ScanResult> {
  const res = await request<any>(`/scan/${scanId}`);
  return normalizeScanResult(res);
}

export async function getThreatIntelligenceStatus(): Promise<Record<string, any>> {
  return request<Record<string, any>>('/scan/intelligence/status');
}

export async function lookupThreatIndicator(indicator: string, indicatorType?: string): Promise<Record<string, any>> {
  const params = new URLSearchParams({ indicator });
  if (indicatorType) {
    params.append('indicator_type', indicatorType);
  }
  return request<Record<string, any>>(`/scan/intelligence/lookup?${params.toString()}`);
}

export async function sendChatMessage(
  message: string,
  history: ChatMessage[] = [],
  context?: Record<string, any>
): Promise<ChatResponse> {
  return request<ChatResponse>('/chat', {
    method: 'POST',
    body: JSON.stringify({ message, history, context }),
  });
}

export async function getChatPrompts(): Promise<string[]> {
  return request<string[]>('/chat/prompts');
}


