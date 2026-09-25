/**
 * ScamBuster Frontend API Service
 */

export interface HealthResponse {
  status: string;
  service: string;
}

const API_BASE = '/api/v1';

export async function checkBackendHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE}/health`, {
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`HTTP error ${response.status}`);
  }

  return response.json();
}
