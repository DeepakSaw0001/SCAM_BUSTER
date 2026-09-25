import { useState, useEffect, useCallback } from 'react';
import { checkBackendHealth, HealthResponse } from '../services/api';

export type ConnectionStatus = 'loading' | 'connected' | 'unavailable';

export function useBackendHealth(pollIntervalMs: number = 10000) {
  const [status, setStatus] = useState<ConnectionStatus>('loading');
  const [data, setData] = useState<HealthResponse | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      const result = await checkBackendHealth();
      if (result && result.status === 'ok') {
        setStatus('connected');
        setData(result);
      } else {
        setStatus('unavailable');
      }
    } catch {
      // Do not expose internal backend errors to users
      setStatus('unavailable');
      setData(null);
    }
  }, []);

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, pollIntervalMs);
    return () => clearInterval(interval);
  }, [fetchHealth, pollIntervalMs]);

  return { status, data, refresh: fetchHealth };
}
