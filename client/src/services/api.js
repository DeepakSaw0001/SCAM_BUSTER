const API_BASE = '/api';

async function request(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const config = {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  };

  try {
    const response = await fetch(url, config);
    let data;
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      data = await response.json();
    } else {
      const text = await response.text();
      data = { error: { message: text || `Request failed with status ${response.status}` } };
    }

    if (!response.ok) {
      throw new Error(data.error?.message || `Request failed with status ${response.status}`);
    }

    return data;
  } catch (error) {
    if (error.name === 'TypeError' && (error.message.includes('fetch') || error.message.includes('NetworkError'))) {
      throw new Error('Unable to connect to the server. Please check if the backend is running.');
    }
    throw error;
  }
}

export const api = {
  healthCheck: () => request('/health'),

  submitAnalysis: (inputType, inputValue) =>
    request('/analysis/submit', {
      method: 'POST',
      body: JSON.stringify({ inputType, inputValue }),
    }),

  getHistory: (page = 1, limit = 20) =>
    request(`/analysis/history?page=${page}&limit=${limit}`),

  getAnalysis: (id) => request(`/analysis/${id}`),
};
