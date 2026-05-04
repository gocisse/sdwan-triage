// API client for communicating with the backend

import type {
  AnalysisJob,
  UploadResponse,
  HealthResponse,
  SystemStatus,
  HistoryResponse,
  AnalysisResults,
  APIError,
} from '../types';

// Base URL for API calls
const API_BASE = '/api';

// ── Auth token management ─────────────────────────────────────
const TOKEN_KEY = 'sdwan_token';

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setAuthToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAuthToken(): void {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem('sdwan_user');
}

// Custom event fired on 401 — AuthContext listens for this to trigger logout
export const AUTH_EXPIRED_EVENT = 'sdwan:auth-expired';

function fireAuthExpired() {
  window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
}

// ── Global error notification hook ───────────────────────────────
// Set by ToastProvider at mount time so fetchApi can push errors
// without importing React.
let _onApiError: ((err: { title: string; message?: string }) => void) | null = null;

export function setGlobalApiErrorHandler(
  handler: ((err: { title: string; message?: string }) => void) | null
) {
  _onApiError = handler;
}

function notifyError(title: string, message?: string) {
  _onApiError?.({ title, message });
}

// Custom error class for API errors
export class ApiError extends Error {
  status: number;
  details?: string;

  constructor(message: string, status: number, details?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

// Generic fetch wrapper with error handling
async function fetchApi<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  
  try {
    const token = getAuthToken();
    const authHeaders: Record<string, string> = token
      ? { Authorization: `Bearer ${token}` }
      : {};

    const response = await fetch(url, {
      ...options,
      headers: {
        'Accept': 'application/json',
        ...authHeaders,
        ...options.headers,
      },
    });

    // Global 401 interception — fire event so AuthContext can logout
    if (response.status === 401 && !endpoint.startsWith('/login')) {
      fireAuthExpired();
    }

    // Handle non-JSON responses
    const contentType = response.headers.get('content-type');
    if (!contentType?.includes('application/json')) {
      if (!response.ok) {
        throw new ApiError(
          'Server error',
          response.status,
          await response.text()
        );
      }
      return response as unknown as T;
    }

    const data = await response.json();

    if (!response.ok) {
      const error = data as APIError;
      throw new ApiError(
        error.error || 'Request failed',
        response.status,
        error.details
      );
    }

    return data as T;
  } catch (error) {
    if (error instanceof ApiError) {
      notifyError(error.message, error.details);
      throw error;
    }
    
    // Network error or other fetch error
    if (error instanceof TypeError) {
      const err = new ApiError(
        'Network error. Please check your connection.',
        0,
        error.message
      );
      notifyError(err.message, err.details);
      throw err;
    }
    
    const err = new ApiError(
      'An unexpected error occurred',
      0,
      String(error)
    );
    notifyError(err.message, err.details);
    throw err;
  }
}

// Health check
export async function checkHealth(): Promise<HealthResponse> {
  return fetchApi<HealthResponse>('/health');
}

// System status
export async function getSystemStatus(): Promise<SystemStatus> {
  return fetchApi<SystemStatus>('/status');
}

// Upload file with progress callback
export async function uploadFile(
  file: File,
  onProgress?: (progress: number) => void
): Promise<UploadResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    const formData = new FormData();
    formData.append('file', file);

    const uploadUrl = `${API_BASE}/upload`;
    console.log(`[Upload] Starting upload to ${uploadUrl}, file: ${file.name} (${file.size} bytes)`);

    xhr.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable && onProgress) {
        const progress = Math.round((event.loaded / event.total) * 100);
        onProgress(progress);
      }
    });

    xhr.addEventListener('load', () => {
      console.log(`[Upload] Response received: status=${xhr.status}, body length=${xhr.responseText.length}`);

      // Handle empty response (often caused by CORS blocking)
      if (!xhr.responseText || xhr.responseText.length === 0) {
        const msg = xhr.status === 0 || xhr.status === 403
          ? 'Request blocked by CORS policy. Check that the backend allows this origin.'
          : `Server returned empty response (HTTP ${xhr.status}). The backend may have crashed or timed out.`;
        console.error(`[Upload] Empty response body. Status: ${xhr.status}`);
        reject(new ApiError(msg, xhr.status));
        return;
      }

      try {
        const response = JSON.parse(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300) {
          console.log(`[Upload] Success: id=${response.id}`);
          resolve(response as UploadResponse);
        } else {
          console.error(`[Upload] Server error:`, response);
          reject(new ApiError(
            response.error || `Upload failed (HTTP ${xhr.status})`,
            xhr.status,
            response.details
          ));
        }
      } catch (parseErr) {
        console.error(`[Upload] Failed to parse response:`, xhr.responseText.substring(0, 200));
        reject(new ApiError(
          `Server returned invalid JSON (HTTP ${xhr.status}). Response: ${xhr.responseText.substring(0, 100)}`,
          xhr.status
        ));
      }
    });

    xhr.addEventListener('error', () => {
      console.error(`[Upload] Network error. Status: ${xhr.status}, readyState: ${xhr.readyState}`);
      reject(new ApiError(
        'Network error during upload. Check that the backend server is running on port 8080.',
        0,
        `readyState=${xhr.readyState}, status=${xhr.status}`
      ));
    });

    xhr.addEventListener('abort', () => {
      reject(new ApiError('Upload cancelled', 0));
    });

    xhr.addEventListener('timeout', () => {
      reject(new ApiError('Upload timed out. The file may be too large or the server is unresponsive.', 0));
    });

    xhr.open('POST', uploadUrl);
    xhr.timeout = 300000; // 5 minute timeout for large files

    // Attach JWT token to upload requests
    const token = getAuthToken();
    if (token) {
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    }

    xhr.send(formData);
  });
}

// Start analysis
export async function startAnalysis(id: string): Promise<{ id: string; status: string; message: string; ws_url: string }> {
  return fetchApi(`/analyze/${id}`, {
    method: 'POST',
  });
}

// Get analysis status
export async function getAnalysisStatus(id: string): Promise<AnalysisJob> {
  return fetchApi<AnalysisJob>(`/analyze/${id}/status`);
}

// Cancel analysis
export async function cancelAnalysis(id: string): Promise<{ id: string; status: string; message: string }> {
  return fetchApi(`/analyze/${id}/cancel`, {
    method: 'POST',
  });
}

// Get analysis results
export async function getResults(id: string): Promise<AnalysisResults> {
  return fetchApi<AnalysisResults>(`/results/${id}`);
}

// Authenticated file download — fetches with Bearer token, returns a blob download.
// Browsers cannot send Authorization headers via <a href> or window.open(), so we
// must fetch the file via JS and trigger the download programmatically.
export async function downloadFile(id: string, format: 'json' | 'html'): Promise<void> {
  const url = `${API_BASE}/results/${id}/${format}`;
  const token = getAuthToken();

  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  if (response.status === 401) {
    fireAuthExpired();
    throw new ApiError('Session expired — please log in again', 401);
  }

  if (!response.ok) {
    throw new ApiError(`Download failed (${response.status})`, response.status);
  }

  // Extract filename from Content-Disposition header, or use a sensible default
  const disposition = response.headers.get('Content-Disposition');
  let fileName = `report.${format}`;
  if (disposition) {
    const match = disposition.match(/filename=(.+)/);
    if (match) {
      fileName = match[1].replace(/["']/g, '');
    }
  }

  const blob = await response.blob();
  const objectUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.URL.revokeObjectURL(objectUrl);
}

// List history
export async function listHistory(
  limit: number = 20,
  offset: number = 0
): Promise<HistoryResponse> {
  return fetchApi<HistoryResponse>(`/history?limit=${limit}&offset=${offset}`);
}

// Delete analysis
export async function deleteAnalysis(id: string): Promise<{ id: string; message: string }> {
  return fetchApi(`/history/${id}`, {
    method: 'DELETE',
  });
}

// Get network topology for an analysis
export async function getTopology(id: string): Promise<{ nodes: any[]; links: any[] }> {
  return fetchApi(`/topology/${id}`);
}

// Submit wizard symptoms and get prioritized findings
export async function postWizard(id: string, symptomId: string, answers: Record<string, string>): Promise<{ symptom_id: string; findings: any[]; total: number }> {
  return fetchApi(`/wizard/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ symptom_id: symptomId, answers }),
  });
}

// Compare two analysis results
export async function compareAnalyses(baselineId: string, currentId: string): Promise<{ metrics: any[]; new_issues: string[]; resolved_issues: string[]; summary: string }> {
  return fetchApi('/compare', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseline_id: baselineId, current_id: currentId }),
  });
}

// Get historical trend data
export async function getTrends(): Promise<{ trend_points: any[]; total: number }> {
  return fetchApi('/trends');
}

// ── Auth API functions ────────────────────────────────────────

export interface LoginResponse {
  token: string;
  expires_at: string;
  user: { id: number; username: string; role: string };
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  return fetchApi<LoginResponse>('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

export async function getMe(): Promise<{ id: number; username: string; role: string; last_login?: string }> {
  return fetchApi('/auth/me');
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<{ message: string }> {
  return fetchApi('/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
  });
}

// WebSocket connection for real-time progress
export function createProgressWebSocket(
  id: string,
  onMessage: (job: AnalysisJob) => void,
  onError: (error: Error) => void,
  onClose: () => void
): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  const token = getAuthToken();
  const tokenParam = token ? `?token=${encodeURIComponent(token)}` : '';
  const ws = new WebSocket(`${protocol}//${host}/api/ws/${id}${tokenParam}`);

  ws.onmessage = (event) => {
    try {
      const job = JSON.parse(event.data) as AnalysisJob;
      onMessage(job);
    } catch (error) {
      console.error('Failed to parse WebSocket message:', error);
    }
  };

  ws.onerror = () => {
    onError(new Error('WebSocket connection error'));
  };

  ws.onclose = () => {
    onClose();
  };

  return ws;
}
