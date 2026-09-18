import axios, { type AxiosInstance } from 'axios';
import type {
  Asset,
  AuditLog,
  AppNotification,
  RemediationTask,
  ScannerIntegration,
  SecurityFinding,
  User,
  Vulnerability,
} from '../types';
import { API_BASE_URL, USE_MOCK_DATA } from './config';
import {
  mockAssets,
  mockAuditLogs,
  mockCredentials,
  mockFindings,
  mockIntegrations,
  mockNotifications,
  mockRemediation,
  mockUsers,
  mockVulnerabilities,
} from '../data/mockData';


export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 4000,
  headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
});

apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('cybershield_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,

  async (error) => {
    const originalRequest = error.config;

    // If access token expired, try refreshing it once
    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes('auth/login/') &&
      !originalRequest.url?.includes('auth/refresh/')
    ) {
      originalRequest._retry = true;

      const refreshToken = localStorage.getItem(
        'cybershield_refresh_token'
      );

      if (!refreshToken) {
        return Promise.reject(error);
      }

      try {
        const response = await axios.post(
          `${API_BASE_URL}auth/refresh/`,
          {
            refresh: refreshToken,
          }
        );

        const newAccessToken = response.data.access;

        localStorage.setItem(
          'cybershield_token',
          newAccessToken
        );

        originalRequest.headers.Authorization =
          `Bearer ${newAccessToken}`;

        return apiClient(originalRequest);
      } catch (refreshError) {
        localStorage.removeItem('cybershield_token');
        localStorage.removeItem('cybershield_refresh_token');
        localStorage.removeItem('cybershield_user');

        window.location.href = '/login';

        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  }
);

function toApiError(err: unknown, resource: string): Error {
  if (axios.isAxiosError(err)) {
    const status = err.response?.status;
    const detail =
      (err.response?.data as { detail?: string; message?: string } | undefined)?.detail ||
      (err.response?.data as { detail?: string; message?: string } | undefined)?.message;
    if (status) return new Error(`API error loading ${resource}: HTTP ${status}${detail ? ` — ${detail}` : ''}.`);
    return new Error(`Cannot reach the API loading ${resource}: ${err.message}.`);
  }
  return new Error(`Unexpected error loading ${resource}.`);
}

/**
 * REAL API access (Django REST Framework). These helpers never fall back to
 * demo data: failures throw so the UI can report real API errors.
 */
async function fetchResource<T>(path: string, resource: string): Promise<T> {
  try {
    const res = await apiClient.get<T>(path);
    return res.data;
  } catch (err) {
    throw toApiError(err, resource);
  }
}

/**
 * Demo login (development only). Validates strictly against the demo
 * credential list — invalid credentials are rejected, never silently
 * accepted. The returned token is a demo placeholder, NOT a Django JWT.
 * Later, replace the body of the REAL branch with nothing to change:
 * POST /api/auth/login/ is already the real endpoint used below.
 */
async function demoLogin(email: string, password: string): Promise<{ token: string; user: User }> {
  const cred = mockCredentials.find(
    (c) => c.email.toLowerCase() === email.trim().toLowerCase() && c.password === password,
  );
  if (!cred) {
    throw new Error('Invalid email or password.');
  }
  const user = mockUsers.find((u) => u.id === cred.userId);
  if (!user) throw new Error('Invalid email or password.');
  return { token: `demo-token-${user.id}`, user };
}

async function realLogin(
  username: string,
  password: string
): Promise<{ token: string; refreshToken: string; user: User }> {

  let res;

  try {
    res = await apiClient.post('auth/login/', {
      username,
      password,
    });
  } catch (err) {
    throw toApiError(err, 'authentication');
  }

  const data = res.data as {
    access?: string;
    refresh?: string;
    user?: User;
  };

  const token = data.access || '';
  const refreshToken = data.refresh || '';

  if (!token || !refreshToken || !data.user) {
    throw new Error('Login failed: the API did not return a valid session.');
  }

  return {
    token,
    refreshToken,
    user: data.user,
  };
}
export const api = {
  /** True while the app runs on temporary demo data (see src/services/config.ts). */
  isDemoMode: USE_MOCK_DATA,

  async login(
  username: string,
  password: string
): Promise<{ token: string; refreshToken?: string; user: User }> {

  if (USE_MOCK_DATA) return demoLogin(username, password);

  return realLogin(username, password);
},
async getCurrentUser(): Promise<User> {
  return fetchResource<User>('auth/me/', 'current user');
},
  async getFindings(): Promise<SecurityFinding[]> {
    if (USE_MOCK_DATA) return mockFindings;
    return fetchResource<SecurityFinding[]>('findings/', 'findings');
  },

  async getVulnerabilities(): Promise<Vulnerability[]> {
    if (USE_MOCK_DATA) return mockVulnerabilities;
    return fetchResource<Vulnerability[]>('vulnerabilities/', 'vulnerabilities');
  },

  async getAssets(): Promise<Asset[]> {
    if (USE_MOCK_DATA) return mockAssets;
    return fetchResource<Asset[]>('assets/', 'assets');
  },

  async getRemediationTasks(): Promise<RemediationTask[]> {
    if (USE_MOCK_DATA) return mockRemediation;
    return fetchResource<RemediationTask[]>('remediation/', 'remediation tasks');
  },

  async getIntegrations(): Promise<ScannerIntegration[]> {
    if (USE_MOCK_DATA) return mockIntegrations;
    return fetchResource<ScannerIntegration[]>('integrations/', 'scanner integrations');
  },

  async getNotifications(): Promise<AppNotification[]> {
    if (USE_MOCK_DATA) return mockNotifications;
    return fetchResource<AppNotification[]>('notifications/', 'notifications');
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    if (USE_MOCK_DATA) return mockAuditLogs;
    return fetchResource<AuditLog[]>('audit-logs/', 'audit logs');
  },

  async getUsers(): Promise<User[]> {
    if (USE_MOCK_DATA) return mockUsers;
    return fetchResource<User[]>('users/', 'users');
  },

  async syncScanner(id: string): Promise<{ imported: number }> {
    if (USE_MOCK_DATA) return { imported: mockFindings.length };
    try {
      const res = await apiClient.post(`integrations/${id}/sync/`, {});
      const n = (res.data as { imported?: number })?.imported;
      if (typeof n === 'number') return { imported: n };
      throw new Error('Sync failed: the API did not return an import count.');
    } catch (err) {
      throw toApiError(err, 'scanner sync');
    }
  },

  async testConnection(): Promise<{ ok: boolean; latencyMs: number; message: string }> {
    const start = performance.now();
    try {
      await apiClient.get('health/');
      return { ok: true, latencyMs: Math.round(performance.now() - start), message: 'Connection test passed.' };
    } catch (err) {
      const latencyMs = Math.round(performance.now() - start);
      if (USE_MOCK_DATA) {
        return { ok: false, latencyMs, message: 'Backend unreachable — running on demo data.' };
      }
      throw toApiError(err, 'connection test');
    }
  },
};

