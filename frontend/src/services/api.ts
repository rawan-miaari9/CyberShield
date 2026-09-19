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
    const body = err.response?.data as { detail?: string; message?: string; error?: string } | undefined;
    const detail = body?.detail || body?.message || body?.error;
    if (status) {
      const e = new Error(detail ? `${detail}` : `API error loading ${resource}: HTTP ${status}.`);
      (e as { status?: number }).status = status;
      return e;
    }
    return new Error(`Cannot reach the API loading ${resource}: ${err.message}.`);
  }
  return new Error(`Unexpected error loading ${resource}.`);
}

/**
 * REAL API access (Django REST Framework). These helpers never fall back to
 * demo data: failures throw so the UI can report real API errors.
 */
type DjangoAsset = {
  id: number;
  name: string;
  asset_type: string;
  hostname: string;
  ip_address: string | null;
  url: string;
  criticality: string;
  description: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
};

function mapDjangoAsset(asset: DjangoAsset): Asset {
  return {
    id: String(asset.id),
    name: asset.name,
    type: asset.asset_type as Asset['type'],
    address: asset.url || asset.hostname || asset.ip_address || '',
    description: asset.description,
    owner: '',
    criticality: asset.criticality as Asset['criticality'],
    createdAt: asset.created_at,
  };
}

type DjangoSecurityFinding = {
  id: number;
  integration: number;
  asset: number;
  external_id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  cwe_id: string;
  evidence: string;
  source_url: string;
  status: string;
  raw_data: Record<string, unknown> | null;
  imported_at: string;
  updated_at: string;
};

// Day 5 status consistency (Part 10, smallest change):
// backend uses UPPERCASE (NEW/REVIEWED/PROMOTED/DISMISSED, HIGH/...),
// frontend Finding types use Title-case/lowercase. Normalize here so
// existing FindingsPage filters and FindingDetailPage buttons keep working.
function normalizeFindingStatus(s: string): SecurityFinding['status'] {
  const u = String(s || '').toUpperCase();
  if (u === 'NEW') return 'New';
  if (u === 'REVIEWED') return 'Reviewed';
  if (u === 'PROMOTED') return 'Promoted';
  if (u === 'DISMISSED' || u === 'IGNORED') return 'Ignored';
  return (s as SecurityFinding['status']);
}

function normalizeSeverity(s: string): SecurityFinding['severity'] {
  return String(s || '').toLowerCase() as SecurityFinding['severity'];
}

function normalizeRiskLevel(s: string): Vulnerability['riskLevel'] {
  const u = String(s || '').toUpperCase();
  if (u === 'LOW') return 'Low';
  if (u === 'MEDIUM') return 'Medium';
  if (u === 'HIGH') return 'High';
  if (u === 'CRITICAL') return 'Critical';
  return (s as Vulnerability['riskLevel']);
}

function mapDjangoFinding(finding: DjangoSecurityFinding): SecurityFinding {
  return {
    id: String(finding.id),
    title: finding.title,
    description: finding.description,
    severity: normalizeSeverity(finding.severity),
    cvssScore: null,
    cwe: finding.cwe_id || null,
    assetId: String(finding.asset),
    scannerSource: `Integration ${finding.integration}`,
    importedAt: finding.imported_at,
    status: normalizeFindingStatus(finding.status),
    evidence: finding.evidence,
    alertRef: finding.external_id,
  };
}

type DjangoVulnerability = {
  id: number;
  finding: number;
  title: string;
  description: string;
  severity: string;
  impact: number;
  likelihood: number;
  risk_score: number;
  risk_level: string;
  status: string;
  assigned_to: number | null;
  due_date: string | null;
  remediation_guidance: string;
  created_at: string;
  updated_at: string;
};

function mapDjangoVulnerability(
  vulnerability: DjangoVulnerability
): Vulnerability {
  return {
    id: String(vulnerability.id),
    findingId: String(vulnerability.finding),
    title: vulnerability.title,
    description: vulnerability.description,

    // Asset belongs to the related finding.
    // We will resolve it from findingId in React.
    assetId: '',

    severity: normalizeSeverity(vulnerability.severity),
    impact: vulnerability.impact,
    likelihood: vulnerability.likelihood,
    riskScore: vulnerability.risk_score,
    riskLevel: normalizeRiskLevel(vulnerability.risk_level),
    status: vulnerability.status as Vulnerability['status'],

    assignedTo: vulnerability.assigned_to
      ? String(vulnerability.assigned_to)
      : null,

    dueDate: vulnerability.due_date,
    discoveredAt: vulnerability.created_at,

    // CWE belongs to the SecurityFinding, not Vulnerability.
    cwe: null,

    proposedFix: vulnerability.remediation_guidance,
  };
}
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

  const findings = await fetchResource<DjangoSecurityFinding[]>(
    'findings/',
    'findings'
  );

  return findings.map(mapDjangoFinding);
},

async reviewFinding(id: string): Promise<SecurityFinding> {
  const finding = await apiClient.post<DjangoSecurityFinding>(
    `findings/${id}/review/`
  );

  return mapDjangoFinding(finding.data);
},

async promoteFinding(
  id: string,
  impact: number,
  likelihood: number
): Promise<Vulnerability> {
  const vulnerability = await apiClient.post<DjangoVulnerability>(
    `findings/${id}/promote/`,
    {
      impact,
      likelihood,
    }
  );

  return mapDjangoVulnerability(vulnerability.data);
},

async assignVulnerability(
  id: string,
  userId: string
): Promise<Vulnerability> {
  try {
    const res = await apiClient.post<DjangoVulnerability>(
      `vulnerabilities/${id}/assign/`,
      { assigned_to: Number(userId) }
    );
    return mapDjangoVulnerability(res.data);
  } catch (err) {
    throw toApiError(err, 'vulnerability assignment');
  }
},

async updateVulnerabilityDueDate(
  id: string,
  dueDate: string
): Promise<Vulnerability> {
  try {
    const res = await apiClient.post<DjangoVulnerability>(
      `vulnerabilities/${id}/due-date/`,
      { due_date: dueDate }
    );
    return mapDjangoVulnerability(res.data);
  } catch (err) {
    throw toApiError(err, 'due date update');
  }
},

async verifyVulnerability(
  id: string
): Promise<Vulnerability> {
  try {
    const res = await apiClient.post<DjangoVulnerability>(
      `vulnerabilities/${id}/verify/`,
      {}
    );
    return mapDjangoVulnerability(res.data);
  } catch (err) {
    throw toApiError(err, 'vulnerability verification');
  }
},

async transitionVulnerability(
  id: string,
  status: string
): Promise<Vulnerability> {
  try {
    const res = await apiClient.post<DjangoVulnerability>(
      `vulnerabilities/${id}/transition/`,
      { status }
    );
    return mapDjangoVulnerability(res.data);
  } catch (err) {
    throw toApiError(err, 'lifecycle transition');
  }
},
  async getVulnerabilities(): Promise<Vulnerability[]> {
  if (USE_MOCK_DATA) return mockVulnerabilities;

  const vulnerabilities =
    await fetchResource<DjangoVulnerability[]>(
      'vulnerabilities/',
      'vulnerabilities'
    );

  return vulnerabilities.map(mapDjangoVulnerability);
},
async getAssets(): Promise<Asset[]> {
  if (USE_MOCK_DATA) return mockAssets;

  const assets = await fetchResource<DjangoAsset[]>('assets/', 'assets');

  return assets.map(mapDjangoAsset);
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

