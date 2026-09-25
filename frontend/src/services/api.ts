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
  VulnerabilityAIAnalysis,
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
  // Day 9 Task 5: 4000ms was cancelling the large findings payload (and
  // occasionally the N+1 audit-logs query). Pagination + select_related are
  // the real fix; this modest bump to 10s is defensive headroom only — a
  // single 50-row page now resolves in well under a second.
  baseURL: API_BASE_URL,
  timeout: 10000,
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
  finding_count?: number;
  open_vulnerability_count?: number;
  created_at: string;
  updated_at: string;
};

// Day 9 Task 6: backend Asset.ASSET_TYPE_CHOICES are codes (WEB_APP,
// SERVER, NETWORK_DEVICE, OTHER) while the frontend AssetType union uses
// display labels. Normalize at this mapping boundary so `a.type === type`
// filtering works; DB values are never changed for display.
function normalizeAssetType(s: string): Asset['type'] {
  const u = String(s || '').toUpperCase();
  if (u === 'WEB_APP' || u === 'WEB APPLICATION') return 'Web Application';
  if (u === 'SERVER') return 'Server';
  if (u === 'API') return 'API';
  if (u === 'NETWORK_DEVICE' || u === 'NETWORK DEVICE') return 'Network Device';
  if (u === 'DATABASE') return 'Database';
  if (u === 'OTHER') return 'Other';
  return (s as Asset['type']);
}

function mapDjangoAsset(asset: DjangoAsset): Asset {
  return {
    id: String(asset.id),
    name: asset.name,
    type: normalizeAssetType(asset.asset_type),
    address: asset.url || asset.hostname || asset.ip_address || '',
    url: asset.url || '',
    hostname: asset.hostname || '',
    ipAddress: asset.ip_address || null,
    description: asset.description,
    owner: '',
    criticality: asset.criticality as Asset['criticality'],
    createdAt: asset.created_at,
    findingCount: typeof asset.finding_count === 'number' ? asset.finding_count : undefined,
    openVulnerabilityCount: typeof asset.open_vulnerability_count === 'number' ? asset.open_vulnerability_count : undefined,
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
  asset?: number | null;
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

// Day 6: backend RemediationTask <-> frontend RemediationTask mapping.
// The backend enum is OPEN/IN_PROGRESS/COMPLETED/CANCELLED — there is no
// REMEDIATED task state. The vulnerability lifecycle stays authoritative:
// a task reads 'Remediated' only when the linked vulnerability is
// REMEDIATED (see getRemediationDisplay in SecurityContext). The raw
// backend value is preserved as backendStatus so the display derivation
// never has to guess, and reloads always reflect server truth.
function mapDjangoRemediationStatus(s: string): RemediationTask['status'] {
  const u = String(s || '').toUpperCase();
  if (u === 'IN_PROGRESS') return 'In Progress';
  if (u === 'COMPLETED') return 'Completed';
  return 'To Do';
}

function mapFrontendRemediationStatus(s: RemediationTask['status']): string {
  if (s === 'In Progress' || s === 'Remediated' || s === 'Awaiting Verification') return 'IN_PROGRESS';
  if (s === 'Completed') return 'COMPLETED';
  return 'OPEN';
}

type DjangoRemediation = {
  id: number;
  vulnerability: number;
  title: string;
  description: string;
  assigned_to: number | null;
  status: string;
  due_date: string | null;
  notes: string;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
};

function mapDjangoRemediation(task: DjangoRemediation): RemediationTask {
  return {
    id: String(task.id),
    vulnerabilityId: String(task.vulnerability),
    assignedTo: task.assigned_to ? String(task.assigned_to) : null,
    status: mapDjangoRemediationStatus(task.status),
    backendStatus: String(task.status || '').toUpperCase(),
    dueDate: task.due_date,
    notes: task.notes || '',
    proposedFix: task.description || '',
    verificationNotes: '',
    createdAt: task.created_at,
    updatedAt: task.updated_at,
  };
}

type DjangoNotification = {
  id: number;
  recipient: number;
  notification_type: string;
  title: string;
  message: string;
  vulnerability: number | null;
  is_read: boolean;
  created_at: string;
};

function mapDjangoNotification(n: DjangoNotification): AppNotification {
  const t = String(n.notification_type || '').toUpperCase();
  const type = (
    t === 'ASSIGNMENT' ? 'assigned'
    : t === 'REMEDIATION' ? 'submitted_verification'
    : t === 'SCANNER_SYNC' ? 'scanner_sync'
    : 'verified'
  ) as AppNotification['type'];
  return {
    id: String(n.id),
    recipientId: String(n.recipient),
    title: n.title,
    message: n.message,
    type,
    read: !!n.is_read,
    createdAt: n.created_at,
    link: n.vulnerability ? `/vulnerabilities/${n.vulnerability}` : null,
  };
}

type DjangoAuditLog = {
  id: number;
  actor: number | null;
  actor_name: string;
  action: string;
  entity_type: string;
  entity_id: string;
  old_value: unknown;
  new_value: unknown;
  created_at: string;
};

function auditValue(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function mapDjangoAuditLog(a: DjangoAuditLog): AuditLog {
  return {
    id: String(a.id),
    timestamp: a.created_at,
    user: a.actor_name || (a.actor ? `User ${a.actor}` : 'system'),
    action: a.action,
    entityType: a.entity_type,
    entityId: String(a.entity_id),
    oldValue: auditValue(a.old_value),
    newValue: auditValue(a.new_value),
  };
}

function mapDjangoVulnerability(
  vulnerability: DjangoVulnerability
): Vulnerability {
  return {
    id: String(vulnerability.id),
    findingId: String(vulnerability.finding),
    title: vulnerability.title,
    description: vulnerability.description,

    // Day 9 Task 6: backend now exposes the asset id directly (read-only
    // `asset` via finding.asset). Older payloads without it fall back to
    // resolving through findingId in React.
    assetId: vulnerability.asset != null ? String(vulnerability.asset) : '',

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
type DjangoAIAnalysis = {
  id: number;
  vulnerability: number;
  explanation: string;
  potential_impact: string;
  remediation_steps: string;
  verification_steps: string;
  provider: string;
  model_name: string;
  generated_by: number | null;
  generated_by_name: string | null;
  created_at: string;
};

function mapDjangoAIAnalysis(a: DjangoAIAnalysis): VulnerabilityAIAnalysis {
  return {
    id: String(a.id),
    vulnerabilityId: String(a.vulnerability),
    explanation: a.explanation,
    potentialImpact: a.potential_impact,
    remediationSteps: a.remediation_steps,
    verificationSteps: a.verification_steps,
    provider: a.provider,
    modelName: a.model_name,
    generatedBy: a.generated_by ? String(a.generated_by) : null,
    generatedByName: a.generated_by_name,
    createdAt: a.created_at,
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

/** Day 9 Task 5: DRF PageNumberPagination envelope for findings. */
export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface FindingsFilters {
  search?: string;
  severity?: string;
  status?: string;
  /** Day 9 Task 6: asset-scoped listing for AssetDetailPage. */
  asset?: string;
}

export interface FindingsPage {
  items: SecurityFinding[];
  count: number;
  page: number;
  pageSize: number;
  numPages: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

export interface FindingsStats {
  total: number;
  open: number;
  new: number;
  reviewed: number;
  promoted: number;
  dismissed: number;
}

/** POST /api/assets/ payload — backend enum codes (WEB_APP, …). */
export interface CreateAssetInput {
  name: string;
  asset_type: string;
  hostname?: string;
  ip_address?: string | null;
  url?: string;
  criticality?: string;
  description?: string;
}

export const FINDINGS_PAGE_SIZE = 50;

function isPaginatedFindings(
  data: unknown,
): data is { count: number; next: string | null; previous: string | null; results: DjangoSecurityFinding[] } {
  if (typeof data !== 'object' || data === null) return false;
  const d = data as Record<string, unknown>;
  return typeof d.count === 'number' && Array.isArray(d.results);
}

function buildFindingsPage(
  data: DjangoSecurityFinding[] | { count: number; next: string | null; previous: string | null; results: DjangoSecurityFinding[] },
  page: number,
  pageSize: number,
): FindingsPage {
  if (isPaginatedFindings(data)) {
    const count = data.count;
    return {
      items: data.results.map(mapDjangoFinding),
      count,
      page,
      pageSize,
      numPages: Math.max(1, Math.ceil(count / pageSize)),
      hasNext: data.next !== null,
      hasPrevious: data.previous !== null,
    };
  }
  // Back-compat: if the backend ever returns a raw array, wrap it.
  const items = (data as DjangoSecurityFinding[]).map(mapDjangoFinding);
  return {
    items,
    count: items.length,
    page,
    pageSize,
    numPages: 1,
    hasNext: false,
    hasPrevious: false,
  };
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

async testZapConnection(): Promise<{
  success: boolean;
  version?: string;
  error?: string;
}> {
  try {
    const res = await apiClient.get('findings/zap/test-connection/');
    return res.data;
  } catch (err) {
    throw toApiError(err, 'ZAP connection');
  }
},

async syncZapFindings(assetId: string): Promise<{
  success: boolean;
  total: number;
  created: number;
  duplicates: number;
  error?: string;
}> {
  try {
    const res = await apiClient.post(
      'findings/zap/sync/',
      { asset_id: Number(assetId) },
      { timeout: 60000 }
    );

    return res.data;
  } catch (err) {
    throw toApiError(err, 'ZAP sync');
  }
},

async startZapScan(assetId: string): Promise<{
  scan_id: string;
  asset_id: number;
  asset_name: string;
  target: string;
  status: string;
}> {
  // No ZAP credentials here — the backend owns the ZAP API key and only
  // returns the scan ID plus safe asset/target info.
  try {
    const res = await apiClient.post(
      'findings/zap/scan/',
      { asset_id: Number(assetId) },
      { timeout: 30000 }
    );

    return res.data;
  } catch (err) {
    throw toApiError(err, 'ZAP scan start');
  }
},

async getZapScanStatus(scanId: string): Promise<{
  scan_id: string;
  progress: number;
  status: string;
}> {
  try {
    const res = await apiClient.get(
      'findings/zap/scan-status/',
      { params: { scan_id: scanId } }
    );

    return res.data;
  } catch (err) {
    throw toApiError(err, 'ZAP scan status');
  }
},

async getFindingsPage(
  page = 1,
  pageSize: number = FINDINGS_PAGE_SIZE,
  filters: FindingsFilters = {},
): Promise<FindingsPage> {
  if (USE_MOCK_DATA) {
    const q = (filters.search || '').toLowerCase();
    const sev = (filters.severity || 'all').toLowerCase();
    const st = (filters.status || 'all').toLowerCase();
    const filtered = mockFindings.filter((f) => {
      const matchQ =
        !q ||
        f.title.toLowerCase().includes(q) ||
        f.id.toLowerCase().includes(q) ||
        (f.cwe || '').toLowerCase().includes(q);
      const matchSev = sev === 'all' || f.severity === sev;
      const matchSt = st === 'all' || f.status.toLowerCase() === st;
      const matchAsset = !filters.asset || String(f.assetId) === String(filters.asset);
      return matchQ && matchSev && matchSt && matchAsset;
    });
    const count = filtered.length;
    const start = (page - 1) * pageSize;
    return {
      items: filtered.slice(start, start + pageSize),
      count,
      page,
      pageSize,
      numPages: Math.max(1, Math.ceil(count / pageSize)),
      hasNext: start + pageSize < count,
      hasPrevious: page > 1,
    };
  }

  const params: Record<string, string | number> = { page, page_size: pageSize };
  if (filters.search) params.search = filters.search;
  if (filters.severity && filters.severity !== 'all') params.severity = filters.severity;
  if (filters.status && filters.status !== 'all') params.status = filters.status;
  if (filters.asset) params.asset = filters.asset;
  try {
    const res = await apiClient.get<
      DjangoSecurityFinding[] | PaginatedResponse<DjangoSecurityFinding>
    >('findings/', { params });
    return buildFindingsPage(res.data, page, pageSize);
  } catch (err) {
    throw toApiError(err, 'findings');
  }
},

async getFindingsStats(): Promise<FindingsStats> {
  if (USE_MOCK_DATA) {
    const countBy = (s: string) =>
      mockFindings.filter((f) => f.status === s).length;
    const fresh = countBy('New');
    const reviewed = countBy('Reviewed');
    return {
      total: mockFindings.length,
      open: fresh + reviewed,
      new: fresh,
      reviewed,
      promoted: countBy('Promoted'),
      dismissed: mockFindings.filter((f) => f.status === 'Ignored').length,
    };
  }
  return fetchResource<FindingsStats>('findings/stats/', 'findings statistics');
},

async getFinding(id: string): Promise<SecurityFinding> {
  if (USE_MOCK_DATA) {
    const found = mockFindings.find((f) => f.id === id);
    if (!found) throw new Error('Finding not found.');
    return found;
  }
  try {
    const res = await apiClient.get<DjangoSecurityFinding>(`findings/${id}/`);
    return mapDjangoFinding(res.data);
  } catch (err) {
    throw toApiError(err, 'finding');
  }
},

async getFindings(): Promise<SecurityFinding[]> {
  if (USE_MOCK_DATA) return mockFindings;

  // Back-compat shim: returns the first page only. New code should use
  // getFindingsPage() + getFindingsStats() so a 50-row page is never
  // mistaken for the full findings table.
  const first = await api.getFindingsPage(1, FINDINGS_PAGE_SIZE);
  return first.items;
},

async reviewFinding(id: string): Promise<SecurityFinding> {
  try {
    const finding = await apiClient.post<DjangoSecurityFinding>(
      `findings/${id}/review/`
    );

    return mapDjangoFinding(finding.data);
  } catch (err) {
    throw toApiError(err, 'finding review');
  }
},

async promoteFinding(
  id: string,
  impact: number,
  likelihood: number
): Promise<Vulnerability> {
  try {
    const vulnerability = await apiClient.post<DjangoVulnerability>(
      `findings/${id}/promote/`,
      {
        impact,
        likelihood,
      }
    );

    return mapDjangoVulnerability(vulnerability.data);
  } catch (err) {
    throw toApiError(err, 'finding promotion');
  }
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

async createAsset(input: CreateAssetInput): Promise<Asset> {
  try {
    const res = await apiClient.post<DjangoAsset>('assets/', input);
    return mapDjangoAsset(res.data);
  } catch (err) {
    throw toApiError(err, 'asset creation');
  }
},

async updateAsset(id: string, patch: Partial<CreateAssetInput>): Promise<Asset> {
  try {
    const res = await apiClient.patch<DjangoAsset>(`assets/${id}/`, patch);
    return mapDjangoAsset(res.data);
  } catch (err) {
    throw toApiError(err, 'asset update');
  }
},

async deleteAsset(id: string): Promise<void> {
  try {
    await apiClient.delete(`assets/${id}/`);
  } catch (err) {
    throw toApiError(err, 'asset deletion');
  }
},

  async getRemediationTasks(): Promise<RemediationTask[]> {
    if (USE_MOCK_DATA) return mockRemediation;
    const tasks = await fetchResource<DjangoRemediation[]>('remediation/', 'remediation tasks');
    return tasks.map(mapDjangoRemediation);
  },

  async createRemediationTask(input: {
    vulnerabilityId: string;
    notes: string;
    proposedFix: string;
  }): Promise<RemediationTask> {
    try {
      const res = await apiClient.post<DjangoRemediation>('remediation/', {
        vulnerability: Number(input.vulnerabilityId),
        title: `Remediation for vulnerability ${input.vulnerabilityId}`,
        description: input.proposedFix,
        notes: input.notes,
        status: 'OPEN',
      });
      return mapDjangoRemediation(res.data);
    } catch (err) {
      throw toApiError(err, 'remediation create');
    }
  },

  async updateRemediationTask(
    id: string,
    input: { notes: string; proposedFix: string }
  ): Promise<RemediationTask> {
    try {
      const res = await apiClient.patch<DjangoRemediation>(`remediation/${id}/`, {
        description: input.proposedFix,
        notes: input.notes,
      });
      return mapDjangoRemediation(res.data);
    } catch (err) {
      throw toApiError(err, 'remediation update');
    }
  },

  /**
   * Persist a remediation task status change (PATCH remediation/:id/).
   * Backend enum: OPEN / IN_PROGRESS / COMPLETED / CANCELLED. The assigned
   * developer (or analyst/admin) may write; the backend enforces this and
   * audits the change server-side. 'Remediated' has no backend task value —
   * callers persist COMPLETED and synchronize the vulnerability lifecycle
   * (IN_PROGRESS -> REMEDIATED); the display derivation then reads
   * 'Remediated' from server truth on every load.
   */
  async updateRemediationTaskStatus(
    id: string,
    backendStatus: 'OPEN' | 'IN_PROGRESS' | 'COMPLETED'
  ): Promise<RemediationTask> {
    if (USE_MOCK_DATA) {
      const found = mockRemediation.find((t) => t.id === id);
      if (!found) throw new Error('Remediation task not found.');
      return { ...found, status: mapDjangoRemediationStatus(backendStatus) };
    }
    try {
      const res = await apiClient.patch<DjangoRemediation>(`remediation/${id}/`, {
        status: backendStatus,
      });
      return mapDjangoRemediation(res.data);
    } catch (err) {
      throw toApiError(err, 'remediation status update');
    }
  },

  async getIntegrations(): Promise<ScannerIntegration[]> {
    if (USE_MOCK_DATA) return mockIntegrations;
    // No backend /api/integrations/ route exists (scanner sync lives under
    // findings/zap/*). Return empty instead of issuing a request that 404s.
    return [];
  },

  async getNotifications(): Promise<AppNotification[]> {
    if (USE_MOCK_DATA) return mockNotifications;
    const items = await fetchResource<DjangoNotification[]>('notifications/', 'notifications');
    return items.map(mapDjangoNotification);
  },

  async markNotificationRead(id: string): Promise<AppNotification> {
    try {
      const res = await apiClient.post<DjangoNotification>(`notifications/${id}/read/`, {});
      return mapDjangoNotification(res.data);
    } catch (err) {
      throw toApiError(err, 'notification update');
    }
  },

  async markAllNotificationsRead(): Promise<number> {
    try {
      const res = await apiClient.post<{ marked?: number }>('notifications/mark-all-read/', {});
      return typeof res.data?.marked === 'number' ? res.data.marked : 0;
    } catch (err) {
      throw toApiError(err, 'notification update');
    }
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    if (USE_MOCK_DATA) return mockAuditLogs;
    const logs = await fetchResource<DjangoAuditLog[]>('audit-logs/', 'audit logs');
    return logs.map(mapDjangoAuditLog);
  },

  async getUsers(): Promise<User[]> {
    if (USE_MOCK_DATA) return mockUsers;
    const items = await fetchResource<Array<User & { is_active?: boolean }>>('users/', 'users');
    // The Status column reflects the Django account flag (is_active),
    // not online presence — map it onto the existing User.active field.
    return items.map(({ is_active, ...rest }) => ({ ...rest, active: is_active }));
  },

  async generateAIAnalysis(vulnerabilityId: string): Promise<VulnerabilityAIAnalysis> {
    // Server-side Gemini generation only: never contacts an AI provider
    // from React. Explicit analyst/admin action; backend RBAC applies.
    // Per-request 90s timeout (global stays 10s): generation legitimately
    // takes 10-60s plus one bounded server-side retry, so the default
    // window would abort healthy requests and cause broken-pipe waste.
    try {
      const res = await apiClient.post<DjangoAIAnalysis>(
        `vulnerabilities/${vulnerabilityId}/ai-analysis/`,
        {},
        { timeout: 90000 }
      );
      return mapDjangoAIAnalysis(res.data);
    } catch (err) {
      throw toApiError(err, 'AI analysis generation');
    }
  },

  async getAIAnalyses(vulnerabilityId: string): Promise<VulnerabilityAIAnalysis[]> {
    if (USE_MOCK_DATA) return [];
    const items = await fetchResource<DjangoAIAnalysis[]>(
      `vulnerabilities/${vulnerabilityId}/ai-analyses/`,
      'AI analyses'
    );
    return items.map(mapDjangoAIAnalysis);
  },

  async syncScanner(_id: string): Promise<{ imported: number }> {
    if (USE_MOCK_DATA) return { imported: mockFindings.length };
    // The legacy POST integrations/:id/sync/ endpoint no longer exists and
    // would only 404. ZAP sync is explicit per asset on the Findings page
    // (api.syncZapFindings), so fail loudly instead of hiding a 404.
    throw new Error('Scanner sync moved: use Sync Findings on the Findings page (OWASP ZAP Scanner).');
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

