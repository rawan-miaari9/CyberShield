import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type {
  AppNotification,
  Asset,
  AuditLog,
  RemediationTask,
  ScannerIntegration,
  SecurityFinding,
  User,
  Vulnerability,
} from '../types';
import { api, FINDINGS_PAGE_SIZE } from '../services/api';
import type { FindingsFilters, FindingsStats } from '../services/api';
import { USE_MOCK_DATA } from '../services/config';
import { calculateRiskScore, riskLevelForScore } from '../utils/risk';

interface AppContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  findings: SecurityFinding[];
  // Day 9 Task 5: findings are server-paginated (50/page). `findings` holds
  // the current page only — never mistake it for the full table. Totals and
  // the dashboard Open KPI come from `findingsStats` (GET findings/stats/).
  // findingsError !== null means "request failed" (distinct from a real
  // empty table); findingsLoading covers the in-flight state.
  findingsLoading: boolean;
  findingsError: string | null;
  findingsStats: FindingsStats | null;
  findingsTotal: number;
  findingsPage: number;
  findingsNumPages: number;
  findingsHasNext: boolean;
  findingsHasPrevious: boolean;
  findingsFilters: FindingsFilters;
  loadFindingsPage: (page: number, filters?: FindingsFilters) => Promise<void>;
  getFindingById: (id: string) => Promise<SecurityFinding | undefined>;
  vulnerabilities: Vulnerability[];
  assets: Asset[];
  remediation: RemediationTask[];
  integrations: ScannerIntegration[];
  notifications: AppNotification[];
  auditLogs: AuditLog[];
  users: User[];
  isLoading: boolean;
  apiError: string | null;
  isDemoMode: boolean;
  authReady: boolean;
  markNotificationRead: (id: string) => Promise<void>;
  markAllNotificationsRead: () => Promise<void>;
  updateFindingStatus: (id: string, status: SecurityFinding['status']) => Promise<void>;
  refreshFindings: () => Promise<void>;
  promoteFinding: (id: string, impact: number, likelihood: number) => Promise<string>;
  updateVulnerabilityStatus: (id: string, status: Vulnerability['status']) => Promise<void>;
  assignVulnerability: (id: string, userId: string | null) => Promise<void>;
  updateVulnerabilityDueDate: (id: string, dueDate: string) => Promise<void>;
  verifyVulnerability: (id: string) => Promise<void>;
  saveRemediation: (vulnerabilityId: string, input: { notes: string; proposedFix: string }) => Promise<void>;
  updateRemediationStatus: (id: string, status: RemediationTask['status']) => Promise<void>;
  /** Live display status: combines the persisted task state with the linked vulnerability lifecycle. */
  getRemediationDisplay: (task: RemediationTask) => RemediationTask['status'];
  syncScanner: (id: string) => Promise<number>;
  unreadCount: number;
  assetById: (id: string | number) => Asset | undefined;
  userById: (id: string | number | null) => User | undefined;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

/**
 * Single role gate for the audit trail, mirroring the backend
 * `IsAdministratorOrSecurityAnalyst` permission (Administrator +
 * Security Analyst only). IT/Developer (and any unknown role) must never
 * trigger a GET /api/audit-logs/ — the backend 403 is correct, so the
 * frontend avoids the forbidden request instead of catching it.
 */
export function canViewAuditLogs(
  user: Pick<User, 'role'> | null | undefined,
): boolean {
  return user?.role === 'Administrator' || user?.role === 'Security Analyst';
}

function appendAudit(
  setAuditLogs: React.Dispatch<React.SetStateAction<AuditLog[]>>,
  user: string,
  action: string,
  entityType: string,
  entityId: string,
  oldValue: string | null,
  newValue: string | null,
) {
  const entry: AuditLog = {
    id: `AUD-${Date.now()}`,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    user,
    action,
    entityType,
    entityId,
    oldValue,
    newValue,
  };
  setAuditLogs((prev) => [entry, ...prev]);
}

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(() => {
    try {
      const raw = localStorage.getItem('cybershield_user');
      return raw ? (JSON.parse(raw) as User) : null;
    } catch {
      return null;
    }
  });
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('cybershield_token'));
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [findingsError, setFindingsError] = useState<string | null>(null);
  const [findingsStats, setFindingsStats] = useState<FindingsStats | null>(null);
  const [findingsPage, setFindingsPage] = useState(1);
  const [findingsNumPages, setFindingsNumPages] = useState(1);
  const [findingsHasNext, setFindingsHasNext] = useState(false);
  const [findingsHasPrevious, setFindingsHasPrevious] = useState(false);
  const [findingsTotal, setFindingsTotal] = useState(0);
  const [findingsFilters, setFindingsFilters] = useState<FindingsFilters>({});
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [remediation, setRemediation] = useState<RemediationTask[]>([]);
  const [integrations, setIntegrations] = useState<ScannerIntegration[]>([]);
  const [notifications, setNotifications] = useState<AppNotification[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  const [authReady, setAuthReady] = useState(false);

  // Auth restoration: distinguish "still restoring" from "unauthenticated".
  // Runs once on startup; data fetching below waits for authReady.
  useEffect(() => {
    let cancelled = false;
    const restore = async () => {
      if (USE_MOCK_DATA) {
        setAuthReady(true);
        return;
      }
      const stored = localStorage.getItem('cybershield_token');
      if (!stored) {
        setAuthReady(true);
        return;
      }
      try {
        // Attaches the stored token (refreshing it if expired) and returns
        // the current user; failure means the session is genuinely invalid.
        const me = await api.getCurrentUser();
        if (!cancelled) setUser(me);
      } catch {
        if (!cancelled) {
          setUser(null);
          setToken(null);
          localStorage.removeItem('cybershield_token');
          localStorage.removeItem('cybershield_refresh_token');
          localStorage.removeItem('cybershield_user');
        }
      } finally {
        if (!cancelled) setAuthReady(true);
      }
    };
    restore();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    // Never fire authenticated requests before auth is restored, or when
    // there is no session at all (avoids false 401/403 noise).
    if (!authReady) return;
    if (!token) {
      setFindings([]);
      setFindingsStats(null);
      setFindingsError(null);
      setFindingsLoading(false);
      setFindingsPage(1);
      setFindingsTotal(0);
      setVulnerabilities([]);
      setAssets([]);
      setRemediation([]);
      setIntegrations([]);
      setNotifications([]);
      setAuditLogs([]);
      setUsers([]);
      setApiError(null);
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setFindingsLoading(true);
      setApiError(null);
      setFindingsError(null);
      try {
        // No api.getIntegrations() here: there is no backend
        // /api/integrations/ route (ZAP sync lives under findings/zap/*),
        // so requesting it only produced a 404 that polluted apiError.
        // Findings load as page 1 + a lightweight stats aggregate; the
        // paginated page is never mistaken for the full table.
        // Audit logs are appended only for roles the backend authorizes;
        // anything else would 403 and pollute apiError with an expected
        // permission denial, so the request is never made for them.
        const includeAuditLogs = canViewAuditLogs(user);
        const batch: Array<Promise<unknown>> = [
          api.getFindingsPage(1, FINDINGS_PAGE_SIZE, {}),
          api.getFindingsStats(),
          api.getVulnerabilities(),
          api.getAssets(),
          api.getRemediationTasks(),
          api.getNotifications(),
          api.getUsers(),
        ];
        const names = ['findings', 'findings statistics', 'vulnerabilities', 'assets', 'remediation tasks', 'notifications', 'users'];
        if (includeAuditLogs) {
          batch.push(api.getAuditLogs());
          names.push('audit logs');
        } else {
          setAuditLogs([]);
        }
        const results = await Promise.allSettled(batch);
        if (cancelled) return;
        const errors: string[] = [];
        const values: Array<unknown> = results.map((r, i) => {
          if (r.status === 'fulfilled') return r.value;
          errors.push(`${names[i]}: ${r.reason instanceof Error ? r.reason.message : 'failed to load'}`);
          return undefined;
        });
        const [pageRes, statsRes, v, a, r, n, u, logs] = values as [
          Awaited<ReturnType<typeof api.getFindingsPage>> | undefined,
          FindingsStats | undefined,
          Vulnerability[] | undefined, Asset[] | undefined, RemediationTask[] | undefined,
          AppNotification[] | undefined, User[] | undefined, AuditLog[] | undefined,
        ];
        if (pageRes) {
          setFindings(pageRes.items);
          setFindingsTotal(pageRes.count);
          setFindingsPage(pageRes.page);
          setFindingsNumPages(pageRes.numPages);
          setFindingsHasNext(pageRes.hasNext);
          setFindingsHasPrevious(pageRes.hasPrevious);
          setFindingsFilters({});
        } else {
          // Truthful failure: keep the previous page out, flag the error,
          // and do NOT present [] as "zero findings".
          setFindings([]);
          setFindingsError(errors.find((e) => e.startsWith('findings:')) || 'Failed to load findings.');
        }
        if (statsRes) {
          setFindingsStats(statsRes);
        } else if (!errors.some((e) => e.startsWith('findings statistics:'))) {
          // no-op: stats simply unavailable
        } else {
          setFindingsStats(null);
        }
        if (v) setVulnerabilities(v);
        if (a) setAssets(a);
        if (r) setRemediation(r);
        setIntegrations([]);
        if (n) setNotifications(n);
        if (logs) setAuditLogs(logs);
        if (u) setUsers(u);
        const nonFindingsErrors = errors.filter(
          (e) => !e.startsWith('findings:') && !e.startsWith('findings statistics:'),
        );
        const findingsErrors = errors.filter(
          (e) => e.startsWith('findings:') || e.startsWith('findings statistics:'),
        );
        if (findingsErrors.length > 0 && !pageRes) {
          setFindingsError(findingsErrors.join(' '));
        } else if (findingsErrors.length > 0 && pageRes && !statsRes) {
          // Page loaded but stats failed: dashboard KPI falls back to the
          // loaded page with a visible qualifier (see DashboardPage).
          setFindingsError(null);
        }
        if (nonFindingsErrors.length > 0 || (findingsErrors.length > 0 && (!pageRes || !statsRes))) {
          setApiError([...findingsErrors, ...nonFindingsErrors].join(' '));
        }
      } finally {
        if (!cancelled) {
          setIsLoading(false);
          setFindingsLoading(false);
        }
      }
    };
    load();
    return () => {
      cancelled = true;
    };
    // user?.role (not the user object): the audit-log gate depends on the
    // role, and the effect refetches only when the role resolves/changes —
    // never before auth is restored.
  }, [authReady, token, user?.role]);

const login = useCallback(async (username: string, password: string) => {
  const result = await api.login(username, password);

  setUser(result.user);
  setToken(result.token);

  localStorage.setItem('cybershield_token', result.token);
  localStorage.setItem('cybershield_user', JSON.stringify(result.user));

  if (result.refreshToken) {
    localStorage.setItem('cybershield_refresh_token', result.refreshToken);
  }
}, []);

  const logout = useCallback(() => {
    setUser(null);
    setToken(null);
    localStorage.removeItem('cybershield_token');
    localStorage.removeItem('cybershield_refresh_token');
    localStorage.removeItem('cybershield_user');
    // The token-gated load effect clears domain state on token loss.
  }, []);

  // Day 6: server owns audit + workflow notifications, so after each
  // persisted action we best-effort refresh both lists. Failures are
  // swallowed so unrelated endpoint errors never wipe existing state.
  // Role-gated: unauthorized roles never request audit logs (the backend
  // 403 is expected for them), so no forbidden request is ever made here.
  const refreshAuditLogs = useCallback(async () => {
    if (!canViewAuditLogs(user)) return;
    try {
      const logs = await api.getAuditLogs();
      setAuditLogs(logs);
    } catch {
      /* keep existing */
    }
  }, [user]);

  const refreshNotifications = useCallback(async () => {
    try {
      const items = await api.getNotifications();
      setNotifications(items);
    } catch {
      /* keep existing */
    }
  }, []);

  const markNotificationRead = useCallback(async (id: string) => {
    const updated = await api.markNotificationRead(id);
    setNotifications((prev) => prev.map((n) => (n.id === id ? updated : n)));
  }, []);

  // The header bell is a personal inbox: only rows addressed to the
  // current user (or local notes without a recipient) belong to it.
  // Analysts are additionally served everyone else's rows for the
  // Notifications overview page — those must not leak into the bell.
  const isMine = useCallback((n: AppNotification) => {
    if (n.recipientId === undefined || n.recipientId === null) return true;
    if (!user) return false;
    return String(n.recipientId) === String(user.id);
  }, [user]);

  const markAllNotificationsRead = useCallback(async () => {
    await api.markAllNotificationsRead();
    // The backend marks only the caller's own rows — mirror exactly that
    // locally instead of visually clearing other users' notifications.
    setNotifications((prev) => prev.map((n) => (isMine(n) ? { ...n, read: true } : n)));
  }, [isMine]);

  const refreshFindingsStats = useCallback(async () => {
    try {
      const stats = await api.getFindingsStats();
      setFindingsStats(stats);
    } catch {
      /* keep existing stats; dashboard falls back with a qualifier */
    }
  }, []);

  const loadFindingsPage = useCallback(
    async (page: number, filters?: FindingsFilters) => {
      const nextFilters = filters !== undefined ? filters : findingsFilters;
      setFindingsLoading(true);
      setFindingsError(null);
      try {
        const res = await api.getFindingsPage(page, FINDINGS_PAGE_SIZE, nextFilters);
        setFindings(res.items);
        setFindingsTotal(res.count);
        setFindingsPage(res.page);
        setFindingsNumPages(res.numPages);
        setFindingsHasNext(res.hasNext);
        setFindingsHasPrevious(res.hasPrevious);
        setFindingsFilters(nextFilters);
      } catch (error) {
        // Do not substitute [] silently: surface the failure so the UI can
        // distinguish "load failed" from "zero findings".
        setFindingsError(error instanceof Error ? error.message : 'Failed to load findings.');
      } finally {
        setFindingsLoading(false);
      }
    },
    [findingsFilters],
  );

  const getFindingById = useCallback(
    async (id: string): Promise<SecurityFinding | undefined> => {
      const local = findings.find((f) => f.id === id);
      if (local) return local;
      try {
        return await api.getFinding(id);
      } catch {
        return undefined;
      }
    },
    [findings],
  );

  const refreshFindings = useCallback(async () => {
    await loadFindingsPage(findingsPage, findingsFilters);
    await refreshFindingsStats();
  }, [loadFindingsPage, findingsPage, findingsFilters, refreshFindingsStats]);


  const updateFindingStatus = useCallback(
    async (id: string, status: SecurityFinding['status']) => {
      // Day 6: REVIEWED persists via the backend (server-audited as
      // FINDING_REVIEWED). Other local states have no backend endpoint.
      if (status === 'Reviewed') {
        const updated = await api.reviewFinding(id);
        setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
        await refreshAuditLogs();
        await refreshFindingsStats();
        return;
      }
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status } : f)));
      appendAudit(setAuditLogs, user?.email || 'unknown', 'FINDING_STATUS_CHANGE', 'SecurityFinding', id, null, status);
    },
    [user, refreshAuditLogs, refreshFindingsStats],
  );

  const promoteFinding = useCallback(
    async (id: string, impact: number, likelihood: number): Promise<string> => {
      const finding = findings.find((f) => f.id === id);
      if (!finding) return '';
      const vuln = await api.promoteFinding(id, impact, likelihood);

      setVulnerabilities((prev) => [vuln, ...prev]);
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status: 'Promoted' as const } : f)));
      setNotifications((prev) => [
        {
          id: `N-${Date.now()}`,
          recipientId: user ? String(user.id) : null,
          title: 'Finding promoted',
          message: `${finding.id} was promoted to vulnerability ${vuln.id}.`,
          type: 'critical_vulnerability',
          read: false,
          createdAt: new Date().toISOString(),
          link: `/vulnerabilities/${vuln.id}`,
        },
        ...prev,
      ]);

      // Day 6: FINDING_PROMOTED is audited server-side (single record).
      await refreshAuditLogs();
      await refreshFindingsStats();
      return vuln.id;
    },
    [user, findings, assets, vulnerabilities.length, refreshAuditLogs, refreshFindingsStats],
  );

  const updateVulnerabilityStatus = useCallback(
    async (id: string, status: Vulnerability['status']) => {
      // REMEDIATED -> VERIFIED keeps using the dedicated verify endpoint
      // so the existing Mark-verified behavior is preserved.
      const updated = status === 'VERIFIED'
        ? await api.verifyVulnerability(id)
        : await api.transitionVulnerability(id, status);
      setVulnerabilities((prev) => prev.map((v) => (v.id === id ? updated : v)));
      // Day 6: status changes are audited + notified server-side.
      await refreshAuditLogs();
      await refreshNotifications();
    },
    [refreshAuditLogs, refreshNotifications],
  );

  const assignVulnerability = useCallback(
    async (id: string, userId: string | null) => {
      if (userId === null || userId === '') {
        throw new Error('Please select a user.');
      }
      const updated = await api.assignVulnerability(id, userId);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === id ? updated : v)),
      );
      // Day 6: assignment is audited + notified server-side.
      await refreshAuditLogs();
      await refreshNotifications();
    },
    [refreshAuditLogs, refreshNotifications],
  );

  const updateVulnerabilityDueDate = useCallback(
    async (id: string, dueDate: string) => {
      if (!dueDate) {
        throw new Error('Please select a due date.');
      }
      const updated = await api.updateVulnerabilityDueDate(id, dueDate);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === id ? updated : v)),
      );
      // Day 6: due-date change is audited server-side.
      await refreshAuditLogs();
    },
    [refreshAuditLogs],
  );

  const verifyVulnerability = useCallback(
    async (id: string) => {
      const updated = await api.verifyVulnerability(id);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === id ? updated : v)),
      );
      // Day 6: verification is audited + notified server-side.
      await refreshAuditLogs();
      await refreshNotifications();
    },
    [refreshAuditLogs, refreshNotifications],
  );

  const saveRemediation = useCallback(
    async (vulnerabilityId: string, input: { notes: string; proposedFix: string }) => {
      const existing = remediation.find((r) => r.vulnerabilityId === vulnerabilityId);
      const saved = existing
        ? await api.updateRemediationTask(existing.id, input)
        : await api.createRemediationTask({ vulnerabilityId, ...input });
      setRemediation((prev) => {
        if (prev.some((r) => r.id === saved.id)) {
          return prev.map((r) => (r.id === saved.id ? saved : r));
        }
        return [saved, ...prev];
      });
      // Day 6: remediation create/update is audited server-side.
      await refreshAuditLogs();
    },
    [remediation, refreshAuditLogs],
  );

  const updateRemediationStatus = useCallback(
    async (id: string, status: RemediationTask['status']) => {
      // Day 9 remediation persistence fix: status changes are PATCHed to
      // the backend (server-audited as REMEDIATION_UPDATED) instead of
      // living only in local state where any re-fetch wiped them.
      // Backend enum is OPEN/IN_PROGRESS/COMPLETED — 'Remediated' additionally
      // advances the linked vulnerability IN_PROGRESS -> REMEDIATED (the
      // authoritative lifecycle); the display derivation then reads
      // 'Remediated' from server truth on every load. Backward jumps are
      // rejected: the backend task endpoint has no guarded workflow, so the
      // UI must not invent backward/skip transitions.
      const task = remediation.find((r) => r.id === id);
      if (!task) throw new Error('Remediation task not found.');
      const vuln = vulnerabilities.find((v) => v.id === task.vulnerabilityId);

      const replaceTask = (saved: RemediationTask) =>
        setRemediation((prev) =>
          prev.some((r) => r.id === saved.id)
            ? prev.map((r) => (r.id === saved.id ? saved : r))
            : [saved, ...prev],
        );

      if (status === 'In Progress') {
        if (task.backendStatus === 'IN_PROGRESS') return; // idempotent
        if (task.backendStatus && task.backendStatus !== 'OPEN') {
          throw new Error(`Invalid transition: ${task.status} -> In Progress. Only the next step is allowed.`);
        }
        replaceTask(await api.updateRemediationTaskStatus(id, 'IN_PROGRESS'));
        await refreshAuditLogs();
        return;
      }

      if (status === 'Remediated') {
        // Vulnerability lifecycle first (authoritative): only a real
        // IN_PROGRESS vulnerability can advance; an already-REMEDIATED one
        // (e.g. advanced from the vulnerability page) is accepted as-is.
        if (vuln && vuln.status === 'IN_PROGRESS') {
          const updated = await api.transitionVulnerability(vuln.id, 'REMEDIATED');
          setVulnerabilities((prev) => prev.map((v) => (v.id === updated.id ? updated : v)));
          await refreshNotifications();
        } else if (vuln && vuln.status !== 'REMEDIATED') {
          throw new Error(
            `Cannot mark Remediated while vulnerability ${vuln.id} is ${vuln.status.replace(/_/g, ' ')}. Advance it to In Progress first.`,
          );
        }
        replaceTask(await api.updateRemediationTaskStatus(id, 'COMPLETED'));
        await refreshAuditLogs();
        return;
      }

      if (status === 'Completed') {
        // Final closure stays analyst-only in the UI (backend additionally
        // guards verification itself). Normally already COMPLETED via the
        // Remediated step; this persists the terminal state explicitly.
        const role = user?.role;
        if (role !== 'Administrator' && role !== 'Security Analyst' && role !== 'Security Manager') {
          throw new Error('Only a Security Analyst can complete verification.');
        }
        replaceTask(await api.updateRemediationTaskStatus(id, 'COMPLETED'));
        await refreshAuditLogs();
        return;
      }

      throw new Error(`Invalid transition to ${status}. Only the next workflow step is allowed.`);
    },
    [remediation, vulnerabilities, user, refreshAuditLogs, refreshNotifications],
  );

  // Live display status for a remediation task. The persisted backend task
  // state (backendStatus) is combined with the linked vulnerability
  // lifecycle so reloads always show server truth: a VERIFIED/CLOSED vuln
  // -> Completed; a COMPLETED task on a still-open vuln -> Remediated; IN_PROGRESS -> In
  // Progress; otherwise To Do. Rows without backendStatus (demo mocks)
  // pass through their literal status untouched.
  const getRemediationDisplay = useCallback(
    (task: RemediationTask): RemediationTask['status'] => {
      if (!task.backendStatus) return task.status;
      const vuln = vulnerabilities.find((v) => v.id === task.vulnerabilityId);
      const vs = vuln?.status;
      if (vs === 'VERIFIED' || vs === 'CLOSED') return 'Completed';
      if (task.backendStatus === 'COMPLETED') return 'Remediated';
      if (task.backendStatus === 'IN_PROGRESS') return 'In Progress';
      return 'To Do';
    },
    [vulnerabilities],
  );

  const syncScanner = useCallback(
    async (id: string) => {
      const result = await api.syncScanner(id);
      const stamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      setIntegrations((prev) => prev.map((i) => (i.id === id ? { ...i, lastSync: stamp, status: 'active' as const } : i)));
      setNotifications((prev) => [
        { id: `N-${Date.now()}`, recipientId: user ? String(user.id) : null, title: 'Scanner sync completed', message: `Sync imported ${result.imported} findings.`, type: 'scanner_sync', read: false, createdAt: stamp, link: '/findings' },
        ...prev,
      ]);
      appendAudit(setAuditLogs, user?.email || 'unknown', 'SCANNER_SYNC', 'ScannerIntegration', id, null, `${result.imported} findings imported`);
      return result.imported;
    },
    [user],
  );

  const assetById = useCallback((id: string | number) => assets.find((a) => String(a.id) === String(id)), [assets]);
  const userById = useCallback((id: string | number | null) => {
    if (id === null || id === undefined || id === '') return undefined;
    return users.find((u) => String(u.id) === String(id));
  }, [users]);

  const value = useMemo(
    () => ({
      user, token, login, logout, findings, findingsLoading, findingsError,
      findingsStats, findingsTotal, findingsPage, findingsNumPages,
      findingsHasNext, findingsHasPrevious, findingsFilters, loadFindingsPage,
      getFindingById, vulnerabilities, assets, remediation, integrations,
      notifications, auditLogs, users, isLoading, apiError, isDemoMode: USE_MOCK_DATA, markNotificationRead, markAllNotificationsRead,
      updateFindingStatus, refreshFindings, promoteFinding, updateVulnerabilityStatus, assignVulnerability,
      updateVulnerabilityDueDate, verifyVulnerability, saveRemediation, updateRemediationStatus, syncScanner,
      unreadCount: notifications.filter((n) => !n.read && isMine(n)).length,
      assetById, userById, authReady, getRemediationDisplay,
    }),
    [user, token, login, logout, findings, findingsLoading, findingsError, findingsStats, findingsTotal, findingsPage, findingsNumPages, findingsHasNext, findingsHasPrevious, findingsFilters, loadFindingsPage, getFindingById, vulnerabilities, assets, remediation, integrations, notifications, auditLogs, users, isLoading, apiError, authReady, markNotificationRead, markAllNotificationsRead, updateFindingStatus, refreshFindings, promoteFinding, updateVulnerabilityStatus, assignVulnerability, updateVulnerabilityDueDate, verifyVulnerability, saveRemediation, updateRemediationStatus, syncScanner, assetById, userById, isMine, getRemediationDisplay],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export function useApp(): AppContextType {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
