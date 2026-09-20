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
import { api } from '../services/api';
import { USE_MOCK_DATA } from '../services/config';
import { calculateRiskScore, riskLevelForScore } from '../utils/risk';

interface AppContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  findings: SecurityFinding[];
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
  promoteFinding: (id: string, impact: number, likelihood: number) => Promise<string>;
  updateVulnerabilityStatus: (id: string, status: Vulnerability['status']) => Promise<void>;
  assignVulnerability: (id: string, userId: string | null) => Promise<void>;
  updateVulnerabilityDueDate: (id: string, dueDate: string) => Promise<void>;
  verifyVulnerability: (id: string) => Promise<void>;
  saveRemediation: (vulnerabilityId: string, input: { notes: string; proposedFix: string }) => Promise<void>;
  updateRemediationStatus: (id: string, status: RemediationTask['status']) => void;
  syncScanner: (id: string) => Promise<number>;
  unreadCount: number;
  assetById: (id: string | number) => Asset | undefined;
  userById: (id: string | number | null) => User | undefined;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

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
      setApiError(null);
      try {
        const results = await Promise.allSettled([
          api.getFindings(),
          api.getVulnerabilities(),
          api.getAssets(),
          api.getRemediationTasks(),
          api.getIntegrations(),
          api.getNotifications(),
          api.getAuditLogs(),
          api.getUsers(),
        ]);
        if (cancelled) return;
        const names = ['findings', 'vulnerabilities', 'assets', 'remediation tasks', 'integrations', 'notifications', 'audit logs', 'users'];
        const errors: string[] = [];
        const values: Array<unknown> = results.map((r, i) => {
          if (r.status === 'fulfilled') return r.value;
          errors.push(`${names[i]}: ${r.reason instanceof Error ? r.reason.message : 'failed to load'}`);
          return [];
        });
        const [f, v, a, r, integ, n, logs, u] = values as [
          SecurityFinding[], Vulnerability[], Asset[], RemediationTask[],
          ScannerIntegration[], AppNotification[], AuditLog[], User[],
        ];
        setFindings(f);
        setVulnerabilities(v);
        setAssets(a);
        setRemediation(r);
        setIntegrations(integ);
        setNotifications(n);
        setAuditLogs(logs);
        setUsers(u);
        if (errors.length > 0) {
          setApiError(errors.join(' '));
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [authReady, token]);

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
  const refreshAuditLogs = useCallback(async () => {
    try {
      const logs = await api.getAuditLogs();
      setAuditLogs(logs);
    } catch {
      /* keep existing */
    }
  }, []);

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

  const markAllNotificationsRead = useCallback(async () => {
    await api.markAllNotificationsRead();
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const updateFindingStatus = useCallback(
    async (id: string, status: SecurityFinding['status']) => {
      // Day 6: REVIEWED persists via the backend (server-audited as
      // FINDING_REVIEWED). Other local states have no backend endpoint.
      if (status === 'Reviewed') {
        const updated = await api.reviewFinding(id);
        setFindings((prev) => prev.map((f) => (f.id === id ? updated : f)));
        await refreshAuditLogs();
        return;
      }
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status } : f)));
      appendAudit(setAuditLogs, user?.email || 'unknown', 'FINDING_STATUS_CHANGE', 'SecurityFinding', id, null, status);
    },
    [user, refreshAuditLogs],
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
      return vuln.id;
    },
    [findings, assets, vulnerabilities.length, refreshAuditLogs],
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
    (id: string, status: RemediationTask['status']) => {
      setRemediation((prev) => prev.map((r) => (r.id === id ? { ...r, status, updatedAt: new Date().toISOString().substring(0, 10) } : r)));
      appendAudit(setAuditLogs, user?.email || 'unknown', 'REMEDIATION_STATUS_CHANGE', 'RemediationTask', id, null, status);
      if (status === 'Awaiting Verification') {
        setNotifications((prev) => [
          { id: `N-${Date.now()}`, title: 'Remediation submitted for verification', message: `${id} is awaiting analyst verification.`, type: 'submitted_verification', read: false, createdAt: new Date().toISOString(), link: `/remediation/${id}` },
          ...prev,
        ]);
      }
    },
    [user],
  );

  const syncScanner = useCallback(
    async (id: string) => {
      const result = await api.syncScanner(id);
      const stamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
      setIntegrations((prev) => prev.map((i) => (i.id === id ? { ...i, lastSync: stamp, status: 'active' as const } : i)));
      setNotifications((prev) => [
        { id: `N-${Date.now()}`, title: 'Scanner sync completed', message: `Sync imported ${result.imported} findings.`, type: 'scanner_sync', read: false, createdAt: stamp, link: '/findings' },
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
      user, token, login, logout, findings, vulnerabilities, assets, remediation, integrations,
      notifications, auditLogs, users, isLoading, apiError, isDemoMode: USE_MOCK_DATA, markNotificationRead, markAllNotificationsRead,
      updateFindingStatus, promoteFinding, updateVulnerabilityStatus, assignVulnerability,
      updateVulnerabilityDueDate, verifyVulnerability, saveRemediation, updateRemediationStatus, syncScanner,
      unreadCount: notifications.filter((n) => !n.read).length,
      assetById, userById, authReady,
    }),
    [user, token, login, logout, findings, vulnerabilities, assets, remediation, integrations, notifications, auditLogs, users, isLoading, apiError, authReady, markNotificationRead, markAllNotificationsRead, updateFindingStatus, promoteFinding, updateVulnerabilityStatus, assignVulnerability, updateVulnerabilityDueDate, verifyVulnerability, saveRemediation, updateRemediationStatus, syncScanner, assetById, userById],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export function useApp(): AppContextType {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
