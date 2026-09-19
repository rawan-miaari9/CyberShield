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
  markNotificationRead: (id: string) => void;
  markAllNotificationsRead: () => void;
  updateFindingStatus: (id: string, status: SecurityFinding['status']) => void;
  promoteFinding: (id: string, impact: number, likelihood: number) => Promise<string>;
  updateVulnerabilityStatus: (id: string, status: Vulnerability['status']) => Promise<void>;
  assignVulnerability: (id: string, userId: string | null) => Promise<void>;
  updateVulnerabilityDueDate: (id: string, dueDate: string) => Promise<void>;
  verifyVulnerability: (id: string) => Promise<void>;
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

  useEffect(() => {
    let mounted = true;
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
        if (!mounted) return;
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
        if (mounted) setIsLoading(false);
      }
    };
    load();
    return () => {
      mounted = false;
    };
  }, []);

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
  }, []);

  const markNotificationRead = useCallback((id: string) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const markAllNotificationsRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const updateFindingStatus = useCallback(
    (id: string, status: SecurityFinding['status']) => {
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status } : f)));
      appendAudit(setAuditLogs, user?.email || 'unknown', 'FINDING_STATUS_CHANGE', 'SecurityFinding', id, null, status);
    },
    [user],
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

      appendAudit(
        setAuditLogs,
        user?.email || 'unknown',
        'FINDING_PROMOTE',
        'SecurityFinding',
        id,
        finding.status,
        `Promoted -> ${vuln.id}`
      );
      return vuln.id;
    },
    [findings, assets, vulnerabilities.length, user],
  );

  const updateVulnerabilityStatus = useCallback(
    async (id: string, status: Vulnerability['status']) => {
      const previous = vulnerabilities.find((v) => v.id === id);
      // REMEDIATED -> VERIFIED keeps using the dedicated verify endpoint
      // so the existing Mark-verified behavior is preserved.
      const updated = status === 'VERIFIED'
        ? await api.verifyVulnerability(id)
        : await api.transitionVulnerability(id, status);
      setVulnerabilities((prev) => prev.map((v) => (v.id === id ? updated : v)));
      appendAudit(setAuditLogs, user?.email || 'unknown', 'VULNERABILITY_STATUS_CHANGE', 'Vulnerability', id, previous?.status ?? null, status);
    },
    [user, vulnerabilities],
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
      appendAudit(setAuditLogs, user?.email || 'unknown', 'VULNERABILITY_ASSIGN', 'Vulnerability', id, null, userId);
    },
    [user],
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
      appendAudit(setAuditLogs, user?.email || 'unknown', 'VULNERABILITY_DUE_DATE', 'Vulnerability', id, null, dueDate);
    },
    [user],
  );

  const verifyVulnerability = useCallback(
    async (id: string) => {
      const updated = await api.verifyVulnerability(id);
      setVulnerabilities((prev) =>
        prev.map((v) => (v.id === id ? updated : v)),
      );
      appendAudit(setAuditLogs, user?.email || 'unknown', 'VULNERABILITY_VERIFY', 'Vulnerability', id, null, 'VERIFIED');
    },
    [user],
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
      updateVulnerabilityDueDate, verifyVulnerability, updateRemediationStatus, syncScanner,
      unreadCount: notifications.filter((n) => !n.read).length,
      assetById, userById,
    }),
    [user, token, login, logout, findings, vulnerabilities, assets, remediation, integrations, notifications, auditLogs, users, isLoading, apiError, markNotificationRead, markAllNotificationsRead, updateFindingStatus, promoteFinding, updateVulnerabilityStatus, assignVulnerability, updateVulnerabilityDueDate, verifyVulnerability, updateRemediationStatus, syncScanner, assetById, userById],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export function useApp(): AppContextType {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
