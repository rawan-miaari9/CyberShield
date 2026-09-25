// ---------------------------------------------------------------------------
// DEMO DATA (temporary, development only).
// Used only when VITE_USE_MOCK_DATA=true in src/services/config.ts.
// Each export below maps 1:1 to a future Django API response and will be
// replaced with a real API call in src/services/api.ts without UI changes.
//
// Identifier conventions for demo data:
// - Vulnerabilities use internal IDs (VULN-001, ...). No CVE identifiers are
//   shown unless a verified CVE is received from the scanner/backend.
// - Scanner findings use finding IDs (FND-001, ...). CWE identifiers may be
//   used where technically appropriate. ZAP alert references are kept in the
//   `alertRef` field as scanner-provided metadata.
// ---------------------------------------------------------------------------
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

export const mockUsers: User[] = [
  { id: 'USR-001', name: 'Amina Diallo', username: 'amina', email: 'amina@cybershield.local', first_name: 'Amina', last_name: 'Diallo', role: 'Administrator', active: true, lastLogin: '2026-09-15 09:12 UTC' },
  { id: 'USR-002', name: 'Jonas Vance', username: 'jonas', email: 'jonas@cybershield.local', first_name: 'Jonas', last_name: 'Vance', role: 'Security Analyst', active: true, lastLogin: '2026-09-16 08:20 UTC' },
  { id: 'USR-003', name: 'Priya Nair', username: 'priya', email: 'priya@cybershield.local', first_name: 'Priya', last_name: 'Nair', role: 'Security Analyst', active: true, lastLogin: '2026-09-14 16:44 UTC' },
  { id: 'USR-004', name: 'Marco Reyes', username: 'marco', email: 'marco@cybershield.local', first_name: 'Marco', last_name: 'Reyes', role: 'IT / Developer', active: true, lastLogin: '2026-09-13 11:02 UTC' },
];

// Demo credentials for local development only (validated strictly — invalid
// credentials are rejected and never silently succeed).
export const mockCredentials: Array<{ email: string; password: string; userId: string }> = [
  { email: 'admin@cybershield.local', password: 'admin123', userId: 'USR-001' },
  { email: 'analyst@cybershield.local', password: 'analyst123', userId: 'USR-002' },
];

export const mockAssets: Asset[] = [
  { id: 'AST-001', name: 'Customer Portal', type: 'Web Application', address: 'https://portal.example.com', description: 'Public customer self-service portal.', owner: 'Web Team', criticality: 'high', createdAt: '2026-02-10' },
  { id: 'AST-002', name: 'Auth Server', type: 'Server', address: '10.20.12.8', description: 'Internal authentication server.', owner: 'Platform Team', criticality: 'critical', createdAt: '2026-01-22' },
  { id: 'AST-003', name: 'Payments API', type: 'API', address: 'https://api.example.com/payments', description: 'Payment processing API.', owner: 'Payments Team', criticality: 'critical', createdAt: '2026-03-05' },
  { id: 'AST-004', name: 'Core Switch 01', type: 'Network Device', address: '10.20.1.1', description: 'Core distribution switch.', owner: 'NetOps', criticality: 'medium', createdAt: '2025-11-18' },
  { id: 'AST-005', name: 'Orders Database', type: 'Database', address: '10.20.20.2:5432', description: 'Primary orders PostgreSQL database.', owner: 'Data Team', criticality: 'high', createdAt: '2026-01-30' },
  { id: 'AST-006', name: 'Docs Site', type: 'Web Application', address: 'https://docs.example.com', description: 'Public documentation site.', owner: 'Web Team', criticality: 'low', createdAt: '2026-04-12' },
];

export const mockFindings: SecurityFinding[] = [
  { id: 'FND-001', title: 'Missing Anti-clickjacking Header', description: 'The response does not include X-Frame-Options or CSP frame-ancestors to protect against clickjacking.', severity: 'medium', cvssScore: 5.4, cwe: 'CWE-1021', assetId: 'AST-001', scannerSource: 'OWASP ZAP', importedAt: '2026-09-15 10:02 UTC', status: 'New', evidence: 'GET https://portal.example.com/ -> no X-Frame-Options header present.', alertRef: 'ZAP-10020' },
  { id: 'FND-002', title: 'SQL Injection Possibility', description: 'A parameter appears to alter SQL query structure. Requires analyst review before promotion.', severity: 'high', cvssScore: 8.1, cwe: 'CWE-89', assetId: 'AST-003', scannerSource: 'OWASP ZAP', importedAt: '2026-09-15 10:04 UTC', status: 'New', evidence: 'GET /payments?order_id=1 AND 1=1 produced timing differential.', alertRef: 'ZAP-40018' },
  { id: 'FND-003', title: 'Cross-Domain Misconfiguration', description: 'Wildcard CORS policy allows any origin with credentials on a sensitive endpoint.', severity: 'high', cvssScore: 7.5, cwe: 'CWE-639', assetId: 'AST-003', scannerSource: 'OWASP ZAP', importedAt: '2026-09-15 10:04 UTC', status: 'Reviewed', evidence: 'Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.', alertRef: 'ZAP-40032' },
  { id: 'FND-004', title: 'Server Leaks Version Information', description: 'Server header discloses version details useful for targeted exploitation.', severity: 'low', cvssScore: 3.7, cwe: 'CWE-200', assetId: 'AST-001', scannerSource: 'OWASP ZAP', importedAt: '2026-09-14 09:41 UTC', status: 'Reviewed', evidence: 'Server: nginx/1.24.0', alertRef: 'ZAP-10036' },
  { id: 'FND-005', title: 'Reflected XSS Candidate', description: 'User input reflected without encoding on search endpoint.', severity: 'critical', cvssScore: 9.0, cwe: 'CWE-79', assetId: 'AST-001', scannerSource: 'OWASP ZAP', importedAt: '2026-09-14 09:44 UTC', status: 'New', evidence: 'GET /search?q=<script>alert(1)</script> reflected in response body.', alertRef: 'ZAP-40012' },
  { id: 'FND-006', title: 'Insecure Cookie Flag', description: 'Session cookie missing Secure flag.', severity: 'medium', cvssScore: 5.3, cwe: 'CWE-614', assetId: 'AST-002', scannerSource: 'OWASP ZAP', importedAt: '2026-09-13 15:20 UTC', status: 'Ignored', evidence: 'Set-Cookie: sessionid=...; HttpOnly (no Secure).', alertRef: 'ZAP-10010' },
  { id: 'FND-007', title: 'Path Traversal Probe', description: 'Scanner payload reached filesystem error message.', severity: 'high', cvssScore: 7.7, cwe: 'CWE-22', assetId: 'AST-002', scannerSource: 'OWASP ZAP', importedAt: '2026-09-13 15:22 UTC', status: 'Promoted', evidence: 'GET /files?path=../../etc/passwd returned root: entry.', alertRef: 'ZAP-6' },
  { id: 'FND-008', title: 'Content-Security-Policy Not Set', description: 'CSP header not configured on marketing pages.', severity: 'low', cvssScore: 3.1, cwe: 'CWE-693', assetId: 'AST-006', scannerSource: 'OWASP ZAP', importedAt: '2026-09-12 11:10 UTC', status: 'Reviewed', evidence: 'No Content-Security-Policy header on GET /', alertRef: 'ZAP-10038' },
];

export const mockVulnerabilities: Vulnerability[] = [
  { id: 'VULN-001', findingId: 'FND-007', title: 'Path traversal on file download endpoint', description: 'Analyst-confirmed path traversal allowing access to files outside the web root on the Auth Server.', assetId: 'AST-002', severity: 'high', impact: 4, likelihood: 4, riskScore: 16, riskLevel: 'High', status: 'IN_PROGRESS', assignedTo: 'USR-004', dueDate: '2026-09-24', discoveredAt: '2026-09-13', cwe: 'CWE-22', proposedFix: 'Canonicalize paths and enforce an allow-listed download directory.' },
  { id: 'VULN-002', findingId: 'FND-002', title: 'Possible SQL injection in order lookup', description: 'Under review: order_id parameter shows anomalous query behavior. Pending developer confirmation.', assetId: 'AST-003', severity: 'high', impact: 5, likelihood: 3, riskScore: 15, riskLevel: 'High', status: 'ASSIGNED', assignedTo: 'USR-002', dueDate: '2026-09-22', discoveredAt: '2026-09-15', cwe: 'CWE-89', proposedFix: 'Use parameterized queries and least-privilege DB role.' },
  { id: 'VULN-003', findingId: null, title: 'Session cookie missing Secure flag', description: 'Session cookie can be transmitted over plain HTTP on legacy subdomains.', assetId: 'AST-002', severity: 'medium', impact: 3, likelihood: 2, riskScore: 6, riskLevel: 'Medium', status: 'NEW', assignedTo: null, dueDate: null, discoveredAt: '2026-09-13', cwe: 'CWE-614', proposedFix: 'Set Secure and HttpOnly flags; enforce HSTS.' },
  { id: 'VULN-004', findingId: 'FND-005', title: 'Reflected input on search endpoint', description: 'Search term reflected without output encoding; needs output-encoding fix and review.', assetId: 'AST-001', severity: 'critical', impact: 5, likelihood: 4, riskScore: 20, riskLevel: 'Critical', status: 'NEW', assignedTo: null, dueDate: '2026-09-20', discoveredAt: '2026-09-14', cwe: 'CWE-79', proposedFix: 'Context-aware output encoding plus input validation.' },
  { id: 'VULN-005', findingId: null, title: 'Wildcard CORS on payments API', description: 'Payments API returns wildcard origin with credentials allowed.', assetId: 'AST-003', severity: 'high', impact: 4, likelihood: 3, riskScore: 12, riskLevel: 'High', status: 'REMEDIATED', assignedTo: 'USR-004', dueDate: '2026-09-16', discoveredAt: '2026-09-10', cwe: 'CWE-639', proposedFix: 'Restrict allowed origins to known frontends.' },
  { id: 'VULN-006', findingId: null, title: 'Verbose server banner on portal', description: 'Portal discloses exact server version.', assetId: 'AST-001', severity: 'low', impact: 2, likelihood: 2, riskScore: 4, riskLevel: 'Low', status: 'VERIFIED', assignedTo: 'USR-004', dueDate: '2026-09-12', discoveredAt: '2026-09-08', cwe: 'CWE-200', proposedFix: 'Suppress version banner in server configuration.' },
  { id: 'VULN-007', findingId: null, title: 'Missing CSP on docs site', description: 'Docs site has no content security policy.', assetId: 'AST-006', severity: 'low', impact: 2, likelihood: 1, riskScore: 2, riskLevel: 'Low', status: 'CLOSED', assignedTo: 'USR-004', dueDate: '2026-09-05', discoveredAt: '2026-09-01', cwe: 'CWE-693', proposedFix: 'Deploy baseline CSP and report-only monitoring.' },
];

export const mockRemediation: RemediationTask[] = [
  { id: 'REM-001', vulnerabilityId: 'VULN-001', assignedTo: 'USR-004', status: 'In Progress', dueDate: '2026-09-24', notes: 'Developer reproduced issue on staging. Fix in progress.', proposedFix: 'Resolve canonical path and limit downloads to the designated directory.', verificationNotes: '', createdAt: '2026-09-13', updatedAt: '2026-09-15' },
  { id: 'REM-002', vulnerabilityId: 'VULN-005', assignedTo: 'USR-004', status: 'Awaiting Verification', dueDate: '2026-09-16', notes: 'CORS allow-list deployed to staging.', proposedFix: 'Restrict Access-Control-Allow-Origin to portal and checkout origins.', verificationNotes: '', createdAt: '2026-09-11', updatedAt: '2026-09-15' },
  { id: 'REM-003', vulnerabilityId: 'VULN-006', assignedTo: 'USR-004', status: 'Completed', dueDate: '2026-09-12', notes: 'Banner suppressed and verified by analyst.', proposedFix: 'Disable version disclosure in server configuration.', verificationNotes: 'Verified with response header check on 2026-09-12.', createdAt: '2026-09-08', updatedAt: '2026-09-12' },
];

export const mockIntegrations: ScannerIntegration[] = [
  { id: 'INT-ZAP', name: 'OWASP ZAP', type: 'OWASP ZAP', status: 'active', lastSync: '2026-09-15 10:05 UTC', findingsCount: 8, endpoint: 'http://127.0.0.1:8080', apiKeyConfigured: true, description: 'External dynamic application security scanner. Findings are imported into CyberShield for review.' },
];

export const mockNotifications: AppNotification[] = [
  { id: 'N-001', recipientId: 'USR-002', title: 'Critical vulnerability created', message: 'VULN-004 (reflected input) was created with Critical risk.', type: 'critical_vulnerability', read: false, createdAt: '2026-09-14 09:50 UTC', link: '/vulnerabilities/VULN-004' },
  { id: 'N-002', recipientId: 'USR-002', title: 'Vulnerability assigned', message: 'VULN-002 was assigned to Jonas Vance.', type: 'assigned', read: false, createdAt: '2026-09-15 08:12 UTC', link: '/vulnerabilities/VULN-002' },
  { id: 'N-003', recipientId: 'USR-003', title: 'Remediation submitted for verification', message: 'REM-002 is awaiting analyst verification.', type: 'submitted_verification', read: true, createdAt: '2026-09-15 11:30 UTC', link: '/remediation/REM-002' },
  { id: 'N-004', recipientId: 'USR-001', title: 'Scanner sync completed', message: 'OWASP ZAP sync imported 8 findings.', type: 'scanner_sync', read: true, createdAt: '2026-09-15 10:05 UTC', link: '/findings' },
];

export const mockAuditLogs: AuditLog[] = [
  { id: 'AUD-1001', timestamp: '2026-09-15 10:05 UTC', user: 'jonas@cybershield.local', action: 'SCANNER_SYNC', entityType: 'ScannerIntegration', entityId: 'INT-ZAP', oldValue: null, newValue: '8 findings imported' },
  { id: 'AUD-1002', timestamp: '2026-09-15 08:12 UTC', user: 'sara@cybershield.local', action: 'VULNERABILITY_ASSIGN', entityType: 'Vulnerability', entityId: 'VULN-002', oldValue: 'unassigned', newValue: 'USR-002' },
  { id: 'AUD-1003', timestamp: '2026-09-14 09:50 UTC', user: 'jonas@cybershield.local', action: 'VULNERABILITY_CREATE', entityType: 'Vulnerability', entityId: 'VULN-004', oldValue: null, newValue: 'status=NEW risk=Critical(20)' },
  { id: 'AUD-1004', timestamp: '2026-09-13 15:22 UTC', user: 'jonas@cybershield.local', action: 'FINDING_PROMOTE', entityType: 'SecurityFinding', entityId: 'FND-007', oldValue: 'Reviewed', newValue: 'Promoted -> VULN-001' },
  { id: 'AUD-1005', timestamp: '2026-09-12 14:00 UTC', user: 'jonas@cybershield.local', action: 'REMEDIATION_VERIFY', entityType: 'RemediationTask', entityId: 'REM-003', oldValue: 'Awaiting Verification', newValue: 'Completed' },
];

export const trendData = [
  { week: 'W33', open: 9, closed: 4 },
  { week: 'W34', open: 11, closed: 5 },
  { week: 'W35', open: 8, closed: 7 },
  { week: 'W36', open: 10, closed: 6 },
  { week: 'W37', open: 6, closed: 8 },
];
