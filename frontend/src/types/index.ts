export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Role = 'Administrator' | 'Security Analyst' | 'IT / Developer' | 'Security Manager';

export interface User {
  id: string | number;

  // Django authentication fields
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  role: Role;

  // Existing frontend fields
  name?: string;
  active?: boolean;
  lastLogin?: string;
}

export type AssetType =
  | 'Web Application'
  | 'Server'
  | 'API'
  | 'Network Device'
  | 'Database'
  | 'Other';

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  address: string;
  /** Raw backend locator fields (kept separate for correct edit prefill). */
  url?: string;
  hostname?: string;
  ipAddress?: string | null;
  description: string;
  owner: string;
  criticality: Severity;
  createdAt: string;
  /** Day 9 Task 6: TRUE backend aggregates — never derived from a page. */
  findingCount?: number;
  openVulnerabilityCount?: number;
}

export interface ScannerIntegration {
  id: string;
  name: string;
  type: 'OWASP ZAP';
  status: 'active' | 'inactive' | 'error';
  lastSync: string | null;
  findingsCount: number;
  endpoint: string;
  apiKeyConfigured: boolean;
  description: string;
}

export type FindingStatus = 'New' | 'Reviewed' | 'Promoted' | 'Ignored';

export interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cvssScore: number | null;
  cwe: string | null;
  assetId: string;
  scannerSource: string;
  importedAt: string;
  status: FindingStatus;
  evidence: string;
  alertRef: string;
}

export type VulnerabilityStatus =
  | 'NEW'
  | 'ASSIGNED'
  | 'IN_PROGRESS'
  | 'REMEDIATED'
  | 'VERIFIED'
  | 'CLOSED';

export type RiskLevel = 'Low' | 'Medium' | 'High' | 'Critical';

export interface Vulnerability {
  id: string;
  findingId: string | null;
  title: string;
  description: string;
  assetId: string;
  severity: Severity;
  impact: number;
  likelihood: number;
  riskScore: number;
  riskLevel: RiskLevel;
  status: VulnerabilityStatus;
  assignedTo: string | null;
  dueDate: string | null;
  discoveredAt: string;
  cwe: string | null;
  proposedFix: string;
}

export type RemediationStatus =
  | 'To Do'
  | 'In Progress'
  | 'Remediated'
  | 'Awaiting Verification'
  | 'Completed';

export interface RemediationTask {
  id: string;
  vulnerabilityId: string;
  assignedTo: string | null;
  status: RemediationStatus;
  /** Raw backend enum (OPEN/IN_PROGRESS/COMPLETED/…). Absent on mock rows. */
  backendStatus?: string;
  dueDate: string | null;
  notes: string;
  proposedFix: string;
  verificationNotes: string;
  createdAt: string;
  updatedAt: string;
}

export interface AIAnalysis {
  id: string;
  vulnerabilityId: string;
  explanation: string;
  impact: string;
  remediationSteps: string[];
  verificationSteps: string[];
  generatedAt: string;
  model: string;
}

/** Persisted server-side AI guidance (backend AIAnalysisSerializer shape). */
export interface VulnerabilityAIAnalysis {
  id: string;
  vulnerabilityId: string;
  explanation: string;
  potentialImpact: string;
  remediationSteps: string;
  verificationSteps: string;
  provider: string;
  modelName: string;
  generatedBy: string | null;
  generatedByName: string | null;
  createdAt: string;
}

export interface AppNotification {
  id: string;
  /** Backend recipient user id. Absent only on local client-generated notes. */
  recipientId?: string | null;
  title: string;
  message: string;
  type:
    | 'critical_vulnerability'
    | 'assigned'
    | 'due_soon'
    | 'submitted_verification'
    | 'verified'
    | 'scanner_sync';
  read: boolean;
  createdAt: string;
  link: string | null;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  entityType: string;
  entityId: string;
  oldValue: string | null;
  newValue: string | null;
}
