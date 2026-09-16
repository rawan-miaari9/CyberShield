import type { RiskLevel } from '../types';

export function calculateRiskScore(impact: number, likelihood: number): number {
  const i = Math.min(5, Math.max(1, Math.round(impact)));
  const l = Math.min(5, Math.max(1, Math.round(likelihood)));
  return i * l;
}

export function riskLevelForScore(score: number): RiskLevel {
  if (score >= 17) return 'Critical';
  if (score >= 10) return 'High';
  if (score >= 5) return 'Medium';
  return 'Low';
}
