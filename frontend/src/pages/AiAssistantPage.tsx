import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Sparkles } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, Mono, inputClass, buttonPrimary } from '../components/ui';
import { mockAIAnalyses } from '../data/mockData';
import type { AIAnalysis } from '../types';

function localAnalysis(vulnId: string, title: string): AIAnalysis {
  const preset = mockAIAnalyses[vulnId];
  if (preset) return preset;
  return {
    id: `AI-${vulnId}`,
    vulnerabilityId: vulnId,
    explanation: `“${title}” indicates a weakness that should be understood in the context of the affected asset before fixing. This is advisory guidance only.`,
    impact: 'If exploited, it could affect confidentiality, integrity, or availability depending on exposure and asset criticality. Treat impact as provisional until verified.',
    remediationSteps: ['Confirm the affected component and version.', 'Apply the proposed fix in a test environment first.', 'Add a regression check for this weakness.', 'Schedule the change with the asset owner.'],
    verificationSteps: ['Re-test with the same conditions that confirmed the issue.', 'Confirm normal functionality still works.', 'Record evidence and request analyst verification.'],
    generatedAt: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    model: 'server-side (placeholder)',
  };
}

export const AiAssistantPage: React.FC = () => {
  const { vulnerabilities, assetById } = useApp();
  const [selectedId, setSelectedId] = useState(vulnerabilities[0]?.id || '');
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const selected = vulnerabilities.find((v) => v.id === selectedId);

  const generate = () => {
    if (!selected) return;
    setBusy(true);
    setTimeout(() => {
      setAnalysis(localAnalysis(selected.id, selected.title));
      setBusy(false);
    }, 700);
  };

  return (
    <div>
      <PageHeader title="AI Security Assistant" subtitle="Advisory guidance for a selected vulnerability. Guidance is produced server-side; the frontend never contacts an AI provider directly." />
      <Card className="p-6 mb-6">
        <div className="flex flex-col md:flex-row gap-4 md:items-end">
          <div className="flex-1">
            <label className="block text-sm text-slate-300 mb-1.5">Vulnerability</label>
            <select value={selectedId} onChange={(e) => { setSelectedId(e.target.value); setAnalysis(null); }} className={inputClass}>
              {vulnerabilities.map((v) => <option key={v.id} value={v.id}>{v.id} — {v.title}</option>)}
            </select>
          </div>
          <button onClick={generate} disabled={!selected || busy} className={buttonPrimary}>
            <Sparkles className="w-4 h-4" /> {analysis ? 'Regenerate analysis' : 'Generate AI analysis'}
          </button>
        </div>
        {selected && <p className="text-sm text-slate-500 mt-3">Asset: {assetById(selected.assetId)?.name} · <Mono className="text-xs">Risk {selected.riskScore} ({selected.riskLevel})</Mono></p>}
      </Card>

      {analysis && selected ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-2">1 · Vulnerability explanation</h3>
            <p className="text-sm text-slate-300 leading-relaxed">{analysis.explanation}</p>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-2">2 · Potential impact</h3>
            <p className="text-sm text-slate-300 leading-relaxed">{analysis.impact}</p>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-3">3 · Suggested remediation steps</h3>
            <ol className="list-decimal ml-5 space-y-2 text-sm text-slate-300">
              {analysis.remediationSteps.map((s) => <li key={s}>{s}</li>)}
            </ol>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-3">4 · Suggested verification steps</h3>
            <ol className="list-decimal ml-5 space-y-2 text-sm text-slate-300">
              {analysis.verificationSteps.map((s) => <li key={s}>{s}</li>)}
            </ol>
          </Card>
        </div>
      ) : (
        <Card className="p-10 text-center">
          <Sparkles className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
          <p className="text-base text-slate-200 font-medium">No analysis yet</p>
          <p className="text-sm text-slate-500 mt-1">Select a vulnerability and generate guidance. Open items: {vulnerabilities.map((v) => v.id).join(', ')}</p>
        </Card>
      )}

      <div className="mt-6 p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-sm text-amber-200">
        AI-generated security guidance. Human review is required before implementation.
      </div>
      <p className="text-xs text-slate-500 mt-3">
        The AI never auto-fixes, executes commands, modifies code, verifies, closes, or overrides the Risk = Impact × Likelihood calculation. See{' '}
        <Link to={`/vulnerabilities/${selectedId}`} className="text-cyan-300 hover:underline">vulnerability detail</Link>.
      </p>
    </div>
  );
};
