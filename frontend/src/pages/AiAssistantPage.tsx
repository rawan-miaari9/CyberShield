import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Sparkles } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { api } from '../services/api';
import { displayUser } from './VulnerabilityDetailPage';
import { Card, PageHeader, Mono, Field, LoadingState, inputClass, buttonPrimary } from '../components/ui';
import type { VulnerabilityAIAnalysis } from '../types';

export const AiAssistantPage: React.FC = () => {
  const { vulnerabilities, assetById, userById, user } = useApp();
  // Generation workflow lists active vulnerabilities only — CLOSED items
  // are excluded (NEW through VERIFIED stay available).
  const activeVulnerabilities = vulnerabilities.filter((v) => v.status !== 'CLOSED');
  const [selectedId, setSelectedId] = useState(activeVulnerabilities[0]?.id || '');
  const [analyses, setAnalyses] = useState<VulnerabilityAIAnalysis[] | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiGenerating, setAiGenerating] = useState(false);
  const [aiErr, setAiErr] = useState<string | null>(null);
  const [showHistory, setShowHistory] = useState(false);
  // If the current selection is missing or CLOSED (e.g. closed after
  // selection), fall back to the first active item without generating.
  useEffect(() => {
    if (!activeVulnerabilities.some((v) => v.id === selectedId)) {
      setSelectedId(activeVulnerabilities[0]?.id || '');
      setAnalyses(null);
      setAiErr(null);
    }
  }, [selectedId, vulnerabilities]);
  const selected = activeVulnerabilities.find((v) => v.id === selectedId);

  // Load persisted AI guidance for the selection. Never generates implicitly.
  useEffect(() => {
    if (!selectedId) {
      setAnalyses([]);
      setAiLoading(false);
      return;
    }
    let cancelled = false;
    setAnalyses(null);
    setAiErr(null);
    setAiLoading(true);
    api.getAIAnalyses(selectedId).then(
      (rows) => {
        if (!cancelled) {
          setAnalyses(rows);
          setAiLoading(false);
        }
      },
      (e) => {
        if (!cancelled) {
          setAnalyses([]);
          setAiErr(e instanceof Error ? e.message : 'Could not load AI analyses.');
          setAiLoading(false);
        }
      },
    );
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  // Same frontend permission rule as Vulnerability Details (UX only —
  // the backend remains authoritative): Administrator / Security Analyst
  // always; IT/Developer only when the selection is assigned to them.
  const isAssignee = !!selected?.assignedTo && !!user && String(selected.assignedTo) === String(user.id);
  const canGenerateAI = user?.role === 'Administrator' || user?.role === 'Security Analyst' || isAssignee;
  const [latestAnalysis, ...olderAnalyses] = analyses ?? [];

  // Explicit user action only. Uses the real backend record and prepends
  // it to history; never retries automatically.
  const handleGenerate = async () => {
    if (!selected || aiGenerating) return;
    setAiErr(null);
    setAiGenerating(true);
    try {
      const record = await api.generateAIAnalysis(selected.id);
      setAnalyses((prev) => [record, ...(prev ?? [])]);
    } catch (e) {
      setAiErr(e instanceof Error ? e.message : 'AI generation failed.');
    } finally {
      setAiGenerating(false);
    }
  };

  return (
    <div>
      <PageHeader title="AI Security Assistant" subtitle="Advisory guidance for a selected vulnerability. Guidance is produced server-side; the frontend never contacts an AI provider directly." />
      <Card className="p-6 mb-6">
        <div className="flex flex-col md:flex-row gap-4 md:items-end">
          <div className="flex-1">
            <label className="block text-sm text-slate-300 mb-1.5">Vulnerability</label>
            <select value={selectedId} onChange={(e) => { setSelectedId(e.target.value); setAnalyses(null); setAiErr(null); setShowHistory(false); }} className={inputClass}>
              {activeVulnerabilities.length === 0
                ? <option value="">No active vulnerabilities</option>
                : activeVulnerabilities.map((v) => <option key={v.id} value={v.id}>{v.id} — {v.title}</option>)}
            </select>
          </div>
          {canGenerateAI && (
            <button onClick={handleGenerate} disabled={!selected || aiLoading || aiGenerating} className={buttonPrimary}>
              <Sparkles className="w-4 h-4" /> {aiGenerating ? 'Generating AI analysis…' : latestAnalysis ? 'Regenerate analysis' : 'Generate AI analysis'}
            </button>
          )}
        </div>
        {selected && <p className="text-sm text-slate-500 mt-3">Asset: {assetById(selected.assetId)?.name} · <Mono className="text-xs">Risk {selected.riskScore} ({selected.riskLevel})</Mono></p>}
        {!canGenerateAI && activeVulnerabilities.length > 0 && (
          <p className="text-xs text-slate-500 mt-3">
            {user?.role === 'IT / Developer'
              ? 'Read-only: only the assigned developer, Security Analyst or Administrator can generate AI analysis for this vulnerability.'
              : 'Read-only: you can view existing analyses but cannot generate new ones.'}
          </p>
        )}
      </Card>

      {aiErr && <div className="mb-6 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{aiErr}</div>}
      {aiLoading ? (
        <Card className="p-10 text-center"><LoadingState title="Loading AI guidance…" /></Card>
      ) : latestAnalysis && selected ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-2">1 · Vulnerability explanation</h3>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">{latestAnalysis.explanation}</p>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-2">2 · Potential impact</h3>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">{latestAnalysis.potentialImpact}</p>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-3">3 · Suggested remediation steps</h3>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">{latestAnalysis.remediationSteps}</p>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-3">4 · Suggested verification steps</h3>
            <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">{latestAnalysis.verificationSteps}</p>
          </Card>
        </div>
      ) : (
        <Card className="p-10 text-center">
          <Sparkles className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
          {activeVulnerabilities.length === 0 ? (
            <>
              <p className="text-base text-slate-200 font-medium">No active vulnerabilities</p>
              <p className="text-sm text-slate-500 mt-1">All vulnerabilities are CLOSED — there is nothing to generate guidance for.</p>
            </>
          ) : (
            <>
              <p className="text-base text-slate-200 font-medium">No analysis yet</p>
              <p className="text-sm text-slate-500 mt-1">Select a vulnerability and generate guidance. Active: {activeVulnerabilities.map((v) => v.id).join(', ')}</p>
            </>
          )}
        </Card>
      )}
      {latestAnalysis && selected && (
        <div className="mt-6">
          <p className="text-xs text-slate-500">
            {latestAnalysis.provider}{latestAnalysis.modelName ? ` · ${latestAnalysis.modelName}` : ''} ·{' '}
            <Mono>{new Date(latestAnalysis.createdAt).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</Mono>
            {' · '}by {latestAnalysis.generatedByName || displayUser(userById(latestAnalysis.generatedBy)) || '—'}
          </p>
          {olderAnalyses.length > 0 && (
            <div className="mt-3">
              <button onClick={() => setShowHistory((s) => !s)} className="text-xs text-cyan-300 hover:underline">
                {showHistory ? 'Hide previous analyses' : `View ${olderAnalyses.length} previous ${olderAnalyses.length === 1 ? 'analysis' : 'analyses'}`}
              </button>
              {showHistory && (
                <div className="mt-3 space-y-3">
                  {olderAnalyses.map((a) => (
                    <div key={a.id} className="p-4 rounded-xl bg-[#0d1322] border border-slate-800 text-sm space-y-2">
                      <p className="text-xs text-slate-500">
                        <Mono>{new Date(a.createdAt).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}</Mono>
                        {' · '}by {a.generatedByName || displayUser(userById(a.generatedBy)) || '—'}
                      </p>
                      <p><span className="text-slate-500">Explanation: </span><span className="text-slate-200 whitespace-pre-line">{a.explanation}</span></p>
                      <p><span className="text-slate-500">Impact: </span><span className="text-slate-200 whitespace-pre-line">{a.potentialImpact}</span></p>
                      <p><span className="text-slate-500">Remediation: </span><span className="text-slate-200 whitespace-pre-line">{a.remediationSteps}</span></p>
                      <p><span className="text-slate-500">Verification: </span><span className="text-slate-200 whitespace-pre-line">{a.verificationSteps}</span></p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
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
