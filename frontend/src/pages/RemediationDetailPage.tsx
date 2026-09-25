import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, Field, Mono, LoadingState, buttonPrimary } from '../components/ui';
import type { RemediationStatus } from '../types';

const flow: RemediationStatus[] = ['To Do', 'In Progress', 'Awaiting Verification', 'Completed'];

// Progress highlighting follows the same order as `flow`. The display
// status is derived from the canonical Vulnerability lifecycle (see
// getRemediationDisplay) — there is no manual task workflow, so
// 'Remediated' never appears as a separate stage.
function flowIndex(status: RemediationStatus): number {
  const i = flow.indexOf(status);
  return i >= 0 ? i : 0;
}

// Same presentation as Dashboard Recent Activity (Day 9): browser locale,
// local timezone. Invalid/missing values never leak raw text to the UI.
function formatDateTime(ts: string | null | undefined): string {
  if (!ts) return 'Date unavailable';
  const t = new Date(ts).getTime();
  if (Number.isNaN(t)) return 'Date unavailable';
  return new Date(t).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

export const RemediationDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { remediation, vulnerabilities, userById, saveRemediation, isLoading, getRemediationDisplay } = useApp();
  const [notes, setNotes] = useState('');
  const [remMsg, setRemMsg] = useState<string | null>(null);
  const [remErr, setRemErr] = useState<string | null>(null);
  const [savingRem, setSavingRem] = useState(false);
  const task = remediation.find((r) => r.id === id);

  if (isLoading && !task) {
    return (
      <div>
        <Link to="/remediation" className="text-sm text-cyan-300 hover:underline">← Back to remediation</Link>
        <Card className="p-10 mt-6 text-center text-slate-400"><LoadingState title="Loading task…" /></Card>
      </div>
    );
  }

  if (!task) {
    return (
      <div>
        <Link to="/remediation" className="text-sm text-cyan-300 hover:underline">← Back to remediation</Link>
        <Card className="p-10 mt-6 text-center text-slate-400">Task not found.</Card>
      </div>
    );
  }

  const vuln = vulnerabilities.find((v) => v.id === task.vulnerabilityId);
  // Live display status, derived from the canonical Vulnerability
  // lifecycle (survives reloads; never a local-only guess).
  const displayStatus = getRemediationDisplay(task);
  const currentStep = flowIndex(displayStatus);

  return (
    <div>
      <Link to="/remediation" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300 mb-6">
        <ArrowLeft className="w-4 h-4" /> Back to remediation
      </Link>
      <div className="mb-8">
        <Mono className="text-sm text-cyan-300 font-semibold">{task.id}</Mono>
        <h1 className="text-2xl font-bold text-white mt-1">
          {vuln ? vuln.title : task.vulnerabilityId}
        </h1>
        {vuln && <p className="text-sm text-slate-400 mt-2">Related vulnerability: <Link to={`/vulnerabilities/${vuln.id}`} className="text-cyan-300 hover:underline font-mono-code">{vuln.id}</Link></p>}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-6 lg:col-span-2 space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <Field label="Status"><p>{displayStatus}</p></Field>
            <Field label="Assigned to"><p>{(() => {
              const u = userById(task.assignedTo);
              if (!u) return '—';
              const full = [u.first_name, u.last_name].filter(Boolean).join(' ').trim();
              return full || u.username || u.email || `User ${u.id}`;
            })()}</p></Field>
            <Field label="Due"><Mono>{task.dueDate || '—'}</Mono></Field>
            <Field label="Updated"><Mono>{formatDateTime(task.updatedAt)}</Mono></Field>
          </div>
          <Field label="Proposed fix"><p>{task.proposedFix}</p></Field>
          <Field label="Remediation notes"><p>{task.notes || '—'}</p></Field>
          <Field label="Verification notes"><p>{task.verificationNotes || '—'}</p></Field>
          <div>
            <label className="block text-xs uppercase tracking-wider text-slate-500 mb-1.5">Add a note</label>
            <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} placeholder="Progress update, evidence, links…" className="w-full px-3.5 py-2.5 bg-[#0d1322] border border-slate-700 rounded-xl text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500" />
            {remMsg && <div className="mt-2 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-sm text-emerald-300">{remMsg}</div>}
            {remErr && <div className="mt-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{remErr}</div>}
            <button
              onClick={async () => {
                setRemMsg(null);
                setRemErr(null);
                if (!notes.trim()) {
                  setRemErr('Enter a note first.');
                  return;
                }
                setSavingRem(true);
                try {
                  await saveRemediation(task.vulnerabilityId, {
                    notes: notes.trim(),
                    proposedFix: task.proposedFix,
                  });
                  setRemMsg('Note saved.');
                  setNotes('');
                } catch (e) {
                  setRemErr(e instanceof Error ? e.message : 'Save failed.');
                } finally {
                  setSavingRem(false);
                }
              }}
              disabled={savingRem}
              className={`${buttonPrimary} justify-center mt-2 !text-xs !px-4 !py-2`}
            >
              {savingRem ? 'Saving…' : 'Save note'}
            </button>
          </div>
        </Card>
        <Card className="p-6">
          <h3 className="text-base font-semibold text-white mb-4">Workflow</h3>
          <div className="space-y-2 mb-5">
            {flow.map((s, i) => (
              <div key={s} className={`flex items-center gap-3 p-2.5 rounded-xl text-sm ${currentStep >= i ? 'bg-cyan-500/10 border border-cyan-500/25 text-cyan-200' : 'text-slate-500'}`}>
                <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold">{i + 1}</span>{s}
              </div>
            ))}
          </div>
          <div className="space-y-2">
            {/* Display only: lifecycle actions (start, remediate, verify,
                close) live canonically on the Vulnerability Details page.
                Notes/work editing above is unaffected. */}
            {displayStatus === 'To Do' && (
              <p className="text-xs text-slate-500">Work not started yet — tracked automatically from the vulnerability lifecycle.</p>
            )}
            {displayStatus === 'In Progress' && (
              <p className="text-xs text-slate-500">Work in progress — tracked automatically from the vulnerability lifecycle.</p>
            )}
            {displayStatus === 'Awaiting Verification' && (
              <p className="text-xs text-slate-500">Work submitted — awaiting analyst verification on the vulnerability.</p>
            )}
            {displayStatus === 'Completed' && (
              <p className="text-xs text-slate-500">Verified and complete — no further actions.</p>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
};
