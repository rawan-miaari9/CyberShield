import React, { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, SeverityBadge, Field, Mono, buttonPrimary, buttonGhost } from '../components/ui';

export const FindingDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { findings, assetById, updateFindingStatus, promoteFinding } = useApp();
  const [msg, setMsg] = useState<string | null>(null);
  const finding = findings.find((f) => f.id === id);

  if (!finding) {
    return (
      <div>
        <Link to="/findings" className="text-sm text-cyan-300 hover:underline">← Back to findings</Link>
        <Card className="p-10 mt-6 text-center text-slate-400">Finding not found.</Card>
      </div>
    );
  }

  const asset = assetById(finding.assetId);

  const handlePromote = () => {
    const newId = promoteFinding(finding.id);
    setMsg(`Promoted to ${newId}.`);
    setTimeout(() => navigate(`/vulnerabilities/${newId}`), 900);
  };

  return (
    <div>
      <Link to="/findings" className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-cyan-300 mb-6">
        <ArrowLeft className="w-4 h-4" /> Back to findings
      </Link>
      {msg && <div className="mb-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-sm text-emerald-300">{msg}</div>}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4 mb-8">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Mono className="text-sm text-cyan-300 font-semibold">{finding.id}</Mono>
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-200 border border-slate-700">{finding.status}</span>
          </div>
          <h1 className="text-2xl font-bold text-white">{finding.title}</h1>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="p-6 lg:col-span-2 space-y-6">
          <Field label="Description"><p>{finding.description}</p></Field>
          <Field label="Evidence"><Mono className="text-[13px] text-slate-300 block bg-[#05080e] border border-slate-800 rounded-xl p-4 leading-relaxed">{finding.evidence}</Mono></Field>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            <Field label="CVSS">{finding.cvssScore !== null ? <Mono>{finding.cvssScore.toFixed(1)}</Mono> : '—'}</Field>
            <Field label="CWE">{finding.cwe ? <Mono>{finding.cwe}</Mono> : '—'}</Field>
            <Field label="Alert ref"><Mono>{finding.alertRef}</Mono></Field>
            <Field label="Imported"><Mono>{finding.importedAt}</Mono></Field>
          </div>
        </Card>
        <div className="space-y-6">
          <Card className="p-6 space-y-4">
            <Field label="Scanner source"><p>{finding.scannerSource}</p></Field>
            <Field label="Affected asset">
              {asset ? <Link to={`/assets/${asset.id}`} className="text-cyan-300 hover:underline">{asset.name}</Link> : finding.assetId}
            </Field>
            <Field label="Status">
              <div className="flex flex-wrap gap-2 mt-1">
                {(['New', 'Reviewed', 'Ignored'] as const).map((s) => (
                  <button key={s} onClick={() => updateFindingStatus(finding.id, s)} className={`${buttonGhost} !px-3 !py-1.5 !text-xs ${finding.status === s ? '!border-cyan-500/50 !text-cyan-300' : ''}`}>{s}</button>
                ))}
              </div>
            </Field>
          </Card>
          <Card className="p-6">
            <h3 className="text-base font-semibold text-white mb-2">Analyst review</h3>
            <p className="text-sm text-slate-400 mb-4 leading-relaxed">If this finding is valid, promote it into a managed vulnerability with risk scoring and assignment.</p>
            <button onClick={handlePromote} disabled={finding.status === 'Promoted'} className={`${buttonPrimary} w-full justify-center`}>
              {finding.status === 'Promoted' ? 'Already promoted' : 'Promote to vulnerability'}
            </button>
          </Card>
        </div>
      </div>
    </div>
  );
};
