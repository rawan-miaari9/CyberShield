import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Server } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, LoadingState, Mono, inputClass } from '../components/ui';

export const AssetsPage: React.FC = () => {
  const { assets, findings, vulnerabilities, isLoading } = useApp();
  const [search, setSearch] = useState('');
  const [type, setType] = useState('all');

  const filtered = assets.filter((a) => {
    const q = search.toLowerCase();
    return (!q || a.name.toLowerCase().includes(q) || a.address.toLowerCase().includes(q)) && (type === 'all' || a.type === type);
  });

  return (
    <div>
      <PageHeader title="Assets" subtitle="Systems and applications covered by vulnerability management. Open an asset to see its findings and vulnerabilities." />
      <Card className="p-5 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search name or address…" className={`${inputClass} md:col-span-2`} />
          <select value={type} onChange={(e) => setType(e.target.value)} className={inputClass}>
            <option value="all">All types</option>
            <option>Web Application</option>
            <option>Server</option>
            <option>API</option>
            <option>Network Device</option>
            <option>Database</option>
            <option>Other</option>
          </select>
        </div>
      </Card>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {filtered.map((a) => {
          const f = findings.filter((x) => x.assetId === a.id).length;
          const v = vulnerabilities.filter((x) => x.assetId === a.id && !['VERIFIED', 'CLOSED'].includes(x.status)).length;
          return (
            <Link key={a.id} to={`/assets/${a.id}`}>
              <Card className="p-6 hover:border-slate-700 transition-colors h-full">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-300"><Server className="w-5 h-5" /></div>
                    <div>
                      <Mono className="text-xs text-cyan-300 font-semibold">{a.id}</Mono>
                      <h3 className="text-base font-semibold text-white">{a.name}</h3>
                    </div>
                  </div>
                  <SeverityBadge severity={a.criticality} />
                </div>
                <p className="text-sm text-slate-400 mb-4">{a.type} · <Mono className="text-[13px]">{a.address}</Mono></p>
                <div className="flex items-center gap-4 text-sm text-slate-400 pt-4 border-t border-slate-800/70">
                  <span>{f} findings</span>
                  <span>{v} open vulns</span>
                  <span className="ml-auto text-xs">Owner: {a.owner}</span>
                </div>
              </Card>
            </Link>
          );
        })}
      </div>
      {isLoading ? <Card className="mt-6"><LoadingState title="Loading assets…" /></Card> : filtered.length === 0 && <Card className="mt-6"><EmptyState title="No assets match" hint="Adjust your search." /></Card>}
    </div>
  );
};
