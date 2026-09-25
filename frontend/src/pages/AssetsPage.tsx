import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Server } from 'lucide-react';
import { useApp } from '../context/SecurityContext';
import { Card, PageHeader, SeverityBadge, EmptyState, LoadingState, Mono, inputClass, buttonPrimary } from '../components/ui';

export const AssetsPage: React.FC = () => {
  const { assets, findings, vulnerabilities, isLoading, isDemoMode, user, createAsset, updateAsset, deleteAsset } = useApp();
  const [search, setSearch] = useState('');
  const [type, setType] = useState('all');
  // Analyst-only writes (backend enforces the same rule — this is UX only).
  const canManageAssets = user?.role === 'Administrator' || user?.role === 'Security Analyst';
  const [showForm, setShowForm] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [assetType, setAssetType] = useState('');
  const [url, setUrl] = useState('');
  const [hostname, setHostname] = useState('');
  const [ipAddress, setIpAddress] = useState('');
  const [criticality, setCriticality] = useState('MEDIUM');
  const [description, setDescription] = useState('');
  const [formErr, setFormErr] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [deleting, setDeleting] = useState<{ id: string; name: string } | null>(null);
  const [deleteErr, setDeleteErr] = useState<string | null>(null);
  const [deletingBusy, setDeletingBusy] = useState(false);

  // Frontend display labels back to backend codes for prefill/submit.
  const typeToCode = (t: string): string => {
    const u = t.toUpperCase();
    if (u === 'WEB APPLICATION') return 'WEB_APP';
    if (u === 'NETWORK DEVICE') return 'NETWORK_DEVICE';
    if (u === 'SERVER' || u === 'OTHER') return u;
    return '';
  };

  const resetForm = () => {
    setEditingId(null);
    setName('');
    setAssetType('');
    setUrl('');
    setHostname('');
    setIpAddress('');
    setCriticality('MEDIUM');
    setDescription('');
    setFormErr(null);
  };

  const openAdd = () => {
    resetForm();
    setShowForm(true);
  };

  const openEdit = (asset: (typeof assets)[number]) => {
    setEditingId(String(asset.id));
    setName(asset.name);
    setAssetType(typeToCode(asset.type));
    setUrl(asset.url || '');
    setHostname(asset.hostname || '');
    setIpAddress(asset.ipAddress || '');
    setCriticality(String(asset.criticality || 'MEDIUM').toUpperCase());
    setDescription(asset.description || '');
    setFormErr(null);
    setShowForm(true);
  };

  const handleSave = async () => {
    if (saving) return;
    setFormErr(null);
    if (!name.trim()) {
      setFormErr('Name is required.');
      return;
    }
    if (!assetType) {
      setFormErr('Asset type is required.');
      return;
    }
    setSaving(true);
    try {
      const input = {
        name: name.trim(),
        asset_type: assetType,
        hostname: hostname.trim(),
        ip_address: ipAddress.trim() || null,
        url: url.trim(),
        criticality,
        description: description.trim(),
      };
      if (editingId) await updateAsset(editingId, input);
      else await createAsset(input);
      resetForm();
      setShowForm(false);
    } catch (e) {
      setFormErr(e instanceof Error ? e.message : 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleting || deletingBusy) return;
    setDeleteErr(null);
    setDeletingBusy(true);
    try {
      await deleteAsset(deleting.id);
      setDeleting(null);
    } catch (e) {
      // Protected assets stay put with the backend's 409 explanation.
      setDeleteErr(e instanceof Error ? e.message : 'Deletion failed.');
    } finally {
      setDeletingBusy(false);
    }
  };

  const filtered = assets.filter((a) => {
    const q = search.toLowerCase();
    return (!q || a.name.toLowerCase().includes(q) || a.address.toLowerCase().includes(q)) && (type === 'all' || a.type === type);
  });

  // Day 9 Task 6: per-asset counts come from backend aggregates
  // (finding_count / open_vulnerability_count), never from the paginated
  // findings page. In demo mode the aggregates are absent and the local
  // mock collection is complete, so filtering it is truthful there.
  const findingCountFor = (a: (typeof assets)[number]) =>
    typeof a.findingCount === 'number'
      ? a.findingCount
      : isDemoMode
        ? findings.filter((x) => x.assetId === a.id).length
        : 0;
  const openVulnCountFor = (a: (typeof assets)[number]) => {
    if (typeof a.openVulnerabilityCount === 'number') return a.openVulnerabilityCount;
    const assetOf = (v: (typeof vulnerabilities)[number]) => {
      if (v.assetId) return v.assetId;
      const f = findings.find((x) => x.id === v.findingId);
      return f ? f.assetId : '';
    };
    return vulnerabilities.filter((x) => String(assetOf(x)) === String(a.id) && !['VERIFIED', 'CLOSED'].includes(x.status)).length;
  };

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle="Systems and applications covered by vulnerability management. Open an asset to see its findings and vulnerabilities."
        action={canManageAssets ? (
          <button onClick={openAdd} className={buttonPrimary}>
            Add Asset
          </button>
        ) : undefined}
      />
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
          const f = findingCountFor(a);
          const v = openVulnCountFor(a);
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
                {canManageAssets && (
                  <div className="flex gap-2 mt-4" onClick={(e) => { e.preventDefault(); e.stopPropagation(); }}>
                    <button
                      onClick={() => openEdit(a)}
                      className="text-xs px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => { setDeleteErr(null); setDeleting({ id: String(a.id), name: a.name }); }}
                      className="text-xs px-3 py-1.5 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/25 text-rose-300 transition-colors"
                    >
                      Delete
                    </button>
                  </div>
                )}
              </Card>
            </Link>
          );
        })}
      </div>
      {isLoading ? <Card className="mt-6"><LoadingState title="Loading assets…" /></Card> : filtered.length === 0 && <Card className="mt-6"><EmptyState title="No assets match" hint="Adjust your search." /></Card>}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => { if (!saving) setShowForm(false); }}>
          <Card className="p-6 w-full max-w-lg" >
            <div onClick={(e) => e.stopPropagation()}>
              <h3 className="text-base font-semibold text-white mb-4">{editingId ? 'Edit Asset' : 'Add Asset'}</h3>
              {formErr && <div className="mb-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{formErr}</div>}
              <div className="space-y-3">
                <div>
                  <label className="block text-sm text-slate-300 mb-1.5">Name *</label>
                  <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Customer Portal" className={inputClass} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm text-slate-300 mb-1.5">Asset Type *</label>
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value)} className={inputClass}>
                      <option value="">Select type…</option>
                      <option value="WEB_APP">Web Application</option>
                      <option value="SERVER">Server</option>
                      <option value="NETWORK_DEVICE">Network Device</option>
                      <option value="OTHER">Other</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-slate-300 mb-1.5">Criticality</label>
                    <select value={criticality} onChange={(e) => setCriticality(e.target.value)} className={inputClass}>
                      <option value="LOW">Low</option>
                      <option value="MEDIUM">Medium</option>
                      <option value="HIGH">High</option>
                      <option value="CRITICAL">Critical</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-slate-300 mb-1.5">URL</label>
                  <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" className={inputClass} />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm text-slate-300 mb-1.5">Hostname</label>
                    <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="host.example.com" className={inputClass} />
                  </div>
                  <div>
                    <label className="block text-sm text-slate-300 mb-1.5">IP Address</label>
                    <input value={ipAddress} onChange={(e) => setIpAddress(e.target.value)} placeholder="192.0.2.10" className={inputClass} />
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-slate-300 mb-1.5">Description</label>
                  <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={2} placeholder="What this asset is…" className={inputClass} />
                </div>
              </div>
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setShowForm(false)} disabled={saving} className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 transition-colors">
                  Cancel
                </button>
                <button onClick={handleSave} disabled={saving} className={`${buttonPrimary} !text-sm`}>
                  {saving ? 'Saving…' : editingId ? 'Save Changes' : 'Add Asset'}
                </button>
              </div>
            </div>
          </Card>
        </div>
      )}
      {deleting && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={() => { if (!deletingBusy) setDeleting(null); }}>
          <Card className="p-6 w-full max-w-md">
            <div onClick={(e) => e.stopPropagation()}>
              <h3 className="text-base font-semibold text-white mb-2">Delete asset?</h3>
              <p className="text-sm text-slate-400 leading-relaxed">
                This will permanently delete <span className="text-slate-200 font-medium">{deleting.name}</span> (ID {deleting.id}). This cannot be undone.
              </p>
              {deleteErr && <div className="mt-4 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-sm text-rose-300">{deleteErr}</div>}
              <div className="flex justify-end gap-3 mt-5">
                <button onClick={() => setDeleting(null)} disabled={deletingBusy} className="px-4 py-2 rounded-lg bg-slate-800 text-sm text-slate-100 hover:bg-slate-700 disabled:opacity-50 transition-colors">
                  Cancel
                </button>
                <button onClick={handleDelete} disabled={deletingBusy} className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-sm text-white disabled:opacity-50 transition-colors">
                  {deletingBusy ? 'Deleting…' : 'Delete'}
                </button>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
};
