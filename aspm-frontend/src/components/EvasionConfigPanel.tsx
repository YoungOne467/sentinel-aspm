import React, { useState, useEffect } from "react";
import { Cpu, Shield, Plus, Trash2, Save, Sparkles, Loader2, Check } from "lucide-react";
import { apiClient } from "../services/apiClient";
import { Button } from "./ui/button";

export default function EvasionConfigPanel() {
	const [customHeaders, setCustomHeaders] = useState<Record<string, string>>({});
	const [sqliStrategy, setSqliStrategy] = useState("space_to_comment");
	const [xssStrategy, setXssStrategy] = useState("default_polyglot");
	const [lfiStrategy, setLfiStrategy] = useState("double_encoding");

	const [newHeaderKey, setNewHeaderKey] = useState("");
	const [newHeaderVal, setNewHeaderVal] = useState("");

	const [loading, setLoading] = useState(false);
	const [saving, setSaving] = useState(false);
	const [saveSuccess, setSaveSuccess] = useState(false);
	const [saveError, setSaveError] = useState<string | null>(null);

	useEffect(() => {
		const loadSettings = async () => {
			setLoading(true);
			try {
				const data = await apiClient.getEvasionSettings();
				setCustomHeaders(data.custom_headers || {});
				setSqliStrategy(data.sqli_strategy || "space_to_comment");
				setXssStrategy(data.xss_strategy || "default_polyglot");
				setLfiStrategy(data.lfi_strategy || "double_encoding");
			} catch (e) {
				console.error("Failed to load evasion settings", e);
			} finally {
				setLoading(false);
			}
		};
		loadSettings();
	}, []);

	const handleAddHeader = (e: React.FormEvent) => {
		e.preventDefault();
		if (!newHeaderKey.trim() || !newHeaderVal.trim()) return;
		setCustomHeaders({
			...customHeaders,
			[newHeaderKey.trim()]: newHeaderVal.trim(),
		});
		setNewHeaderKey("");
		setNewHeaderVal("");
	};

	const handleDeleteHeader = (key: string) => {
		const updated = { ...customHeaders };
		delete updated[key];
		setCustomHeaders(updated);
	};

	const handleSaveSettings = async () => {
		setSaving(true);
		setSaveSuccess(false);
		setSaveError(null);
		try {
			await apiClient.updateEvasionSettings({
				custom_headers: customHeaders,
				sqli_strategy: sqliStrategy,
				xss_strategy: xssStrategy,
				lfi_strategy: lfiStrategy,
			});
			setSaveSuccess(true);
			setTimeout(() => setSaveSuccess(false), 3000);
		} catch (e) {
			console.error("Failed to save evasion settings", e);
			setSaveError("Failed to save evasion policies.");
			setTimeout(() => setSaveError(null), 5000);
		} finally {
			setSaving(false);
		}
	};

	if (loading) {
		return (
			<div className="flex flex-col items-center justify-center h-64 font-mono text-xs text-zinc-500">
				<Loader2 className="w-6 h-6 text-fuchsia-500 animate-spin mb-2" />
				Syncing evasion profile settings...
			</div>
		);
	}

	return (
		<div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
			{/* Left Column: Headers & Metadata */}
			<div className="lg:col-span-2 space-y-4">
				<div className="glass-card p-5 shadow-xl space-y-4">
					<div className="flex items-center gap-2 border-b border-white/5 pb-3">
						<Shield className="w-5 h-5 text-fuchsia-400" />
						<div>
							<h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider font-mono">
								Dynamic WAF Evasion Headers
							</h3>
							<p className="text-[10px] text-zinc-500 font-sans mt-0.5 leading-normal">
								Configure HTTP request headers injected into scanner connections to bypass source-IP blocks or request origin boundaries.
							</p>
						</div>
					</div>

					{/* Add Header form */}
					<form onSubmit={handleAddHeader} className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
						<div className="space-y-1">
							<span className="text-[9px] text-zinc-500 uppercase font-bold block">
								Header Key
							</span>
							<input
								type="text"
								placeholder="e.g. X-Forwarded-For"
								value={newHeaderKey}
								onChange={(e) => setNewHeaderKey(e.target.value)}
								className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 h-8 font-mono"
							/>
						</div>
						<div className="space-y-1">
							<span className="text-[9px] text-zinc-500 uppercase font-bold block">
								Header Value
							</span>
							<input
								type="text"
								placeholder="e.g. 127.0.0.1"
								value={newHeaderVal}
								onChange={(e) => setNewHeaderVal(e.target.value)}
								className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 h-8 font-mono"
							/>
						</div>
						<div className="flex items-end">
							<Button
								type="submit"
								className="w-full h-8 flex items-center justify-center gap-1.5 bg-brand-600/10 text-brand-400 border border-brand-500/20 hover:bg-brand-500/20 font-sans text-[11px] uppercase font-semibold tracking-wider transition-all"
							>
								<Plus className="w-3.5 h-3.5" />
								Add Header
							</Button>
						</div>
					</form>

					{/* Active Headers table */}
					<div className="border border-white/5 rounded-xl overflow-hidden bg-black/20">
						<table className="w-full font-mono text-xs text-left">
							<thead className="bg-black/40 text-zinc-500 text-[9px] uppercase tracking-widest border-b border-white/5">
								<tr>
									<th className="p-3">Header Name</th>
									<th className="p-3">Injected Value</th>
									<th className="p-3 text-right" />
								</tr>
							</thead>
							<tbody className="divide-y divide-white/5 text-zinc-300">
								{Object.keys(customHeaders).length === 0 ? (
									<tr>
										<td colSpan={3} className="p-4 text-center text-zinc-600 italic">
											No custom headers registered.
										</td>
									</tr>
								) : (
									Object.entries(customHeaders).map(([key, val]) => (
										<tr key={key} className="hover:bg-white/[0.02] transition-colors">
											<td className="p-3 text-zinc-200 font-bold">{key}</td>
											<td className="p-3 text-fuchsia-400 font-semibold">{val}</td>
											<td className="p-3 text-right pr-4">
												<button
													type="button"
													onClick={() => handleDeleteHeader(key)}
													className="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
													title="Remove Header"
													aria-label={`Remove Header ${key}`}
												>
													<Trash2 className="w-3.5 h-3.5" />
												</button>
											</td>
										</tr>
									))
								)}
							</tbody>
						</table>
					</div>
				</div>
			</div>

			{/* Right Column: Evasion Strategies */}
			<div className="space-y-4">
				<div className="glass-card p-5 shadow-xl space-y-5 flex flex-col justify-between h-full">
					<div className="space-y-4">
						<div className="flex items-center gap-2 border-b border-white/5 pb-3">
							<Cpu className="w-5 h-5 text-brand-400" />
							<div>
								<h3 className="text-xs font-bold text-zinc-100 uppercase tracking-wider font-mono">
									Payload Obfuscation
								</h3>
								<p className="text-[10px] text-zinc-500 font-sans mt-0.5 leading-normal">
									Tune active scanner strategy variants designed to slip past local WAF signature checks.
								</p>
							</div>
						</div>

						{/* SQLi strategy */}
						<div className="space-y-1.5">
							<span className="text-[10px] font-bold text-zinc-400 uppercase font-mono tracking-wide block">
								SQL Injection Evasion
							</span>
							<select
								value={sqliStrategy}
								onChange={(e) => setSqliStrategy(e.target.value)}
								className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 text-xs font-mono h-9"
							>
								<option value="space_to_comment">Space to Comments (/**/)</option>
								<option value="mixed_case">Mixed Case Keywords (SeLeCt)</option>
								<option value="hex_encode">Hex Encoding</option>
								<option value="none">No Obfuscation (Plain)</option>
							</select>
						</div>

						{/* XSS strategy */}
						<div className="space-y-1.5">
							<span className="text-[10px] font-bold text-zinc-400 uppercase font-mono tracking-wide block">
								Cross-Site Scripting (XSS)
							</span>
							<select
								value={xssStrategy}
								onChange={(e) => setXssStrategy(e.target.value)}
								className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 text-xs font-mono h-9"
							>
								<option value="default_polyglot">Custom Polyglot Outbreak</option>
								<option value="html_entity">Double URL Entity Obfuscation</option>
								<option value="none">No Obfuscation (Plain)</option>
							</select>
						</div>

						{/* LFI strategy */}
						<div className="space-y-1.5">
							<span className="text-[10px] font-bold text-zinc-400 uppercase font-mono tracking-wide block">
								Path Traversal / LFI
							</span>
							<select
								value={lfiStrategy}
								onChange={(e) => setLfiStrategy(e.target.value)}
								className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 text-xs font-mono h-9"
							>
								<option value="double_encoding">Double URL Slash (%252f)</option>
								<option value="null_byte">Null Byte Truncation (%00)</option>
								<option value="none">No Obfuscation (Plain)</option>
							</select>
						</div>
					</div>

					<div className="pt-4 border-t border-white/5 flex items-center justify-between">
						{saveSuccess ? (
							<div className="flex items-center gap-1.5 text-emerald-400 text-[10px] font-mono font-bold uppercase tracking-wider">
								<Check className="w-4 h-4 text-emerald-400 animate-bounce" />
								Settings Saved
							</div>
						) : saveError ? (
							<div className="flex items-center gap-1.5 text-rose-400 text-[10px] font-mono font-bold uppercase tracking-wider">
								<span className="w-4 h-4 flex items-center justify-center font-bold">!</span>
								{saveError}
							</div>
						) : (
							<div className="text-[9px] text-zinc-600 font-mono italic">
								Unsaved changes pending.
							</div>
						)}

						<Button
							onClick={handleSaveSettings}
							disabled={saving}
							className="h-9 px-4 flex items-center justify-center gap-1.5 bg-gradient-to-r from-brand-600 to-fuchsia-600 hover:from-brand-500 hover:to-fuchsia-500 text-white font-sans text-xs uppercase font-bold tracking-wider hover:opacity-90 shadow-md shadow-brand-500/10"
						>
							{saving ? (
								<>
									<Loader2 className="w-4 h-4 animate-spin text-white" />
									Saving...
								</>
							) : (
								<>
									<Save className="w-4 h-4 text-white" />
									Save Evasion Policies
								</>
							)}
						</Button>
					</div>
				</div>
			</div>
		</div>
	);
}
