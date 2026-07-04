import { useQuery, useMutation } from "@tanstack/react-query";
import { apiClient } from "../services/apiClient";
import { Radio, Send, Crosshair, List, ChevronRight, Play, RefreshCw, Layers } from "lucide-react";
import React, { useState, useMemo, useRef } from "react";
import { motion } from "framer-motion";
import { useSecurityStore } from "../store";
import { useFlashlight } from "../hooks/useFlashlight";

export default function ProxyView() {
	const [activeTab, setActiveTab] = useState<"history" | "repeater" | "intruder">("history");
	const [selectedRecordId, setSelectedRecordId] = useState<string | null>(null);
	const [hostFilter, setHostFilter] = useState<string>("");

	const isEcoMode = useSecurityStore((state) => state.isEcoMode);
	const tableContainerRef = useRef<HTMLDivElement>(null);
	const mousePosition = useFlashlight(tableContainerRef);

	// ─── History State ──────────────────────────────────────────────────────────
	const { data: history = [], refetch: refetchHistory, isFetching: isFetchingHistory } = useQuery<any[]>({
		queryKey: ["proxyHistory", hostFilter],
		queryFn: () => apiClient.getProxyHistory(100, 0, hostFilter || undefined),
		refetchInterval: 3000,
	});

	const { data: selectedRecord, isLoading: loadingRecord } = useQuery<any>({
		queryKey: ["proxyRecord", selectedRecordId],
		queryFn: () => apiClient.getProxyRecord(selectedRecordId!),
		enabled: !!selectedRecordId,
	});

	// ─── Repeater State ──────────────────────────────────────────────────────────
	const [repeaterRequestText, setRepeaterRequestText] = useState<string>("");
	const [repeaterResponse, setRepeaterResponse] = useState<any>(null);

	const sendReplayMutation = useMutation({
		mutationFn: ({ recordId, mods }: { recordId: string; mods: any }) => 
			apiClient.replayRequest(recordId, mods),
		onSuccess: (data) => {
			setRepeaterResponse(data.response);
			refetchHistory();
		},
	});

	const handleSendRepeater = () => {
		if (!selectedRecordId) return;
		// Simplistic parse of modifications from edited raw text area
		const lines = repeaterRequestText.split("\n");
		if (lines.length === 0) return;

		const firstLine = lines[0].split(" ");
		const method = firstLine[0] || "GET";
		const path = firstLine[1] || "/";

		// Headers extraction
		const headers: Record<string, string> = {};
		let bodyStartIndex = -1;
		for (let i = 1; i < lines.length; i++) {
			const line = lines[i].trim();
			if (line === "") {
				bodyStartIndex = i + 1;
				break;
			}
			const colonIndex = line.indexOf(":");
			if (colonIndex !== -1) {
				const key = line.slice(0, colonIndex).trim().toLowerCase();
				const val = line.slice(colonIndex + 1).trim();
				headers[key] = val;
			}
		}

		let body_b64 = "";
		if (bodyStartIndex !== -1 && bodyStartIndex < lines.length) {
			const body = lines.slice(bodyStartIndex).join("\n");
			body_b64 = btoa(body);
		}

		const mods: any = {
			method,
			headers,
		};
		if (body_b64) mods.body_b64 = body_b64;

		// Reconstruct full URL if possible
		const host = headers["host"] || selectedRecord?.request?.host;
		const scheme = selectedRecord?.request?.url?.startsWith("https") ? "https" : "http";
		if (host) {
			mods.url = `${scheme}://${host}${path}`;
		} else {
			mods.url = path;
		}

		sendReplayMutation.mutate({ recordId: selectedRecordId, mods });
	};

	const loadIntoRepeater = (rec: any) => {
		if (!rec) return;
		const req = rec.request;
		const parsedUrl = new URL(req.url);
		const pathAndQuery = parsedUrl.pathname + parsedUrl.search;
		
		let raw = `${req.method} ${pathAndQuery} HTTP/1.1\n`;
		Object.entries(req.headers).forEach(([k, v]) => {
			raw += `${k}: ${v}\n`;
		});
		raw += "\n";
		if (req.body_b64) {
			try {
				raw += atob(req.body_b64);
			} catch {
				raw += "[Binary Data]";
			}
		}
		setRepeaterRequestText(raw);
		setRepeaterResponse(null);
		setActiveTab("repeater");
	};

	// ─── Intruder / Fuzzer State ──────────────────────────────────────────────────
	const [fuzzTargetField, setFuzzTargetField] = useState<string>("url");
	const [fuzzPayloadsText, setFuzzPayloadsText] = useState<string>("admin\n' OR '1'='1\n../etc/passwd\n<script>alert(1)</script>");
	const [fuzzResults, setFuzzResults] = useState<any[]>([]);
	const [fuzzSummary, setFuzzSummary] = useState<any>(null);

	const runFuzzMutation = useMutation({
		mutationFn: (config: any) => apiClient.fuzzRequest(config),
		onSuccess: (data) => {
			setFuzzResults(data.results);
			setFuzzSummary({
				total: data.total_payloads,
				completed: data.completed,
				errors: data.errors,
			});
			refetchHistory();
		},
	});

	const handleRunFuzz = () => {
		if (!selectedRecordId) return;
		const payloads = fuzzPayloadsText.split("\n").map(p => p.trim()).filter(p => p !== "");
		runFuzzMutation.mutate({
			record_id: selectedRecordId,
			position_field: fuzzTargetField,
			payloads,
		});
	};

	// Format HTTP Status Code Color
	const getStatusColorClass = (code: number) => {
		if (code >= 200 && code < 300) return "text-emerald-400";
		if (code >= 300 && code < 400) return "text-cyan-400";
		if (code >= 400 && code < 500) return "text-amber-400";
		if (code >= 500) return "text-rose-400";
		return "text-zinc-500";
	};

	const getMethodColorClass = (method: string) => {
		const m = method.toUpperCase();
		if (m === "GET") return "text-cyan-400 border-cyan-500/20 bg-cyan-500/5";
		if (m === "POST") return "text-emerald-400 border-emerald-500/20 bg-emerald-500/5";
		if (m === "PUT") return "text-amber-400 border-amber-500/20 bg-amber-500/5";
		if (m === "DELETE") return "text-rose-400 border-rose-500/20 bg-rose-500/5";
		return "text-zinc-400 border-zinc-500/20 bg-zinc-500/5";
	};

	return (
		<div className="glass-card flex flex-col h-full overflow-hidden shadow-2xl transition-all duration-300 border-white/5 bg-black/20">
			{/* Top Panel Controls */}
			<div className="flex items-center justify-between border-b border-white/5 bg-black/40 px-4 py-2.5 backdrop-blur-md">
				<div className="flex items-center gap-2">
					<Radio className="h-4 w-4 text-fuchsia-400 animate-pulse" />
					<span className="font-bold uppercase tracking-widest text-xs font-mono text-zinc-200">AETHER INTERCEPTING PROXY</span>
				</div>
				<div className="flex border border-white/5 rounded-lg overflow-hidden bg-black/40">
					<button
						onClick={() => setActiveTab("history")}
						className={`px-4 py-1.5 text-[11px] uppercase tracking-wider font-mono font-bold transition-all ${
							activeTab === "history" ? "bg-white/10 text-fuchsia-400" : "text-zinc-400 hover:bg-white/5 hover:text-zinc-200"
						}`}
					>
						History
					</button>
					<button
						onClick={() => setActiveTab("repeater")}
						className={`px-4 py-1.5 text-[11px] uppercase tracking-wider font-mono font-bold border-l border-white/5 transition-all ${
							activeTab === "repeater" ? "bg-white/10 text-fuchsia-400" : "text-zinc-400 hover:bg-white/5 hover:text-zinc-200"
						}`}
					>
						Repeater
					</button>
					<button
						onClick={() => setActiveTab("intruder")}
						className={`px-4 py-1.5 text-[11px] uppercase tracking-wider font-mono font-bold border-l border-white/5 transition-all ${
							activeTab === "intruder" ? "bg-white/10 text-fuchsia-400" : "text-zinc-400 hover:bg-white/5 hover:text-zinc-200"
						}`}
					>
						Intruder
					</button>
				</div>
			</div>

			{/* Main Content Area */}
			<div className="flex-1 flex overflow-hidden">
				{/* HISTORY TAB */}
				{activeTab === "history" && (
					<div className="flex flex-1 flex-col overflow-hidden">
						{/* Filter bar */}
						<div className="flex items-center gap-3 px-4 py-2.5 border-b border-white/5 bg-black/40">
							<input
								type="text"
								placeholder="Filter by Host (e.g. google.com)..."
								value={hostFilter}
								onChange={(e) => setHostFilter(e.target.value)}
								className="flex-1 bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all font-mono"
							/>
							<button
								onClick={() => refetchHistory()}
								disabled={isFetchingHistory}
								className="flex items-center gap-1.5 bg-white/5 hover:bg-white/10 text-zinc-300 border border-white/10 rounded-lg px-3.5 py-1.5 transition-colors disabled:opacity-50 text-xs font-semibold uppercase tracking-wider font-sans"
							>
								<RefreshCw className={`h-3 w-3 ${isFetchingHistory ? "animate-spin" : ""}`} />
								Refresh
							</button>
						</div>

						{/* Table list */}
						<div className="flex-1 overflow-auto custom-scrollbar">
							<table className="w-full text-left border-collapse font-mono text-[11px] leading-relaxed">
								<thead>
									<tr className="bg-black/60 border-b border-white/5 uppercase tracking-widest text-[9px] text-zinc-500 font-bold">
										<th className="px-4 py-3 font-medium">Method</th>
										<th className="px-4 py-3 font-medium">Host</th>
										<th className="px-4 py-3 font-medium">Path</th>
										<th className="px-4 py-3 font-medium text-right">Status</th>
										<th className="px-4 py-3 font-medium text-right">Time (ms)</th>
									</tr>
								</thead>
								<tbody>
									{history.map((record: any, i: number) => (
										<motion.tr
											initial={isEcoMode ? false : { opacity: 0, y: 10 }}
											animate={{ opacity: 1, y: 0 }}
											transition={{ duration: isEcoMode ? 0 : 0.2, delay: isEcoMode ? 0 : Math.min(i * 0.02, 0.5) }}
											key={record.id}
											onClick={() => setSelectedRecordId(record.id)}
											className={`border-b border-white/5 cursor-pointer relative z-10 transition-colors ${
												selectedRecordId === record.id
													? "bg-white/10 text-white shadow-[inset_2px_0_0_0_#a855f7]"
													: "hover:bg-white/[0.02]"
											}`}
										>
											<td className="px-4 py-2.5 font-bold">
												<span className={`inline-block border px-1.5 py-0.5 text-[9px] rounded-md uppercase font-mono leading-none ${getMethodColorClass(record.method)}`}>
													{record.method}
												</span>
											</td>
											<td className="px-4 py-2.5 text-zinc-400 font-medium">{record.host}</td>
											<td className="px-4 py-2.5 max-w-xs truncate text-[#EAEAEA]">{record.path}</td>
											<td className={`px-4 py-2.5 text-right font-bold ${getStatusColorClass(record.response_status)}`}>
												{record.response_status || "ERR"}
											</td>
											<td className="px-4 py-2.5 text-right text-zinc-500">
												{(record.response_time * 1000).toFixed(0)}
											</td>
										</motion.tr>
									))}
								</tbody>
							</table>
						</div>

						{/* Detail / Split View */}
						{selectedRecordId && (
							<div className="h-1/2 border-t border-white/5 flex flex-col bg-black/40 backdrop-blur-md overflow-hidden">
								<div className="flex items-center justify-between px-4 py-2 border-b border-white/5 bg-black/60">
									<div className="flex items-center gap-2">
										<span className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest font-mono">Transaction Details</span>
										{selectedRecord && (
											<span className="text-[10px] bg-black/40 text-fuchsia-400 font-mono px-2 py-0.5 border border-white/10 rounded-md">
												{selectedRecord.id}
											</span>
										)}
									</div>
									<button
										onClick={() => loadIntoRepeater(selectedRecord)}
										disabled={!selectedRecord}
										title={selectedRecord ? "Send selected transaction to Repeater" : "Select a transaction to send to Repeater"}
										className="flex items-center gap-1.5 bg-gradient-to-r from-brand-600 to-fuchsia-600 hover:from-brand-500 hover:to-fuchsia-500 text-white px-3 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all disabled:opacity-50"
									>
										<Send className="h-3.5 w-3.5" />
										Send to Repeater
									</button>
								</div>

								{loadingRecord ? (
									<div className="flex-1 flex items-center justify-center text-xs text-zinc-500 font-mono">
										RETRIEVING PAYLOAD FROM VAULT...
									</div>
								) : selectedRecord ? (
									<div className="flex-1 flex overflow-hidden">
										{/* Request view */}
										<div className="flex-1 border-r border-white/5 flex flex-col overflow-hidden">
											<div className="px-3 py-1 text-[9px] uppercase font-bold text-zinc-500 bg-black/40 border-b border-white/5 font-mono">HTTP Request</div>
											<pre className="flex-1 p-3 overflow-auto font-mono text-xs text-cyan-400 bg-black/20 custom-scrollbar">
												{`${selectedRecord.request.method} ${selectedRecord.request.path} HTTP/1.1\n`}
												{Object.entries(selectedRecord.request.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
												{"\n\n"}
												{selectedRecord.request.body_b64 ? atob(selectedRecord.request.body_b64) : ""}
											</pre>
										</div>
										{/* Response view */}
										<div className="flex-1 flex flex-col overflow-hidden">
											<div className="px-3 py-1 text-[9px] uppercase font-bold text-zinc-500 bg-black/40 border-b border-white/5 font-mono">HTTP Response</div>
											<pre className="flex-1 p-3 overflow-auto font-mono text-xs text-emerald-400 bg-black/20 custom-scrollbar">
												{`HTTP/1.1 ${selectedRecord.response.status_code}\n`}
												{Object.entries(selectedRecord.response.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
												{"\n\n"}
												{selectedRecord.response.body_b64 ? atob(selectedRecord.response.body_b64) : ""}
											</pre>
										</div>
									</div>
								) : null}
							</div>
						)}
					</div>
				)}

				{/* REPEATER TAB */}
				{activeTab === "repeater" && (
					<div className="flex flex-1 overflow-hidden">
						{/* Request Pane */}
						<div className="flex-1 border-r border-white/5 flex flex-col bg-black/20">
							<div className="flex items-center justify-between px-3 py-2 bg-black/40 border-b border-white/5">
								<span className="text-[10px] uppercase font-bold text-zinc-400 tracking-wider font-mono">Raw HTTP Request Editor</span>
								<button
									onClick={handleSendRepeater}
									disabled={sendReplayMutation.isPending || !repeaterRequestText}
									className="flex items-center gap-1.5 bg-gradient-to-r from-brand-600 to-fuchsia-600 hover:from-brand-500 hover:to-fuchsia-500 text-white disabled:opacity-50 px-3.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider transition-all"
								>
									<Play className="h-3.5 w-3.5 fill-white" />
									Send
								</button>
							</div>
							<textarea
								value={repeaterRequestText}
								onChange={(e) => setRepeaterRequestText(e.target.value)}
								className="flex-1 p-3 bg-black/10 text-cyan-300 font-mono text-xs border-0 resize-none outline-none leading-relaxed custom-scrollbar"
								placeholder="Paste or edit raw request here..."
							/>
						</div>

						{/* Response Pane */}
						<div className="flex-1 flex flex-col bg-black/20">
							<div className="px-3 py-2 bg-black/40 border-b border-white/5 text-[10px] uppercase font-bold text-zinc-400 tracking-wider font-mono">
								HTTP Response Console
							</div>
							{sendReplayMutation.isPending ? (
								<div className="flex-1 flex flex-col items-center justify-center text-xs text-zinc-500 font-mono gap-2 animate-pulse">
									<RefreshCw className="h-5 w-5 animate-spin text-fuchsia-400" />
									WAITING FOR HOST TO RESPOND...
								</div>
							) : repeaterResponse ? (
								<pre className="flex-1 p-3 overflow-auto font-mono text-xs text-emerald-400 bg-black/10 leading-relaxed custom-scrollbar">
									{`HTTP/1.1 ${repeaterResponse.status_code}\n`}
									{Object.entries(repeaterResponse.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
									{"\n\n"}
									{repeaterResponse.body_b64 ? atob(repeaterResponse.body_b64) : ""}
								</pre>
							) : (
								<div className="flex-1 flex items-center justify-center text-xs text-zinc-500 font-mono">
									AWAITING REQUEST EMISSION...
								</div>
							)}
						</div>
					</div>
				)}

				{/* INTRUDER TAB */}
				{activeTab === "intruder" && (
					<div className="flex flex-1 flex-col overflow-hidden">
						{/* Configuration bar */}
						<div className="flex items-start gap-4 p-4 border-b border-white/5 bg-black/40">
							<div className="flex-1 flex flex-col gap-2">
								<span className="text-[10px] uppercase font-bold text-zinc-500 font-mono">Fuzzing Parameter Configuration</span>
								<div className="flex items-center gap-2">
									<select
										value={fuzzTargetField}
										onChange={(e) => setFuzzTargetField(e.target.value)}
										className="bg-black/50 border border-white/10 rounded-lg px-3 py-1.5 text-xs text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all font-mono"
									>
										<option value="url">URL Path/Params</option>
										<option value="body">Request Body</option>
										<option value="headers.User-Agent">User-Agent Header</option>
										<option value="headers.Cookie">Cookie Header</option>
										<option value="headers.X-Forwarded-For">X-Forwarded-For Header</option>
									</select>
									<span className="text-[11px] text-zinc-400 font-mono">
										Fuzz targets substitution coordinates configured.
									</span>
								</div>
							</div>
							<div className="flex-1 flex flex-col gap-2">
								<span className="text-[10px] uppercase font-bold text-zinc-500 font-mono">Payload List (One per line)</span>
								<textarea
									value={fuzzPayloadsText}
									onChange={(e) => setFuzzPayloadsText(e.target.value)}
									rows={3}
									className="w-full bg-black/50 border border-white/10 rounded-lg px-3 py-1 text-xs text-cyan-300 font-mono resize-none focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-all"
								/>
							</div>
							<div className="flex flex-col justify-end h-full pt-6">
								<button
									onClick={handleRunFuzz}
									disabled={runFuzzMutation.isPending || !selectedRecordId}
									title={!selectedRecordId ? "Select a transaction from History first" : "Start fuzzing attack"}
									className="flex items-center gap-1.5 bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white disabled:opacity-50 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all"
								>
									{runFuzzMutation.isPending ? (
										<RefreshCw className="h-4 w-4 animate-spin" />
									) : (
										<Crosshair className="h-4 w-4" />
									)}
									{runFuzzMutation.isPending ? "Attacking..." : "Start Attack"}
								</button>
							</div>
						</div>

						{/* Results summary info */}
						{fuzzSummary && (
							<div className="flex items-center gap-4 px-4 py-2.5 border-b border-white/5 bg-black/60 text-xs font-mono">
								<span className="text-zinc-500 uppercase tracking-widest text-[9px] font-bold">Status: Complete</span>
								<span>Total: <strong className="text-zinc-200">{fuzzSummary.total}</strong></span>
								<span>Successful: <strong className="text-emerald-400">{fuzzSummary.completed}</strong></span>
								<span>Errors: <strong className="text-rose-400">{fuzzSummary.errors}</strong></span>
							</div>
						)}

						{/* Fuzzer Results Grid */}
						<div className="flex-1 overflow-auto custom-scrollbar">
							{runFuzzMutation.isPending ? (
								<div className="h-full flex flex-col items-center justify-center text-xs text-zinc-500 font-mono gap-2 animate-pulse">
									<RefreshCw className="h-5 w-5 animate-spin text-amber-500" />
									INTRUDER PAYLOAD ATTACK PIPELINE RUNNING...
								</div>
							) : fuzzResults.length > 0 ? (
								<table className="w-full text-left border-collapse font-mono text-[11px] leading-relaxed">
									<thead>
										<tr className="bg-black/60 border-b border-white/5 uppercase tracking-widest text-[9px] text-zinc-500 font-bold">
											<th className="px-4 py-3 font-medium">#</th>
											<th className="px-4 py-3 font-medium">Payload</th>
											<th className="px-4 py-3 font-medium text-right">Status</th>
											<th className="px-4 py-3 font-medium text-right">Length (Bytes)</th>
											<th className="px-4 py-3 font-medium text-right">Response Time (ms)</th>
										</tr>
									</thead>
									<tbody>
										{fuzzResults.map((res: any) => (
											<tr
												key={res.index}
												className="border-b border-white/5 hover:bg-white/[0.02] transition-colors"
											>
												<td className="px-4 py-2 text-zinc-500">{res.index}</td>
												<td className="px-4 py-2 font-mono text-zinc-200">{res.payload}</td>
												<td className={`px-4 py-2 text-right font-bold ${getStatusColorClass(res.status_code)}`}>
													{res.status_code}
												</td>
												<td className="px-4 py-2 text-right text-zinc-400">{res.response_length}</td>
												<td className="px-4 py-2 text-right text-zinc-500">
													{(res.response_time * 1000).toFixed(0)}
												</td>
											</tr>
										))}
									</tbody>
								</table>
							) : (
								<div className="h-full flex items-center justify-center text-xs text-zinc-500 font-mono">
									AWAITING INTRUDER ORCHESTRATION CONFIGURATION...
								</div>
							)}
						</div>
					</div>
				)}
			</div>
		</div>
	);
}
