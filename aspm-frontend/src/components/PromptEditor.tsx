import React, { useState, useEffect } from "react";
import {
	X,
	Play,
	Download,
	Copy,
	Check,
	Loader2,
	AlertCircle,
	FileText,
	Terminal,
	HelpCircle,
	Zap,
	Shield,
	Database,
	Layers,
	Activity,
	TerminalSquare,
} from "lucide-react";
import { fetchWithAuth } from "../apiClient";
import { API_BASE_URL } from "../config";

interface PromptEditorProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	findingId: string | null;
}

interface ExecutableAction {
	action_type: string;
	title: string;
	command?: string;
	patch_content?: string;
	target_file?: string;
	target_url?: string;
	method?: string;
	headers?: Record<string, string>;
	risk_level: "safe" | "moderate" | "dangerous";
}

interface BlastRadiusAssessment {
	scope_compliant: boolean;
	syntax_valid: boolean;
	targets_production: boolean;
	estimated_impact: "none" | "read_only" | "state_changing" | "destructive";
	warnings: string[];
	safety_score: number;
}

interface AnalysisResult {
	summary: string;
	vulnerability_confirmed: boolean;
	risk_score: number;
	confidence: number;
	cve_references: string[];
	remediation_steps: string[];
	actions: ExecutableAction[];
	blast_radius: BlastRadiusAssessment[];
}

interface ModelSpec {
	provider: string;
	display_name: string;
	cost_tier: string;
	context_window: number;
	max_output_tokens: number;
	supports_json_mode: boolean;
}

interface RoutingMatrixItem {
	default_chain: { provider: string; model: string; priority: number }[];
	user_override: { provider: string; model: string } | null;
	cost_ceiling: string;
}

interface RoutingConfig {
	routing_matrix: Record<string, RoutingMatrixItem>;
	model_catalog: Record<string, ModelSpec>;
	providers: string[];
}

export default function PromptEditor({
	open,
	onOpenChange,
	findingId,
}: PromptEditorProps) {
	const [loadingPrompt, setLoadingPrompt] = useState(false);
	const [executing, setExecuting] = useState(false);
	const [promptText, setPromptText] = useState("");
	const [provider, setProvider] = useState("");
	const [targetName, setTargetName] = useState("");
	
	const [routingConfig, setRoutingConfig] = useState<RoutingConfig | null>(null);
	const [selectedTaskType, setSelectedTaskType] = useState<string>("exploit_analysis");
	const [overrideProvider, setOverrideProvider] = useState<string>("");
	const [overrideModel, setOverrideModel] = useState<string>("");
	const [forceOverride, setForceOverride] = useState<boolean>(false);

	const [result, setResult] = useState<AnalysisResult | null>(null);
	const [error, setError] = useState<string | null>(null);
	
	const [copiedActionIdx, setCopiedActionIdx] = useState<number | null>(null);
	
	const [executionLogs, setExecutionLogs] = useState<Record<number, {
		stdout: string;
		stderr: string;
		exit_code: number;
		running: boolean;
		error?: string;
	}>>({});

	useEffect(() => {
		if (open) {
			loadRoutingConfig();
			if (findingId) {
				loadCompiledPrompt();
			}
		}
	}, [open, findingId]);

	const loadRoutingConfig = async () => {
		try {
			const resp = await fetchWithAuth(`${API_BASE_URL}/api/ai/routing-config`);
			if (resp.ok) {
				const data = await resp.json();
				setRoutingConfig(data);
			}
		} catch (err) {
			console.error("Failed to load routing configuration", err);
		}
	};

	const loadCompiledPrompt = async () => {
		try {
			setLoadingPrompt(true);
			setError(null);
			setResult(null);
			setExecutionLogs({});
			const resp = await fetchWithAuth(`${API_BASE_URL}/api/ai/compile-prompt/${findingId}`);
			if (!resp.ok) throw new Error("Failed to compile prompt from database telemetry");
			const data = await resp.json();
			setPromptText(data.prompt);
			setProvider(data.provider);
			setTargetName(data.target);
		} catch (err: any) {
			setError(err.message || "Failed to contact compilation endpoint");
		} finally {
			setLoadingPrompt(false);
		}
	};

	const handleExecute = async () => {
		try {
			setExecuting(true);
			setError(null);
			setResult(null);
			setExecutionLogs({});
			
			const payload: Record<string, any> = {
				prompt: promptText,
				task_type: selectedTaskType,
				force_override: forceOverride,
			};
			if (overrideProvider) payload.provider = overrideProvider;
			if (overrideModel) payload.model = overrideModel;

			const resp = await fetchWithAuth(`${API_BASE_URL}/api/ai/execute-custom-prompt`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});
			if (!resp.ok) {
				const errorData = await resp.json().catch(() => ({}));
				throw new Error(errorData.detail || "AI Engine rejected custom prompt execution");
			}
			const data = await resp.json();
			setResult(data);
		} catch (err: any) {
			setError(err.message || "Execution matrix returned a failure");
		} finally {
			setExecuting(false);
		}
	};

	const executeActionAdHoc = async (action: ExecutableAction, idx: number) => {
		setExecutionLogs((prev) => ({
			...prev,
			[idx]: { stdout: "", stderr: "", exit_code: 0, running: true },
		}));

		try {
			const resp = await fetchWithAuth(`${API_BASE_URL}/api/ai/execute/ad-hoc`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(action),
			});
			
			if (!resp.ok) {
				const errorData = await resp.json().catch(() => ({}));
				throw new Error(errorData.detail || "Execution engine rejected request");
			}
			
			const data = await resp.json();
			setExecutionLogs((prev) => ({
				...prev,
				[idx]: {
					stdout: data.stdout || "",
					stderr: data.stderr || "",
					exit_code: data.exit_code,
					running: false,
				},
			}));
		} catch (err: any) {
			setExecutionLogs((prev) => ({
				...prev,
				[idx]: {
					stdout: "",
					stderr: "",
					exit_code: -1,
					running: false,
					error: err.message || "Failed to execute payload inside sandbox container",
				},
			}));
		}
	};

	const downloadPatch = (action: ExecutableAction) => {
		if (!action.patch_content) return;
		const blob = new Blob([action.patch_content], { type: "text/plain" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = action.target_file || "remediation.patch";
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
	};

	const copyCommand = (command: string, idx: number) => {
		navigator.clipboard.writeText(command);
		setCopiedActionIdx(idx);
		setTimeout(() => setCopiedActionIdx(null), 2000);
	};

	if (!open) return null;

	const selectedTaskConfig = routingConfig?.routing_matrix[selectedTaskType];

	return (
		<div className="fixed inset-0 z-50 flex justify-end">
			{/* Backdrop */}
			<div 
				className="absolute inset-0 bg-black/70 backdrop-blur-sm"
				onClick={() => onOpenChange(false)}
			/>

			{/* Slide-out Workspace Panel */}
			<div className="relative w-full max-w-6xl h-full bg-[#050505] border-l border-white/5 flex flex-col shadow-2xl z-10 font-mono">
				
				{/* Drawer Header */}
				<div className="p-4 border-b border-white/5 flex items-center justify-between bg-zinc-950/40 backdrop-blur-xl">
					<div className="flex items-center gap-3">
						<div className="w-8 h-8 rounded-lg bg-fuchsia-500/10 border border-fuchsia-500/30 flex items-center justify-center text-fuchsia-400">
							<Zap className="w-4 h-4 animate-pulse" />
						</div>
						<div>
							<h3 className="text-xs font-bold text-zinc-100 uppercase tracking-widest">Tactical Prompt Inspector</h3>
							<p className="text-[9px] text-zinc-500 uppercase mt-0.5">Triage Matrix Exploit Analyzer ({provider})</p>
						</div>
					</div>
					<button
						type="button"
						onClick={() => onOpenChange(false)}
						className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-white/5 transition-colors"
					>
						<X className="w-4 h-4" />
					</button>
				</div>

				{/* Two Column Layout Split Pane */}
				<div className="flex-1 flex overflow-hidden min-h-0">
					
					{/* Left Workspace Panel: Input prompt & Output Results */}
					<div className="flex-1 overflow-y-auto p-6 space-y-6 custom-scrollbar border-r border-white/5">
						{loadingPrompt ? (
							<div className="flex flex-col items-center justify-center py-20 gap-3 text-zinc-500">
								<Loader2 className="w-6 h-6 animate-spin text-fuchsia-400" />
								<span className="text-[10px] tracking-wider uppercase">Compiling context matrix...</span>
							</div>
						) : error ? (
							<div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg flex items-start gap-3 text-xs">
								<AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
								<div>
									<span className="font-bold">VERDICT FAILURE:</span> {error}
								</div>
							</div>
						) : (
							<div className="space-y-6">
								{/* Prompt Editor */}
								<div className="space-y-2">
									<div className="flex justify-between items-center text-[10px] text-zinc-500 uppercase tracking-wider font-bold">
										<span>Target Context: {targetName}</span>
										<span className="text-fuchsia-400">Editable Live Context Prompt</span>
									</div>
									<textarea
										rows={14}
										value={promptText}
										onChange={(e) => setPromptText(e.target.value)}
										className="w-full text-xs font-mono bg-black border border-white/5 focus:border-fuchsia-500/30 rounded-lg p-4 text-zinc-300 outline-none transition-colors resize-none leading-relaxed"
									/>
									<div className="flex justify-between items-center">
										<p className="text-[9px] text-zinc-600 uppercase">
											Modify targets, parameters, or instructions to redirect verification flow.
										</p>
										<button
											type="button"
											onClick={handleExecute}
											disabled={executing}
											className="px-5 py-2.5 bg-fuchsia-600 hover:bg-fuchsia-700 text-white rounded-lg text-xs uppercase tracking-wider font-bold flex items-center gap-2 disabled:opacity-50 transition-colors shadow-lg shadow-fuchsia-500/10"
										>
											{executing ? (
												<>
													<Loader2 className="w-3.5 h-3.5 animate-spin" />
													<span>TRIAGING MATRIX...</span>
												</>
											) : (
												<>
													<Play className="w-3.5 h-3.5" />
													<span>RUN ANALYSIS PIPELINE</span>
												</>
											)}
										</button>
									</div>
								</div>

								{/* Structured Output Result */}
								{result && (
									<div className="space-y-6 border-t border-white/5 pt-6">
										<h4 className="text-xs font-bold text-zinc-300 uppercase tracking-widest flex items-center gap-2">
											<FileText className="w-4 h-4 text-fuchsia-400" />
											AI Exploit Triage Verdict
										</h4>

										<div className="grid grid-cols-3 gap-3">
											<div className="p-3 bg-zinc-950/40 border border-white/5 rounded-lg flex flex-col justify-center">
												<span className="text-[9px] text-zinc-500 uppercase">Vulnerability Status</span>
												<span className={`text-xs font-bold uppercase mt-1 ${result.vulnerability_confirmed ? "text-rose-400" : "text-emerald-400"}`}>
													{result.vulnerability_confirmed ? "CONFIRMED EXPLOITABLE" : "FALSE POSITIVE"}
												</span>
											</div>
											<div className="p-3 bg-zinc-950/40 border border-white/5 rounded-lg flex flex-col justify-center">
												<span className="text-[9px] text-zinc-500 uppercase">Calculated Risk Score</span>
												<span className={`text-xs font-bold mt-1 ${result.risk_score >= 7 ? "text-rose-400" : result.risk_score >= 4 ? "text-orange-400" : "text-yellow-400"}`}>
													{result.risk_score.toFixed(1)} / 10.0
												</span>
											</div>
											<div className="p-3 bg-zinc-950/40 border border-white/5 rounded-lg flex flex-col justify-center">
												<span className="text-[9px] text-zinc-500 uppercase">AI confidence</span>
												<span className="text-xs font-bold text-zinc-200 mt-1">
													{(result.confidence * 100).toFixed(0)}%
												</span>
											</div>
										</div>

										<div className="space-y-1">
											<span className="text-[10px] text-zinc-500 uppercase">Analysis Executive Summary</span>
											<p className="text-xs text-zinc-400 leading-relaxed bg-zinc-950/20 p-3 rounded-lg border border-white/5 font-sans">
												{result.summary}
											</p>
										</div>

										{result.cve_references && result.cve_references.length > 0 && (
											<div className="space-y-1">
												<span className="text-[10px] text-zinc-500 uppercase">Related CVE References</span>
												<div className="flex flex-wrap gap-1.5 mt-1">
													{result.cve_references.map((cve, idx) => (
														<span key={idx} className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[9px] font-bold">
															{cve}
														</span>
													))}
												</div>
											</div>
										)}

										{result.remediation_steps.length > 0 && (
											<div className="space-y-1.5">
												<span className="text-[10px] text-zinc-500 uppercase">Remediation Blueprint</span>
												<ul className="list-disc pl-5 text-xs text-zinc-400 space-y-1 font-sans">
													{result.remediation_steps.map((step, idx) => (
														<li key={idx}>{step}</li>
													))}
												</ul>
											</div>
										)}

										{/* Executable Actions Matrix */}
										{result.actions.length > 0 && (
											<div className="space-y-4">
												<span className="text-[10px] text-zinc-500 uppercase font-bold tracking-wider">Executable Action Matrix</span>
												<div className="space-y-4">
													{result.actions.map((act, idx) => {
														const safety = result.blast_radius?.[idx];
														const log = executionLogs[idx];

														return (
															<div key={idx} className="p-4 bg-zinc-950/60 border border-white/5 rounded-xl space-y-4">
																
																{/* Action Title & Run Controls */}
																<div className="flex justify-between items-start gap-4">
																	<div>
																		<h5 className="text-xs font-bold text-zinc-200">{act.title}</h5>
																		<span className={`text-[8px] px-1 py-0.5 rounded font-bold uppercase tracking-wider ${
																			act.risk_level === "dangerous" ? "text-rose-400 bg-rose-500/10 border border-rose-500/20" :
																			act.risk_level === "moderate" ? "text-orange-400 bg-orange-500/10 border border-orange-500/20" :
																			"text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"
																		}`}>
																			{act.action_type} • {act.risk_level} risk
																		</span>
																	</div>
																	
																	<div className="flex gap-2">
																		{act.command && (
																			<>
																				<button
																					type="button"
																					onClick={() => copyCommand(act.command!, idx)}
																					className="p-2 bg-white/5 rounded hover:bg-white/10 text-zinc-400 hover:text-white border border-white/5"
																					title="Copy Command"
																				>
																					{copiedActionIdx === idx ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
																				</button>
																				<button
																					type="button"
																					onClick={() => executeActionAdHoc(act, idx)}
																					disabled={log?.running}
																					className="px-3 py-1.5 bg-fuchsia-600 hover:bg-fuchsia-500 text-white rounded text-[10px] uppercase font-bold flex items-center gap-1.5 transition-colors shadow-md shadow-fuchsia-600/10"
																				>
																					{log?.running ? (
																						<>
																							<Loader2 className="w-3 h-3 animate-spin" />
																							<span>sandbox running...</span>
																						</>
																					) : (
																						<>
																							<Terminal className="w-3 h-3" />
																							<span>Run In Sandbox</span>
																						</>
																					)}
																				</button>
																			</>
																		)}

																		{act.patch_content && (
																			<button
																				type="button"
																				onClick={() => downloadPatch(act)}
																				className="px-3 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 rounded text-[10px] uppercase font-bold flex items-center gap-1.5 transition-colors"
																			>
																				<Download className="w-3 h-3" />
																				<span>Download Git Patch</span>
																			</button>
																		)}
																	</div>
																</div>
																
																{/* Blast Radius Assessment Checklist */}
																{safety && (
																	<div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-black/40 p-3 rounded-lg border border-white/5 text-[9px] uppercase tracking-wider">
																		<div className="flex flex-col">
																			<span className="text-zinc-500">Safety Score</span>
																			<span className={`text-xs font-bold ${safety.safety_score >= 0.8 ? "text-emerald-400" : safety.safety_score >= 0.5 ? "text-orange-400" : "text-rose-400"}`}>
																				{(safety.safety_score * 100).toFixed(0)}%
																			</span>
																		</div>
																		<div className="flex flex-col">
																			<span className="text-zinc-500">Scope compliant</span>
																			<span className={`text-xs font-bold ${safety.scope_compliant ? "text-emerald-400" : "text-rose-400"}`}>
																				{safety.scope_compliant ? "VERIFIED" : "BLOCKED"}
																			</span>
																		</div>
																		<div className="flex flex-col">
																			<span className="text-zinc-500">Syntax Valid</span>
																			<span className={`text-xs font-bold ${safety.syntax_valid ? "text-emerald-400" : "text-rose-400"}`}>
																				{safety.syntax_valid ? "YES" : "ERR"}
																			</span>
																		</div>
																		<div className="flex flex-col">
																			<span className="text-zinc-500">Est. Impact</span>
																			<span className={`text-xs font-bold ${
																				safety.estimated_impact === "destructive" ? "text-rose-400 animate-pulse" :
																				safety.estimated_impact === "state_changing" ? "text-orange-400" : "text-zinc-300"
																			}`}>
																				{safety.estimated_impact}
																			</span>
																		</div>
																	</div>
																)}

																{safety && safety.warnings && safety.warnings.length > 0 && (
																	<div className="bg-rose-500/10 border border-rose-500/25 text-rose-400 p-2.5 rounded text-[10px] space-y-1">
																		{safety.warnings.map((warn, wIdx) => (
																			<div key={wIdx} className="flex gap-1.5 items-start">
																				<AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
																				<span>{warn}</span>
																			</div>
																		))}
																	</div>
																)}
																
																{/* Payload text block */}
																{act.command && (
																	<div className="p-3 bg-black rounded-lg border border-white/5 text-[10px] text-zinc-400 overflow-x-auto break-all font-mono select-text">
																		{act.command}
																	</div>
																)}
																
																{act.patch_content && (
																	<div className="p-3 bg-zinc-950 rounded-lg border border-white/5 text-[9px] text-emerald-500 overflow-x-auto whitespace-pre leading-relaxed max-h-40 overflow-y-auto font-mono select-text">
																		{act.patch_content}
																	</div>
																)}

																{/* Container Terminal Execution Console Output */}
																{log && (
																	<div className="space-y-1.5 border border-white/10 rounded-lg overflow-hidden bg-black">
																		<div className="bg-zinc-900 px-3 py-1.5 flex items-center justify-between border-b border-white/5">
																			<div className="flex items-center gap-1.5 text-[9px] text-zinc-400">
																				<TerminalSquare className="w-3.5 h-3.5 text-fuchsia-400" />
																				<span>Ephemeral Docker Execution Console</span>
																			</div>
																			{log.running ? (
																				<span className="text-[8px] bg-fuchsia-500/10 text-fuchsia-400 border border-fuchsia-500/20 px-1.5 py-0.5 rounded font-bold uppercase animate-pulse">Running container</span>
																			) : (
																				<span className={`text-[8px] px-1.5 py-0.5 rounded font-bold uppercase ${
																					log.exit_code === 0 ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
																				}`}>
																					Exit Code: {log.exit_code}
																				</span>
																			)}
																		</div>
																		{log.error ? (
																			<div className="p-3 text-[10px] text-rose-400 whitespace-pre-wrap font-mono">
																				Error: {log.error}
																			</div>
																		) : (
																			<div className="p-3 text-[10px] text-zinc-300 font-mono whitespace-pre-wrap max-h-60 overflow-y-auto select-text leading-normal bg-black">
																				{log.stdout && (
																					<div className="text-zinc-200">
																						<div className="text-zinc-500 text-[8px] uppercase tracking-wider mb-0.5">stdout</div>
																						{log.stdout}
																					</div>
																				)}
																				{log.stderr && (
																					<div className="text-rose-400/90 mt-2">
																						<div className="text-rose-500/50 text-[8px] uppercase tracking-wider mb-0.5">stderr</div>
																						{log.stderr}
																					</div>
																				)}
																				{!log.stdout && !log.stderr && !log.running && (
																					<div className="text-zinc-600 italic">Container exited with no stdout/stderr output.</div>
																				)}
																			</div>
																		)}
																	</div>
																)}
															</div>
														);
													})}
												</div>
											</div>
										)}
									</div>
								)}
							</div>
						)}
					</div>

					{/* Right Sidebar: AI Controller & Routing Matrix */}
					<div className="w-72 overflow-y-auto p-5 space-y-6 bg-zinc-950/40 backdrop-blur-xl">
						
						{/* Task configuration */}
						<div className="space-y-3">
							<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
								<Layers className="w-3.5 h-3.5 text-fuchsia-400" />
								Task Profile
							</h4>
							<div className="space-y-1">
								<span className="text-[8px] text-zinc-500 uppercase font-bold block">AITaskType Domain</span>
								<select
									value={selectedTaskType}
									onChange={(e) => setSelectedTaskType(e.target.value)}
									className="w-full bg-black border border-white/10 rounded-lg p-2 text-xs text-zinc-300 outline-none focus:border-fuchsia-500/30"
								>
									<option value="triage_compression">Triage Compression</option>
									<option value="exploit_analysis">Exploit Analysis</option>
									<option value="remediation_generation">Remediation Gen</option>
									<option value="code_refactor">Code Refactor</option>
									<option value="terminal_automation">Terminal Automation</option>
									<option value="doc_summarization">Doc Summarization</option>
									<option value="batch_classification">Batch Classification</option>
									<option value="creative_frontend">Creative Frontend</option>
									<option value="air_gapped_exec">Air-Gapped Execution</option>
								</select>
							</div>
						</div>

						{/* Fallback chain preview */}
						{selectedTaskConfig && (
							<div className="space-y-3">
								<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
									<Activity className="w-3.5 h-3.5 text-cyan-400" />
									Active Routing Chain
								</h4>
								<div className="space-y-2">
									{selectedTaskConfig.default_chain.map((slot, sIdx) => (
										<div key={sIdx} className="p-2 bg-black/40 border border-white/5 rounded-lg flex items-center justify-between text-[10px]">
											<div className="flex flex-col">
												<span className="font-bold text-zinc-300 uppercase">{slot.provider}</span>
												<span className="text-zinc-500 text-[8px]">{slot.model}</span>
											</div>
											<span className={`px-1 rounded text-[8px] font-bold uppercase ${sIdx === 0 ? "text-cyan-400 bg-cyan-500/10" : "text-zinc-500 bg-zinc-500/10"}`}>
												Priority {slot.priority}
											</span>
										</div>
									))}
								</div>
								<div className="p-2 bg-black/60 rounded text-[8px] text-zinc-500 flex justify-between uppercase">
									<span>Cost Ceiling:</span>
									<span className="text-zinc-300 font-bold">{selectedTaskConfig.cost_ceiling}</span>
								</div>
							</div>
						)}

						{/* Explicit overrides */}
						<div className="space-y-3">
							<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
								<Shield className="w-3.5 h-3.5 text-rose-400" />
								Model Override
							</h4>
							
							<div className="space-y-2">
								<div className="space-y-1">
									<span className="text-[8px] text-zinc-500 uppercase font-bold block">Provider Override</span>
									<select
										value={overrideProvider}
										onChange={(e) => {
											setOverrideProvider(e.target.value);
											setOverrideModel("");
										}}
										className="w-full bg-black border border-white/10 rounded-lg p-2 text-xs text-zinc-300 outline-none focus:border-fuchsia-500/30"
									>
										<option value="">(Use Default Routing)</option>
										{routingConfig?.providers.map((p) => (
											<option key={p} value={p}>{p.toUpperCase()}</option>
										))}
									</select>
								</div>

								{overrideProvider && (
									<div className="space-y-1">
										<span className="text-[8px] text-zinc-500 uppercase font-bold block">Target Model</span>
										<select
											value={overrideModel}
											onChange={(e) => setOverrideModel(e.target.value)}
											className="w-full bg-black border border-white/10 rounded-lg p-2 text-xs text-zinc-300 outline-none focus:border-fuchsia-500/30"
										>
											<option value="">(Select model ID)</option>
											{routingConfig && Object.entries(routingConfig.model_catalog)
												.filter(([_, spec]) => spec.provider === overrideProvider)
												.map(([id, spec]) => (
													<option key={id} value={id}>{spec.display_name}</option>
												))
											}
										</select>
									</div>
								)}

								<div className="pt-2 flex items-center justify-between">
									<label htmlFor="force-override-checkbox" className="text-[9px] text-zinc-400 uppercase font-bold cursor-pointer">
										Bypass Cost Guardrails
									</label>
									<input
										id="force-override-checkbox"
										type="checkbox"
										checked={forceOverride}
										onChange={(e) => setForceOverride(e.target.checked)}
										className="h-3.5 w-3.5 accent-fuchsia-600 bg-black border-white/10 rounded cursor-pointer"
									/>
								</div>
							</div>
						</div>

						{/* Model catalog overview */}
						{routingConfig && (
							<div className="space-y-3">
								<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
									<Database className="w-3.5 h-3.5 text-zinc-400" />
									Active Catalog
								</h4>
								<div className="space-y-2 max-h-60 overflow-y-auto pr-1.5 custom-scrollbar">
									{Object.entries(routingConfig.model_catalog).map(([id, spec]) => (
										<div key={id} className="p-2 bg-black/20 border border-white/5 rounded text-[9px] space-y-1.5">
											<div className="flex justify-between font-bold">
												<span className="text-zinc-300">{spec.display_name}</span>
												<span className={`px-1 rounded text-[7px] uppercase font-bold ${
													spec.cost_tier === "premium" ? "text-rose-400 bg-rose-500/10" :
													spec.cost_tier === "standard" ? "text-orange-400 bg-orange-500/10" :
													spec.cost_tier === "budget" ? "text-cyan-400 bg-cyan-500/10" :
													"text-zinc-500 bg-zinc-500/10"
												}`}>
													{spec.cost_tier}
												</span>
											</div>
											<div className="flex justify-between text-zinc-500 text-[8px]">
												<span>Ctx: {(spec.context_window / 1000).toFixed(0)}k</span>
												<span>Out: {spec.max_output_tokens}</span>
											</div>
										</div>
									))}
								</div>
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
