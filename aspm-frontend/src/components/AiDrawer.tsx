import React, { useState, useEffect } from "react";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "./ui/sheet";
import { fetchWithAuth } from "../apiClient";
import { API_BASE_URL } from "../config";
import {
	Cpu,
	ShieldAlert,
	CheckCircle2,
	Play,
	Activity,
	Loader2,
	AlertTriangle,
	Download,
	Copy,
	Check,
	Terminal,
	TerminalSquare,
} from "lucide-react";

interface AiDrawerProps {
	open: boolean;
	onOpenChange: (open: boolean) => void;
	findingId: string | null;
	findingTitle: string;
	findingSeverity: string;
	mode: "remediation" | "exploit_flow";
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

interface ActionableTriagePlan {
	summary: string;
	vulnerability_confirmed: boolean;
	risk_score: number;
	confidence: number;
	cve_references: string[];
	remediation_steps: string[];
	actions: ExecutableAction[];
	blast_radius: BlastRadiusAssessment[];
}

export function AiDrawer({
	open,
	onOpenChange,
	findingId,
	findingTitle,
	findingSeverity,
	mode,
}: AiDrawerProps) {
	const [loading, setLoading] = useState(false);
	const [plan, setPlan] = useState<ActionableTriagePlan | null>(null);
	const [error, setError] = useState<string | null>(null);

	// Action logs for container runs
	const [executionLogs, setExecutionLogs] = useState<Record<number, {
		stdout: string;
		stderr: string;
		exit_code: number;
		running: boolean;
		error?: string;
	}>>({});
	const [copiedActionIdx, setCopiedActionIdx] = useState<number | null>(null);

	useEffect(() => {
		if (open && findingId) {
			fetchTriagePlan();
		} else {
			setPlan(null);
			setError(null);
			setExecutionLogs({});
		}
	}, [open, findingId, mode]);

	const fetchTriagePlan = async () => {
		if (!findingId) return;
		setLoading(true);
		setError(null);
		setPlan(null);
		setExecutionLogs({});

		try {
			// Call the new full-pipeline analysis endpoint
			const res = await fetchWithAuth(`${API_BASE_URL}/api/ai/analyze-finding/${findingId}`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
			});
			if (!res.ok) throw new Error("Failed to generate AI analysis payload");
			const data = await res.json();
			setPlan(data);
		} catch (err: any) {
			setError(err.message || "Failed to communicate with AI orchestration layer");
		} finally {
			setLoading(false);
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

	return (
		<Sheet open={open} onOpenChange={onOpenChange}>
			<SheetContent
				side="right"
				className="w-[580px] sm:max-w-[580px] bg-black/95 backdrop-blur-xl border-l border-white/5 p-6 overflow-y-auto custom-scrollbar font-mono text-xs select-none"
			>
				<SheetHeader className="mb-6 border-b border-white/5 pb-4">
					<div className="flex items-center gap-2">
						<Cpu className="w-5 h-5 text-fuchsia-400 animate-pulse" />
						<SheetTitle className="text-sm font-bold tracking-wider font-mono text-zinc-100 uppercase">
							{mode === "remediation" ? "AI Remediation Advisory" : "AI Exploit Flow Analyzer"}
						</SheetTitle>
					</div>
					<div className="mt-2 text-[10px] font-mono text-zinc-500">
						Finding Target: <span className="text-zinc-300">{findingTitle}</span>
					</div>
				</SheetHeader>

				<div className="space-y-6">
					{/* Status badge */}
					<div className="flex items-center justify-between">
						<div className="flex items-center gap-2">
							<span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest font-sans">Severity:</span>
							<span
								className={`px-2 py-0.5 text-[9px] font-extrabold rounded border font-mono tracking-widest uppercase ${
									findingSeverity === "critical"
										? "text-rose-400 bg-rose-500/10 border-rose-500/20"
										: findingSeverity === "high"
											? "text-orange-400 bg-orange-500/10 border-orange-500/20"
											: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
								}`}
							>
								{findingSeverity}
							</span>
						</div>
						
						{plan && (
							<span className="text-[9px] text-zinc-500">
								RISK SCORE: <span className={`font-bold ${plan.risk_score >= 7 ? "text-rose-400" : "text-yellow-400"}`}>{plan.risk_score.toFixed(1)}/10.0</span>
							</span>
						)}
					</div>

					{loading ? (
						<div className="flex flex-col items-center justify-center py-20 gap-3 text-zinc-500">
							<Loader2 className="w-6 h-6 animate-spin text-fuchsia-400" />
							<span className="text-[10px] tracking-wider uppercase">Executing cognitive engine...</span>
						</div>
					) : error ? (
						<div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg flex items-start gap-3">
							<ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
							<div>
								<span className="font-bold">ORCHESTRATOR ERROR:</span> {error}
							</div>
						</div>
					) : plan ? (
						<div className="space-y-6">
							
							{/* Summary description */}
							<div className="space-y-2">
								<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
									<Activity className="w-3.5 h-3.5 text-fuchsia-400" />
									Triage Summary
								</h4>
								<div className="bg-zinc-950/20 border border-white/5 rounded-xl p-3 shadow-inner leading-relaxed text-zinc-300 font-sans">
									{plan.summary}
								</div>
							</div>

							{/* Vulnerability status confirmation */}
							<div className={`p-3 rounded-lg border flex items-center justify-between ${
								plan.vulnerability_confirmed ? "bg-rose-500/10 border-rose-500/20 text-rose-400" : "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
							}`}>
								<span className="font-bold tracking-wider uppercase text-[10px]">VERDICT STATUS:</span>
								<span className="font-extrabold uppercase tracking-widest">
									{plan.vulnerability_confirmed ? "CONFIRMED POSITIVE VULNERABILITY" : "SAFE / FALSE POSITIVE"}
								</span>
							</div>

							{/* Remediation guidance block */}
							{mode === "remediation" && plan.remediation_steps.length > 0 && (
								<div className="space-y-3">
									<h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
										<CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
										Remediation Checklist
									</h4>
									<ul className="list-disc pl-5 text-zinc-400 space-y-1 font-sans">
										{plan.remediation_steps.map((step, sIdx) => (
											<li key={sIdx}>{step}</li>
										))}
									</ul>
								</div>
							)}

							{/* Action execution grid */}
							{plan.actions.length > 0 && (
								<div className="space-y-4">
									<h4 className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest flex items-center gap-1.5 border-b border-white/5 pb-2">
										<Play className="w-3.5 h-3.5 text-cyan-400" />
										Executable Actions Matrix
									</h4>
									<div className="space-y-4">
										{plan.actions.map((act, idx) => {
											const safety = plan.blast_radius?.[idx];
											const log = executionLogs[idx];

											return (
												<div key={idx} className="p-4 bg-zinc-950/40 border border-white/5 rounded-xl space-y-3 select-none">
													
													<div className="flex justify-between items-start gap-4">
														<div>
															<h5 className="text-xs font-bold text-zinc-200">{act.title}</h5>
															<span className="text-[8px] text-zinc-500 uppercase tracking-widest font-bold">
																{act.action_type} • {act.risk_level} risk
															</span>
														</div>

														<div className="flex gap-2">
															{act.command && (
																<>
																	<button
																		type="button"
																		onClick={() => copyCommand(act.command!, idx)}
																		className="p-1.5 bg-white/5 rounded hover:bg-white/10 text-zinc-400 hover:text-white border border-white/5"
																		title="Copy Command"
																	>
																		{copiedActionIdx === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
																	</button>
																	<button
																		type="button"
																		onClick={() => executeActionAdHoc(act, idx)}
																		disabled={log?.running}
																		className="px-2.5 py-1.5 bg-fuchsia-600 hover:bg-fuchsia-500 text-white rounded text-[9px] uppercase font-bold flex items-center gap-1.5 transition-colors"
																	>
																		{log?.running ? (
																			<>
																				<Loader2 className="w-3 h-3 animate-spin" />
																				<span>sandbox running...</span>
																			</>
																		) : (
																			<>
																				<Terminal className="w-3 h-3" />
																				<span>Run Payload</span>
																			</>
																		)}
																	</button>
																</>
															)}

															{act.patch_content && (
																<button
																	type="button"
																	onClick={() => downloadPatch(act)}
																	className="px-2.5 py-1.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 hover:bg-emerald-500/20 rounded text-[9px] uppercase font-bold flex items-center gap-1.5 transition-colors"
																>
																	<Download className="w-3 h-3" />
																	<span>Download Patch</span>
																</button>
															)}
														</div>
													</div>

													{/* Safety scores */}
													{safety && (
														<div className="grid grid-cols-4 gap-2 bg-black/40 p-2 rounded text-[8px] uppercase tracking-wider text-zinc-500">
															<div>
																Score: <span className={`font-bold ${safety.safety_score >= 0.8 ? "text-emerald-400" : "text-rose-400"}`}>{(safety.safety_score * 100).toFixed(0)}%</span>
															</div>
															<div>
																Scope: <span className={`font-bold ${safety.scope_compliant ? "text-emerald-400" : "text-rose-400"}`}>{safety.scope_compliant ? "OK" : "NO"}</span>
															</div>
															<div>
																Syntax: <span className={`font-bold ${safety.syntax_valid ? "text-emerald-400" : "text-rose-400"}`}>{safety.syntax_valid ? "OK" : "ERR"}</span>
															</div>
															<div>
																Impact: <span className="font-bold text-zinc-300">{safety.estimated_impact}</span>
															</div>
														</div>
													)}

													{safety && safety.warnings && safety.warnings.length > 0 && (
														<div className="bg-rose-500/10 text-rose-400 p-2 rounded text-[9px]">
															{safety.warnings.map((warn, wIdx) => (
																<div key={wIdx} className="flex gap-1 items-start">
																	<AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
																	<span>{warn}</span>
																</div>
															))}
														</div>
													)}

													{/* Code rendering */}
													{act.command && (
														<div className="p-3 bg-black rounded-lg border border-white/5 text-[9px] text-zinc-400 overflow-x-auto break-all font-mono select-text">
															{act.command}
														</div>
													)}
													
													{act.patch_content && (
														<div className="p-3 bg-zinc-950 rounded-lg border border-white/5 text-[8px] text-emerald-500 overflow-x-auto whitespace-pre leading-relaxed max-h-32 overflow-y-auto font-mono select-text">
															{act.patch_content}
														</div>
													)}

													{/* Terminal output logs */}
													{log && (
														<div className="space-y-1 border border-white/10 rounded-lg overflow-hidden bg-black font-mono">
															<div className="bg-zinc-900 px-2.5 py-1.5 flex items-center justify-between border-b border-white/5">
																<div className="flex items-center gap-1 text-[8px] text-zinc-400">
																	<TerminalSquare className="w-3 h-3 text-fuchsia-400" />
																	<span>Container Logs</span>
																</div>
																<span className={`text-[7px] px-1 rounded font-bold uppercase ${
																	log.exit_code === 0 ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"
																}`}>
																	exit: {log.exit_code}
																</span>
															</div>
															{log.error ? (
																<div className="p-2 text-[9px] text-rose-400">
																	Error: {log.error}
																</div>
															) : (
																<div className="p-2 text-[9px] text-zinc-300 whitespace-pre-wrap max-h-40 overflow-y-auto leading-tight select-text bg-black">
																	{log.stdout && <div>{log.stdout}</div>}
																	{log.stderr && <div className="text-rose-400/90 mt-1">{log.stderr}</div>}
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
					) : (
						<div className="text-zinc-500 italic text-center py-20 font-sans">
							No analysis verdict generated. Run verification to generate.
						</div>
					)}
				</div>
			</SheetContent>
		</Sheet>
	);
}

