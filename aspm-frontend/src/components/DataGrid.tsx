import { motion } from "framer-motion";
import { useFlashlight } from "../hooks/useFlashlight";
import { useVirtualizer } from "@tanstack/react-virtual";
import React, { useMemo, useRef, useState } from "react";
import type { Finding } from "../store";
import { useSecurityStore } from "../store";
import { useShallow } from "zustand/react/shallow";
import { API_URL } from "../config";
import { fetchWithAuth } from "../apiClient";
import { ExploitDiffSheet } from "./ExploitDiffSheet";
import {
	Select,
	SelectContent,
	SelectItem,
	SelectTrigger,
	SelectValue,
} from "./ui/select";

interface DataGridProps {
	findings: Finding[];
	selectedFindingId: string | null;
	onSelectFinding: (id: string) => void;
	onUpdateStatus: (id: string, status: Finding["status"]) => void;
}

const sevClasses: Record<Finding["severity"], string> = {
	critical: "text-rose-400 bg-rose-500/10 border-rose-500/20 shadow-[0_0_10px_rgba(225,29,72,0.15)]",
	high: "text-orange-400 bg-orange-500/10 border-orange-500/20",
	medium: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20",
	low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
	info: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
};

const sevWeights: Record<Finding["severity"], number> = {
	critical: 5,
	high: 4,
	medium: 3,
	low: 2,
	info: 1,
};

interface ActiveFindingDetails {
	title: string;
	severity: string;
	payload?: string;
	evidence?: string;
	diff?: {
		request?: string;
		response?: string;
	};
}

export default function DataGrid({
	findings,
	selectedFindingId,
	onSelectFinding,
	onUpdateStatus,
}: DataGridProps) {
	const containerRef = useRef<HTMLDivElement>(null);
	const mousePosition = useFlashlight(containerRef);
	const { selectedTargetId, isEcoMode } = useSecurityStore(
		useShallow((state) => ({
			selectedTargetId: state.selectedTargetId,
			isEcoMode: state.isEcoMode,
		}))
	);

	const handleDownloadReport = React.useCallback(async () => {
		if (!selectedTargetId) return;
		try {
			const response = await fetchWithAuth(`${API_URL}/reports/${selectedTargetId}/download`);
			if (!response.ok) {
				throw new Error("Failed to download report");
			}
			const blob = await response.blob();
			const url = window.URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = `sentinel_report_${selectedTargetId}.html`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			window.URL.revokeObjectURL(url);
		} catch (error) {
			alert(`Report download failed: ${error}`);
		}
	}, [selectedTargetId]);

	// ─── Filters & Sorting State ────────────────────────────────────────────────
	const [sevFilter, setSevFilter] = useState<string>("all");
	const [statusFilter, setStatusFilter] = useState<string>("all");
	const [searchQuery, setSearchQuery] = useState<string>("");
	const [sortBy, setSortBy] = useState<string>("first_seen");

	const [diffSheetOpen, setDiffSheetOpen] = useState(false);
	const [activeDiffFinding, setActiveDiffFinding] =
		useState<ActiveFindingDetails | null>(null);

	// ─── Apply Filtering and Sorting ────────────────────────────────────────────
	const filteredFindings = useMemo(() => {
		return findings
			.filter((f) => {
				const matchesSev = sevFilter === "all" || f.severity === sevFilter;
				const matchesStatus =
					statusFilter === "all" || f.status === statusFilter;
				const matchesSearch =
					searchQuery === "" ||
					f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
					f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
					f.description.toLowerCase().includes(searchQuery.toLowerCase());
				return matchesSev && matchesStatus && matchesSearch;
			})
			.sort((a, b) => {
				if (sortBy === "severity") {
					return sevWeights[b.severity] - sevWeights[a.severity];
				}
				return (
					new Date(b.first_seen).getTime() - new Date(a.first_seen).getTime()
				);
			});
	}, [findings, sevFilter, statusFilter, searchQuery, sortBy]);

	// ─── Row Virtualization ─────────────────────────────────────────────────────
	const rowVirtualizer = useVirtualizer({
		count: filteredFindings.length,
		getScrollElement: () => containerRef.current,
		estimateSize: () => 40, // High-density grid row height
		overscan: 10,
	});

	const handleRowClick = React.useCallback((finding: Finding) => {
		onSelectFinding(finding.id);

		// Parse evidence/raw data for diff view if available
		let diffData: { request: string; response: string } | undefined;
		let evidenceText = finding.evidence;

		// Try to extract raw HTTP data if present
		if (finding.evidence?.includes("HTTP/")) {
			const parts = finding.evidence.split("--- RESPONSE ---");
			if (parts.length === 2) {
				diffData = {
					request: parts[0].trim(),
					response: parts[1].trim(),
				};
				evidenceText = "Raw HTTP traffic captured.";
			}
		}

		setActiveDiffFinding({
			title: finding.title,
			severity: finding.severity,
			payload:
				finding.title.includes("SQLi") || finding.title.includes("XSS")
					? `' OR 1=1--`
					: undefined, // Simulated payload
			evidence: evidenceText,
			diff: diffData,
		});
		setDiffSheetOpen(true);
	}, [onSelectFinding]);

	return (
		<>
<div className={`${!isEcoMode ? 'animated-border-container' : ''} flex flex-col h-full select-none transition-all duration-300`}>
            <div
                ref={containerRef}
                className={`flex flex-col h-full rounded overflow-hidden relative ${
                    isEcoMode
                        ? "bg-zinc-900/95 border border-white/[0.08]"
                        : "animated-border-content bg-black/40 backdrop-blur-xl"
                }`}
            >
                {!isEcoMode && (
                    <div
                        className="pointer-events-none absolute -inset-px rounded-xl opacity-0 transition duration-300 group-hover:opacity-100"
                        style={{
                            background: `radial-gradient(600px circle at ${mousePosition.x}px ${mousePosition.y}px, rgba(56, 189, 248, 0.1), transparent 40%)`
                        }}
                    />
                )}
				{/* Filtering Header Panel */}
				<div className="p-3 border-b border-white/5 flex flex-wrap gap-3 items-center justify-between bg-black/40">
					<div className="flex items-center gap-1.5 flex-1 min-w-[200px] relative">
						<input
							type="text"
							placeholder="Search findings (regex/keyword)..."
							value={searchQuery}
							onChange={(e) => setSearchQuery(e.target.value)}
							className="w-full bg-black/50 border border-white/10 rounded-lg pl-3 pr-8 py-1.5 text-xs text-zinc-300 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 focus:outline-none placeholder-zinc-600 transition-all font-mono"
						/>
						{searchQuery && (
							<button
								type="button"
								onClick={() => setSearchQuery("")}
								className="absolute right-2.5 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
								aria-label="Clear search"
								title="Clear search"
							>
								<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>
							</button>
						)}
					</div>

					<div className="flex items-center gap-2">
						<Select
							value={sevFilter}
							onValueChange={(v) => setSevFilter(v || "")}
						>
							<SelectTrigger className="w-[130px] bg-black/50 border-white/10 text-zinc-400 h-8 text-[11px] font-mono hover:bg-white/5 transition-colors">
								<SelectValue placeholder="All Severities" />
							</SelectTrigger>
							<SelectContent>
								<SelectItem value="all">All Severities</SelectItem>
								<SelectItem value="critical">Critical</SelectItem>
								<SelectItem value="high">High</SelectItem>
								<SelectItem value="medium">Medium</SelectItem>
								<SelectItem value="low">Low</SelectItem>
								<SelectItem value="info">Info</SelectItem>
							</SelectContent>
						</Select>

						<Select
							value={statusFilter}
							onValueChange={(v) => setStatusFilter(v || "")}
						>
							<SelectTrigger className="w-[120px] bg-black/50 border-white/10 text-zinc-400 h-8 text-[11px] font-mono hover:bg-white/5 transition-colors">
								<SelectValue placeholder="All Statuses" />
							</SelectTrigger>
							<SelectContent>
								<SelectItem value="all">All Statuses</SelectItem>
								<SelectItem value="open">Open</SelectItem>
								<SelectItem value="confirmed">Confirmed</SelectItem>
								<SelectItem value="false_positive">False Positive</SelectItem>
								<SelectItem value="resolved">Resolved</SelectItem>
							</SelectContent>
						</Select>

						<Select value={sortBy} onValueChange={(v) => setSortBy(v || "")}>
							<SelectTrigger className="w-[140px] bg-black/50 border-white/10 text-zinc-400 h-8 text-[11px] font-mono hover:bg-white/5 transition-colors">
								<SelectValue placeholder="Sort by Seen" />
							</SelectTrigger>
							<SelectContent>
								<SelectItem value="first_seen">Sort by Seen</SelectItem>
								<SelectItem value="severity">Sort by Severity</SelectItem>
							</SelectContent>
						</Select>

						<button
							type="button"
							onClick={handleDownloadReport}
							disabled={!selectedTargetId}
							className="h-8 px-4 bg-gradient-to-r from-brand-600 to-fuchsia-600 hover:from-brand-500 hover:to-fuchsia-500 disabled:from-zinc-800 disabled:to-zinc-800 disabled:text-zinc-500 rounded-lg text-white text-[11px] font-bold tracking-wider transition-all shadow-lg shadow-brand-500/20 disabled:shadow-none ring-1 ring-white/10 uppercase"
							title={selectedTargetId ? "Download Target Audit Report" : "Select a target first to download the report"}
							aria-label="Download Target Audit Report"
						>
							Download Report
						</button>
					</div>
				</div>

				{/* Grid Headers */}
				<div className="grid grid-cols-[1fr_85px_110px_100px_85px_30px] border-b border-white/5 px-4 py-2.5 bg-black/60 text-[10px] font-bold text-zinc-500 uppercase tracking-widest backdrop-blur-md">
					<span>Title</span>
					<span>Severity</span>
					<span>Category</span>
					<span>Status</span>
					<span>Detected</span>
					<span />
				</div>

				{/* Virtual Rows Container */}
				<div
					ref={containerRef}
					className="flex-1 overflow-y-auto custom-scrollbar"
					style={{ minHeight: "200px" }}
				>
					{filteredFindings.length === 0 ? (
						<div className="h-full flex items-center justify-center text-xs text-slate-500 italic p-6 font-mono">
							No telemetry records match current selection filters.
						</div>
					) : (
						<div
							style={{
								height: `${rowVirtualizer.getTotalSize()}px`,
								width: "100%",
								position: "relative",
							}}
						>
							{rowVirtualizer.getVirtualItems().map((virtualRow) => {
								const finding = filteredFindings[virtualRow.index];
								const isSelected = selectedFindingId === finding.id;

								return (
									/* biome-ignore lint/a11y/useSemanticElements: grid row cannot be button */
									<div
										key={finding.id}
										role="button"
										tabIndex={0}
										onClick={() => handleRowClick(finding)}
										onKeyDown={(e) => {
											if (e.key === "Enter" || e.key === " ") {
												handleRowClick(finding);
											}
										}}
										className={`grid grid-cols-[1fr_85px_110px_100px_85px_30px] items-center px-4 border-b border-white/5 transition-all duration-200 cursor-pointer text-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand-500 focus-visible:ring-inset group ${
											isSelected
												? "bg-white/10 text-white shadow-[inset_2px_0_0_0_#a855f7]"
												: "text-zinc-300 hover:bg-white/5 hover:text-zinc-100"
										}`}
										style={{
											position: "absolute",
											top: 0,
											left: 0,
											width: "100%",
											height: `${virtualRow.size}px`,
											transform: `translateY(${virtualRow.start}px)`,
										}}
									>
										{/* Title */}
										<span
											className={`truncate font-semibold pr-3 font-mono tracking-tight ${isSelected ? "text-fuchsia-300" : ""}`}
											title={finding.title}
										>
											{finding.title}
										</span>

										{/* Severity Badge */}
										<span
											className={`text-[9px] font-extrabold px-2 py-0.5 rounded-md border font-mono tracking-wider uppercase w-fit transition-all duration-300 ${
												sevClasses[finding.severity]
											}`}
										>
											{finding.severity}
										</span>

										{/* Category */}
										<span className="truncate text-zinc-500 text-[10px] font-medium tracking-wide">
											{finding.category}
										</span>

										{/* Status Dropdown */}
										{/* biome-ignore lint/a11y/noStaticElementInteractions: Stop click propagation */}
										{/* biome-ignore lint/a11y/useKeyWithClickEvents: Stop click propagation */}
										<div onClick={(e) => e.stopPropagation()}>
											<Select
												value={finding.status}
												onValueChange={(val: Finding["status"] | null) => {
													if (val) onUpdateStatus(finding.id, val);
												}}
											>
												<SelectTrigger className="h-6 w-[90px] bg-black/60 border-white/10 text-[10px] px-2 py-0 text-zinc-300 font-mono opacity-60 group-hover:opacity-100 transition-opacity">
													<SelectValue />
												</SelectTrigger>
												<SelectContent>
													<SelectItem value="open">open</SelectItem>
													<SelectItem value="confirmed">confirmed</SelectItem>
													<SelectItem value="false_positive">
														false pos
													</SelectItem>
													<SelectItem value="resolved">resolved</SelectItem>
												</SelectContent>
											</Select>
										</div>

										{/* Detected Time */}
										<span className="text-[10px] text-zinc-600 font-mono">
											{new Date(finding.first_seen).toLocaleDateString()}
										</span>

										{/* AI triaged badge */}
										<span className="text-right pr-2 select-none text-[12px] opacity-70">
											{finding.ai_triaged ? "🧠" : ""}
										</span>
									</div>
								);
							})}
						</div>
					)}
				</div>
			</div>

			<ExploitDiffSheet
				open={diffSheetOpen}
				onOpenChange={setDiffSheetOpen}
				findingDetails={activeDiffFinding}
			/>
		</div>
		</>
	);
}
