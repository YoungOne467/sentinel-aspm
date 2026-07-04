import {
	Background,
	BackgroundVariant,
	Controls,
	type Edge,
	Handle,
	MarkerType,
	MiniMap,
	type Node,
	type NodeProps,
	Position,
	ReactFlow,
	useEdgesState,
	useNodesState,
} from "@xyflow/react";
import React, { useCallback, useEffect, useState } from "react";
import "@xyflow/react/dist/style.css";
import { useSecurityStore } from "../store";
import { fetchWithAuth } from "../apiClient";
import { API_URL } from "../config";
import { Copy } from "lucide-react";

// ─── Node Interface ──────────────────────────────────────────────────────────
export interface TopologyNodeData {
	id: string;
	label: string;
	type: "root" | "subdomain" | "endpoint";
	is_new: boolean;
	has_alert: boolean;
	url?: string;
	status_code?: number;
	id_actual?: string;
	target_id?: string;
	risk_score?: number;
	tech_stack?: string[];
	known_cves?: {
		cve_id: string;
		severity: string;
		cvss: number | string;
		description: string;
	}[];
	shadow_apis?: string[];
	[key: string]: unknown;
}

export interface TopologyData {
	nodes: TopologyNodeData[];
	edges: { source: string; target: string }[];
}

// ─── Custom CustomNode Component ──────────────────────────────────────────────
const CustomNode = React.memo(({ data }: { data: TopologyNodeData }) => {
	const isRoot = data.type === "root";
	const isSubdomain = data.type === "subdomain";
	const isEndpoint = data.type === "endpoint";

	let borderClass = "border-white/10 bg-black/60";
	let labelColor = "text-zinc-300 font-mono tracking-tight";

	if (isRoot) {
		borderClass = "border-brand-500/80 bg-brand-950/20";
		labelColor = "text-brand-400 font-bold tracking-tight";
	} else if (data.has_alert) {
		borderClass = "border-rose-500/80 bg-rose-950/20";
		labelColor = "text-rose-400 font-medium font-mono tracking-tight";
	} else if (data.is_new) {
		borderClass = "border-emerald-500/80 bg-emerald-950/10";
		labelColor = "text-emerald-400 font-medium font-mono tracking-tight";
	} else if (isSubdomain) {
		borderClass = "border-fuchsia-500/30 bg-black/60 hover:border-fuchsia-500/60";
		labelColor = "text-fuchsia-300 font-semibold font-mono tracking-tight";
	}

	// Dynamic scaling based on risk score (0.0 to 10.0) -> scales from 1.0 to 1.2
	const scale = 1 + (data.risk_score || 0) * 0.02;
	
	// Custom glow intensity & color based on risk score & type
let glowColor = "255, 255, 255"; // default white
    if (isRoot) glowColor = "168, 85, 247"; // brand purple
    else if (data.has_alert) glowColor = "225, 29, 72"; // rose red
    else if (data.is_new) glowColor = "16, 185, 129"; // emerald
    else if (isSubdomain) glowColor = "217, 70, 239"; // fuchsia

	const scoreVal = data.risk_score || 0.0;
	const shadowSpread = 8 + scoreVal * 1.5;
	const shadowOpacity = 0.15 + scoreVal * 0.035;
	const customGlow =
		scoreVal > 0
			? `0 0 ${shadowSpread}px rgba(${glowColor}, ${shadowOpacity})`
			: undefined;
	const borderPulse = data.has_alert ? "animate-pulse" : "";

	const safeId = data.id.replace(/[^a-zA-Z0-9_-]/g, "_");
	const nodeClass = `node-dyn-${safeId}`;
	
	return (
		<>
			<style>
				{`.${nodeClass} {
            transform: scale(${scale}) !important;
            box-shadow: ${customGlow || "inset 0 1px 1px rgba(255,255,255,0.05)"} !important;
          }`}
			</style>
			<div
				className={`${nodeClass} px-4 py-3 rounded-2xl border text-left min-w-[220px] max-w-[280px] backdrop-blur-xl transition-all duration-300 ${borderClass} ${borderPulse}`}
			>
				{!isRoot && (
					<Handle
						type="target"
						position={Position.Top}
						className={`w-2 h-2 border-[1.5px] border-[#0a0e1a] !rounded-full ${
							data.has_alert
								? "bg-red-400"
								: data.is_new
									? "bg-emerald-400"
									: "bg-[#2a3050]"
						}`}
					/>
				)}

				<div className="flex items-center justify-between mb-1.5 text-[9px] uppercase tracking-wider font-mono">
					<span className="text-slate-500 font-bold">{data.type}</span>
					<div className="flex items-center gap-1">
						{data.is_new && (
							<span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded text-[8px] font-bold">
								NEW
							</span>
						)}
						{data.has_alert && (
							<span className="bg-red-500/10 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded text-[8px] font-bold animate-pulse">
								ALERT
							</span>
						)}
						{data.status_code && (
							<span
								className={`px-1.5 py-0.5 rounded text-[8px] font-bold ${
									data.status_code >= 200 && data.status_code < 300
										? "bg-emerald-500/10 text-emerald-400"
										: data.status_code >= 300 && data.status_code < 400
											? "bg-cyan-500/10 text-cyan-400"
											: "bg-red-500/10 text-red-400"
								}`}
							>
								{data.status_code}
							</span>
						)}
						{data.risk_score !== undefined && (
							<span
								className={`px-1.5 py-0.5 rounded text-[8px] font-bold border ${
									data.risk_score >= 7.0
										? "bg-red-500/10 text-red-400 border-red-500/30"
										: data.risk_score >= 4.0
											? "bg-orange-500/10 text-orange-400 border-orange-500/30"
											: data.risk_score >= 1.0
												? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
												: "bg-slate-800/60 text-slate-400 border-slate-700/30"
								}`}
							>
								R:{data.risk_score.toFixed(1)}
							</span>
						)}
					</div>
				</div>

				<div className={`text-xs truncate ${labelColor}`} title={data.label}>
					{data.label}
				</div>

				{isEndpoint && data.url && (
					<div className="text-[10px] text-slate-500 truncate mt-1 font-mono hover:text-slate-400 select-all">
						{data.url}
					</div>
				)}

				{data.tech_stack && data.tech_stack.length > 0 && (
					<div className="flex flex-wrap gap-1 mt-1.5 pt-1.5 border-t border-slate-800/50">
						{data.tech_stack.map((tech: string) => (
							<span
								key={tech}
								className="bg-[#1a1f35]/60 border border-[#2a3050]/50 text-slate-400 px-1 py-0.5 rounded text-[8px] font-mono leading-none"
							>
								{tech}
							</span>
						))}
					</div>
				)}

				{!isEndpoint && (
					<Handle
						type="source"
						position={Position.Bottom}
						className={`w-2 h-2 border-[1.5px] border-[#0a0e1a] !rounded-full ${
							isRoot ? "bg-[#38bdf8]" : "bg-[#2a3050]"
						}`}
					/>
				)}
			</div>
		</>
	);
});

CustomNode.displayName = "CustomNode";

const nodeTypes = {
	custom: CustomNode,
};

// ─── Main Architecture Map Component ──────────────────────────────────────────
const ArchitectureMap = React.memo(function ArchitectureMap({ data }: { data: TopologyData }) {
	const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
	const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
	const [selectedNode, setSelectedNode] = useState<TopologyNodeData | null>(null);

	// Retrieve Eco Mode from state
	const isEcoMode = useSecurityStore((state) => state.isEcoMode);

	// Filters
	const [searchTerm, setSearchTerm] = useState("");
	const [filterAlertsOnly, setFilterAlertsOnly] = useState(false);
	const [filterNewOnly, setFilterNewOnly] = useState(false);

	// AI Triage State
	const [isTriaging, setIsTriaging] = useState(false);
	const [triageResult, setTriageResult] = useState<string | null>(null);

	// Clear triage state when selecting a different node
	useEffect(() => {
		setIsTriaging(false);
		setTriageResult(null);
	}, []);

	const handleAITriage = async () => {
		if (!selectedNode) return;
		setIsTriaging(true);
		setTriageResult(null);

		try {
			const targetId =
				selectedNode.target_id ||
				(selectedNode.type === "root" ? selectedNode.id_actual : null) ||
				useSecurityStore.getState().selectedTargetId ||
				"t-1";

			if (!targetId) {
				setTriageResult("Could not determine target ID for AI Triage.");
				setIsTriaging(false);
				return;
			}

			const response = await fetchWithAuth(`${API_URL}/targets/${targetId}/triage`);
			
			if (!response.ok) {
				throw new Error(`Server returned HTTP ${response.status}`);
			}
			const data = await response.json();
			setTriageResult(data.summary);
		} catch (err) {
			const msg = err instanceof Error ? err.message : String(err);
			setTriageResult(`Failed to generate AI triage: ${msg}`);
		} finally {
			setIsTriaging(false);
		}
	};

	// Layout calculations
	const calculateTreeLayout = useCallback(
		(
			rawNodes: TopologyNodeData[],
			rawEdges: { source: string; target: string }[],
		) => {
			// ⚡ Bolt: Cache parentOf dictionary outside of getAncestors to avoid
			// rebuilding it multiple times for different filter passes.
			const parentOf: Record<string, string> = {};
			rawEdges.forEach((e) => {
				parentOf[e.target] = e.source;
			});

			const getAncestors = (startIds: Set<string>): Set<string> => {
				const result = new Set<string>(startIds);

				const expand = (id: string) => {
					let curr = id;
					while (curr && parentOf[curr]) {
						result.add(parentOf[curr]);
						curr = parentOf[curr];
					}
				};

				startIds.forEach(expand);
				return result;
			};

			// 1. Filter nodes based on UI filters
			let activeNodes = rawNodes;
			if (searchTerm.trim()) {
				const term = searchTerm.toLowerCase();
				const matchedIds = new Set<string>();
				rawNodes.forEach((n) => {
					if (
						n.label.toLowerCase().includes(term) ||
						n.id.toLowerCase().includes(term) ||
						n.url?.toLowerCase().includes(term)
					) {
						matchedIds.add(n.id);
					}
				});

				const fullIds = getAncestors(matchedIds);
				activeNodes = rawNodes.filter(
					(n) => fullIds.has(n.id) || n.type === "root",
				);
			}

			if (filterAlertsOnly) {
				const alertIds = new Set<string>();
				rawNodes.forEach((n) => {
					if (n.has_alert) alertIds.add(n.id);
				});
				const fullIds = getAncestors(alertIds);
				activeNodes = activeNodes.filter(
					(n) => fullIds.has(n.id) || n.type === "root",
				);
			}

			if (filterNewOnly) {
				const newIds = new Set<string>();
				rawNodes.forEach((n) => {
					if (n.is_new) newIds.add(n.id);
				});
				const fullIds = getAncestors(newIds);
				activeNodes = activeNodes.filter(
					(n) => fullIds.has(n.id) || n.type === "root",
				);
			}

			// ⚡ Bolt: Construct Set via manual loop instead of array mapping to avoid an O(N) memory allocation
			const activeNodeIds = new Set<string>();
			for (let i = 0; i < activeNodes.length; i++) {
				activeNodeIds.add(activeNodes[i].id);
			}

			const activeEdges = rawEdges.filter(
				(e) => activeNodeIds.has(e.source) && activeNodeIds.has(e.target),
			);

			// 2. Build tree relations
			const childrenMap: Record<string, string[]> = {};
			activeEdges.forEach((edge) => {
				if (!childrenMap[edge.source]) {
					childrenMap[edge.source] = [];
				}
				childrenMap[edge.source].push(edge.target);
			});

			// Width calculation for subtree positioning
			const subtreeWidths: Record<string, number> = {};
			const calculateWidth = (nodeId: string): number => {
				const children = childrenMap[nodeId] || [];
				if (children.length === 0) {
					subtreeWidths[nodeId] = 1;
					return 1;
				}
				let sum = 0;
				children.forEach((child) => {
					sum += calculateWidth(child);
				});
				subtreeWidths[nodeId] = sum;
				return sum;
			};
			
			const rootExists = activeNodeIds.has("root");
			if (rootExists) {
				calculateWidth("root");
			}

			// Assign coordinates
			const xCoords: Record<string, number> = {};
			const yCoords: Record<string, number> = {};
			const assignCoords = (
				nodeId: string,
				leftBoundary: number,
				depth: number,
			) => {
				yCoords[nodeId] = depth * 140 + 80;
				const children = childrenMap[nodeId] || [];
				if (children.length === 0) {
					xCoords[nodeId] = leftBoundary + 120;
					return;
				}

				let currentLeft = leftBoundary;
				children.forEach((child) => {
					const childWidth = subtreeWidths[child] * 240; 
					assignCoords(child, currentLeft, depth + 1);
					currentLeft += childWidth;
				});
				
				const firstChildX = xCoords[children[0]];
				const lastChildX = xCoords[children[children.length - 1]];
				xCoords[nodeId] = (firstChildX + lastChildX) / 2;
			};

			if (rootExists) {
				assignCoords("root", 0, 0);
			}

			activeNodes.forEach((n) => {
				if (xCoords[n.id] === undefined) {
					xCoords[n.id] = 120;
					yCoords[n.id] = 80;
				}
			});
			
			// 3. Map to React Flow Node objects
			const formattedNodes: Node<TopologyNodeData>[] = activeNodes.map((n) => ({
				id: n.id,
				type: "custom",
				position: { x: xCoords[n.id], y: yCoords[n.id] },
				data: n,
			}));
			
			// 4. Map to React Flow Edge objects
			const formattedEdges: Edge[] = activeEdges.map((e) => {
				const sourceNode = rawNodes.find((n) => n.id === e.source);
				const targetNode = rawNodes.find((n) => n.id === e.target);

				const isAlertEdge = targetNode?.has_alert || sourceNode?.has_alert;
				const isNewEdge = targetNode?.is_new;

				const isCriticalRiskPath =
					(sourceNode?.risk_score ?? 0) >= 8.0 ||
					(targetNode?.risk_score ?? 0) >= 8.0;

				let strokeColor = "#2a3050";
				let strokeWidth = 1.5;
				let animated = false;
				let strokeDasharray: string | undefined;
				let filter: string | undefined;

				if (isCriticalRiskPath) {
					strokeColor = "#ef4444"; 
					strokeWidth = 3;
					animated = !isEcoMode;
					strokeDasharray = "5,5";
					filter = isEcoMode ? undefined : "drop-shadow(0 0 4px rgba(239, 68, 68, 0.6))";
				} else if (isAlertEdge) {
					strokeColor = "#f87171";
					strokeWidth = 2;
					animated = !isEcoMode;
				} else if (isNewEdge) {
					strokeColor = "#34d399";
					strokeWidth = 1.5;
					animated = !isEcoMode;
				}

				return {
					id: `edge-${e.source}-${e.target}`,
					source: e.source,
					target: e.target,
					type: "smoothstep",
					style: {
						stroke: strokeColor,
						strokeWidth: strokeWidth,
						opacity: 0.8,
						strokeDasharray: strokeDasharray,
						filter: filter,
					},
					animated: animated,
					markerEnd: {
						type: MarkerType.ArrowClosed,
						width: 15,
						height: 15,
						color: strokeColor,
					},
				};
			});

			return { nodes: formattedNodes, edges: formattedEdges };
		},
		[searchTerm, filterAlertsOnly, filterNewOnly, isEcoMode],
	);
	
	// Apply layout updates whenever data or filters change
	useEffect(() => {
		if (data && (data.nodes || data.edges)) {
			const { nodes: flowNodes, edges: flowEdges } = calculateTreeLayout(
				data.nodes || [],
				data.edges || [],
			);
			setNodes(flowNodes);
			setEdges(flowEdges);
		}
	}, [data, calculateTreeLayout, setNodes, setEdges]);
	
	const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
		setSelectedNode(node.data as unknown as TopologyNodeData);
	}, []);

	const clearSelection = () => {
		setSelectedNode(null);
	};

	return (
		<div className="flex flex-col lg:flex-row gap-5 h-[calc(100vh-230px)] min-h-[500px] animate-fade-in">
			{/* ─── Control Bar & Diagram Panel ──────────────────────────────────────── */}
			<div className="flex-1 flex flex-col bg-[#0d1117] rounded-xl border border-[#2a3050] overflow-hidden relative">
				<div className="flex flex-wrap items-center justify-between p-3.5 bg-[#141824]/90 border-b border-[#2a3050] gap-3 z-10 sticky top-0">
					<div className="flex flex-wrap items-center gap-3">
						<input
							type="text"
							value={searchTerm}
							onChange={(e) => setSearchTerm(e.target.value)}
							placeholder="Search assets, endpoints..."
							className="bg-[#0a0e1a] border border-[#2a3050] rounded-lg px-3 py-1.5 text-xs text-slate-300 w-52 focus:border-cyan-500 focus:outline-none transition-colors"
						/>
						<div className="flex items-center gap-2">
							<label className="flex items-center gap-1.5 text-xs text-slate-400 select-none cursor-pointer">
								<input
									type="checkbox"
									checked={filterAlertsOnly}
									onChange={(e) => setFilterAlertsOnly(e.target.checked)}
									className="rounded border-[#2a3050] bg-[#0a0e1a] text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
								/>
								Alerts Only
							</label>
							<label className="flex items-center gap-1.5 text-xs text-slate-400 select-none cursor-pointer ml-1">
								<input
									type="checkbox"
									checked={filterNewOnly}
									onChange={(e) => setFilterNewOnly(e.target.checked)}
									className="rounded border-[#2a3050] bg-[#0a0e1a] text-cyan-500 focus:ring-0 focus:ring-offset-0 cursor-pointer"
								/>
								New Only
							</label>
						</div>
					</div>
					<div className="flex items-center gap-1.5 text-[10px] text-slate-500 font-mono">
						<span>Nodes: {nodes.length}</span>
						<span>•</span>
						<span>Edges: {edges.length}</span>
					</div>
				</div>

				{/* React Flow Container */}
				<div className="flex-1 w-full min-h-0 relative h-[450px]">
					<ReactFlow
						nodes={nodes}
						edges={edges}
						onNodesChange={onNodesChange}
						onEdgesChange={onEdgesChange}
						onNodeClick={onNodeClick}
						nodeTypes={nodeTypes}
						className="bg-[#0a0e1a] w-full h-full"
						colorMode="dark"
						fitView
						fitViewOptions={{ padding: 0.3 }}
						maxZoom={1.5}
						minZoom={0.1}
					>
						<Background
							variant={BackgroundVariant.Dots}
							gap={20}
							size={1}
							color="#1d233d"
						/>
						<Controls className="bg-[#1a1f35] border border-[#2a3050] rounded-lg text-slate-300" />
						<MiniMap
							nodeColor={(n) => {
								if (n.data?.has_alert) return "#f87171";
								if (n.data?.is_new) return "#34d399";
								if (n.data?.type === "root") return "#38bdf8";
								return "#2a3050";
							}}
							nodeStrokeWidth={3}
							maskColor="rgba(10, 14, 26, 0.7)"
							className="bg-[#0a0e1a] border border-[#2a3050] rounded-lg overflow-hidden"
						/>
					</ReactFlow>
				</div>
			</div>

			{/* ─── Details Side Panel ────────────────────────────────────────────────── */}
			<div
				className={`w-full lg:w-80 shrink-0 flex flex-col ${selectedNode ? "animate-fade-in" : "hidden lg:flex"}`}
			>
				<div className="glass-card p-5 h-full flex flex-col justify-between min-h-[300px]">
					{selectedNode ? (
						<div className="space-y-5 flex-1 flex flex-col justify-between">
							<div className="space-y-4">
								{/* Node Panel Header */}
								<div className="flex items-center justify-between border-b border-[#2a3050] pb-3">
									<div className="flex items-center gap-2">
										<span
											className={`w-2 h-2 rounded-full ${
												selectedNode.type === "root"
													? "bg-cyan-400"
													: selectedNode.has_alert
														? "bg-red-400 animate-pulse"
														: selectedNode.is_new
															? "bg-emerald-400"
															: "bg-purple-400"
											}`}
										/>
										<h3 className="text-sm font-semibold text-slate-200 capitalize">
											{selectedNode.type} Details
										</h3>
									</div>
									<button
										type="button"
										onClick={clearSelection}
										className="text-xs text-slate-500 hover:text-slate-300 font-bold"
									>
										Clear
									</button>
								</div>

								{/* Properties */}
								<div className="space-y-3.5 text-xs">
									<div>
										<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
											LABEL
										</span>
										<div className="text-slate-200 font-semibold font-mono break-all bg-[#0a0e1a] px-2 py-1.5 rounded border border-[#2a3050]/40">
											{selectedNode.label}
										</div>
									</div>

									{selectedNode.url && (
										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												FULL URL
											</span>
											<a
												href={selectedNode.url}
												target="_blank"
												rel="noreferrer"
												className="text-cyan-400 hover:underline font-mono break-all block bg-[#0a0e1a] px-2 py-1.5 rounded border border-[#2a3050]/40"
											>
												{selectedNode.url}
											</a>
										</div>
									)}

									<div className="grid grid-cols-2 gap-3 pt-1">
										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												NEW ASSET
											</span>
											<span
												className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold ${
													selectedNode.is_new
														? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
														: "bg-slate-800 text-slate-400"
												}`}
											>
												{selectedNode.is_new ? "YES" : "NO"}
											</span>
										</div>

										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												HEALTH STATUS
											</span>
											<span
												className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold ${
													selectedNode.has_alert
														? "bg-red-500/10 text-red-400 border border-red-500/20 animate-pulse"
														: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
												}`}
											>
												{selectedNode.has_alert ? "VULNERABLE" : "SECURE"}
											</span>
										</div>
									</div>

									<div className="grid grid-cols-2 gap-3 pt-1">
										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												RISK SCORE
											</span>
											<span
												className={`inline-block px-2.5 py-0.5 rounded text-[10px] font-bold ${
													(selectedNode.risk_score ?? 0) >= 7.0
														? "bg-red-500/10 text-red-400 border border-red-500/20"
														: (selectedNode.risk_score ?? 0) >= 4.0
															? "bg-orange-500/10 text-orange-400 border border-orange-500/20"
															: (selectedNode.risk_score ?? 0) >= 1.0
																? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
																: "bg-slate-800 text-slate-400 border border-slate-700"
												}`}
											>
												{selectedNode.risk_score !== undefined
													? selectedNode.risk_score.toFixed(1)
													: "0.0"}
												/10.0
											</span>
										</div>

										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												TECH STACK
											</span>
											<div className="flex flex-wrap gap-1">
												{selectedNode.tech_stack &&
												selectedNode.tech_stack.length > 0 ? (
													selectedNode.tech_stack.map((tech: string) => (
														<span
															key={tech}
															className="bg-[#1a1f35]/60 border border-[#2a3050]/50 text-slate-300 px-1.5 py-0.5 rounded text-[9px] font-mono leading-none"
														>
															{tech}
														</span>
													))
												) : (
													<span className="text-slate-600 text-[10px]">
														None detected
													</span>
												)}
											</div>
										</div>
									</div>

									{selectedNode.status_code && (
										<div>
											<span className="text-[10px] text-slate-500 font-mono block mb-0.5">
												HTTP STATUS
											</span>
											<span
												className={`inline-block px-2.5 py-0.5 rounded text-xs font-mono font-bold ${
													selectedNode.status_code >= 200 &&
													selectedNode.status_code < 300
														? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
														: selectedNode.status_code >= 300 &&
																selectedNode.status_code < 400
															? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
															: "bg-red-500/10 text-red-400 border border-red-500/20"
												}`}
											>
												{selectedNode.status_code}
											</span>
										</div>
									)}

									{/* Known CVEs Section */}
									<div className="pt-2">
										<span className="text-[10px] text-slate-500 font-mono block mb-1">
											KNOWN CVES
										</span>
										{selectedNode.known_cves &&
										selectedNode.known_cves.length > 0 ? (
											<div className="max-h-36 overflow-y-auto space-y-1.5 pr-1 custom-scrollbar">
												{selectedNode.known_cves.map(
													(cve: {
														cve_id: string;
														severity: string;
														cvss: number | string;
														description: string;
													}) => (
														<div
															key={cve.cve_id}
															className="p-2 rounded border border-[#2a3050]/40 bg-[#0a0e1a]/80 text-[11px]"
														>
															<div className="flex items-center justify-between mb-1">
																<span className="text-red-400 font-bold font-mono">
																	{cve.cve_id}
																</span>
																<span
																	className={`px-1.5 py-0.5 rounded text-[8px] font-mono font-bold ${
																		cve.severity.toLowerCase() === "critical"
																			? "bg-red-500/20 text-red-400 border border-red-500/30"
																			: cve.severity.toLowerCase() === "high"
																				? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
																				: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30"
																	}`}
																>
																	{cve.severity} (CVSS: {cve.cvss})
																</span>
															</div>
															<p className="text-slate-400 leading-normal">
																{cve.description}
															</p>
														</div>
													),
												)}
											</div>
										) : (
											<div className="text-slate-600 text-[11px] italic bg-[#0a0e1a]/30 p-2 rounded border border-[#2a3050]/20">
												No associated CVEs found
											</div>
										)}
									</div>

									{/* Shadow APIs Section */}
									<div className="pt-2">
										<span className="text-[10px] text-slate-500 font-mono block mb-1">
											SHADOW APIS
										</span>
										{selectedNode.shadow_apis &&
										selectedNode.shadow_apis.length > 0 ? (
											<div className="max-h-32 overflow-y-auto space-y-1 pr-1 custom-scrollbar">
												{selectedNode.shadow_apis.map((route: string) => (
													<div
														key={route}
														className="px-2.5 py-1.5 rounded border border-[#2a3050]/30 bg-[#0a0e1a]/70 font-mono text-[10px] text-purple-300 break-all"
													>
														🔑 {route}
													</div>
												))}
											</div>
										) : (
											<div className="text-slate-600 text-[11px] italic bg-[#0a0e1a]/30 p-2 rounded border border-[#2a3050]/20">
												No shadow routes discovered
											</div>
										)}
									</div>

									{/* Autonomous AI Triage Section */}
									<div className="pt-2 border-t border-[#2a3050]/40">
										<span className="text-[10px] text-slate-500 font-mono block mb-1.5">
											AUTONOMOUS AI TRIAGE
										</span>
										{triageResult ? (
											<div className="p-3 rounded-lg border border-cyan-500/30 bg-[#081525]/60 text-[11px] text-slate-300 leading-relaxed font-mono">
												<div className="flex items-center gap-1.5 text-cyan-400 font-bold mb-1.5 uppercase text-[9px] tracking-wider">
													<span>🤖 AI Verdict</span>
												</div>
												{triageResult}
											</div>
										) : isTriaging ? (
											<div className="p-3 rounded-lg border border-[#2a3050]/40 bg-[#0a0e1a]/50 space-y-2 animate-pulse">
												<div className="h-3 w-2/5 bg-slate-800 rounded"></div>
												<div className="h-2 w-full bg-slate-800 rounded"></div>
												<div className="h-2 w-5/6 bg-slate-800 rounded"></div>
												<div className="h-2 w-4/5 bg-slate-800 rounded"></div>
											</div>
										) : (
											<button
												type="button"
												onClick={handleAITriage}
												className="w-full bg-[#0d2137] border border-cyan-500/30 text-cyan-400 px-3 py-2 rounded-lg text-xs font-semibold hover:bg-cyan-500/10 hover:border-cyan-400 transition-colors"
											>
												⚡ Generate AI Triage
											</button>
										)}
									</div>
								</div>
							</div>

							{/* Action Button */}
							<div className="pt-4 border-t border-[#2a3050] mt-auto">
								<button
									type="button"
									onClick={() => {
										navigator.clipboard.writeText(
											selectedNode.url || selectedNode.label,
										);
									}}
									className="flex items-center justify-center gap-2 w-full bg-[#1a1f35] border border-[#2a3050] text-slate-300 px-4 py-2 rounded-lg text-xs font-medium hover:border-cyan-500/40 hover:text-white transition-colors"
								>
									<Copy className="w-3.5 h-3.5" /> Copy Target URL/Label
								</button>
							</div>
						</div>
					) : (
						<div className="flex flex-col items-center justify-center text-center h-full text-slate-600">
							<div className="text-3xl mb-2">⬡</div>
							<p className="text-xs font-medium">
								Select a node in the graph to view detailed security context
							</p>
						</div>
					)}
				</div>
			</div>
		</div>
	);
});

export default ArchitectureMap;
