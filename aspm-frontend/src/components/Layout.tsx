import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Cpu, Play, Plus, Shield, Trash2 } from "lucide-react";
import React, { useMemo, useState } from "react";
import {
    Bar,
    BarChart,
    Cell,
    Legend,
    Pie,
    PieChart,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";
import { apiClient, type ScopeRule, type TopologyData } from "../services/apiClient";
import { useShallow } from "zustand/react/shallow";
import { type Finding, type Target, useSecurityStore } from "../store";
import ArchitectureMap from "./ArchitectureMap";
import DataGrid from "./DataGrid";
import DetailPanel from "./DetailPanel";
import Header from "./Header";
import { AiDrawer } from "./AiDrawer";
import LogicMapViewer from "./LogicMapViewer";
import Sidebar from "./Sidebar";
import TerminalConsole from "./TerminalConsole";
import HardwareMonitor from "./HardwareMonitor";
import EvasionConfigPanel from "./EvasionConfigPanel";
import SettingsView from "../views/SettingsView";
import PromptEditor from "./PromptEditor";
import { Button } from "./ui/button";
import {
    Select,
    SelectContent,
    SelectItem,
    SelectTrigger,
    SelectValue,
} from "./ui/select";

export default function Layout() {
    const queryClient = useQueryClient();
    const {
        tab,
        selectedTargetId,
        setSelectedTargetId,
        selectedFindingId,
        setSelectedFindingId,
        connectWebSocket,
        disconnectWebSocket,
        startHealthPolling,
        stopHealthPolling,
        isEcoMode,
    } = useSecurityStore(
        useShallow((state) => ({
            tab: state.tab,
            selectedTargetId: state.selectedTargetId,
            setSelectedTargetId: state.setSelectedTargetId,
            selectedFindingId: state.selectedFindingId,
            setSelectedFindingId: state.setSelectedFindingId,
            connectWebSocket: state.connectWebSocket,
            disconnectWebSocket: state.disconnectWebSocket,
            startHealthPolling: state.startHealthPolling,
            stopHealthPolling: state.stopHealthPolling,
            isEcoMode: state.isEcoMode,
        }))
    );

    // ─── Initialize WebSocket and Health Polling ────────────────────────────────
    React.useEffect(() => {
        connectWebSocket();
        startHealthPolling();
        return () => {
            disconnectWebSocket();
            stopHealthPolling();
        };
    }, [
        connectWebSocket,
        disconnectWebSocket,
        startHealthPolling,
        stopHealthPolling,
    ]);

    // ─── Sync Eco Mode Class to Body ────────────────────────────────────────────
    React.useEffect(() => {
        if (isEcoMode) {
            document.body.classList.add("eco-mode");
        } else {
            document.body.classList.remove("eco-mode");
        }
    }, [isEcoMode]);

    // ─── Invalidate queries on job status change ─────────────────────────────────
    React.useEffect(() => {
        const handleJobStatus = () => {
            queryClient.invalidateQueries({ queryKey: ["targets"] });
            queryClient.invalidateQueries({ queryKey: ["findings"] });
        };
        window.addEventListener("sentinel_job_status", handleJobStatus);
        return () =>
            window.removeEventListener("sentinel_job_status", handleJobStatus);
    }, [queryClient]);

    // ─── Server State Queries ───────────────────────────────────────────────────
    const { data: targets = [], isLoading: loadingTargets } = useQuery<Target[]>({
        queryKey: ["targets"],
        queryFn: apiClient.getTargets,
    });

    const { data: findings = [], isLoading: loadingFindings } = useQuery<Finding[]>({
        queryKey: ["findings"],
        queryFn: apiClient.getFindings,
    });

    const { data: scopeRules = [], isLoading: loadingScopeRules } = useQuery<ScopeRule[]>({
        queryKey: ["scopeRules"],
        queryFn: apiClient.getScopeRules,
    });

    const emptyTopology = useMemo<TopologyData>(() => ({ nodes: [], edges: [] }), []);
    const { data: topologyData = emptyTopology, isLoading: loadingTopology } =
        useQuery<TopologyData>({
            queryKey: ["topology", selectedTargetId],
            queryFn: () => apiClient.getTopology(selectedTargetId as string),
            enabled: Boolean(selectedTargetId),
        });

    // ─── Mutations ──────────────────────────────────────────────────────────────
    const addTargetMutation = useMutation({
        mutationFn: apiClient.addTarget,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["targets"] }),
    });

    const deleteTargetMutation = useMutation({
        mutationFn: apiClient.deleteTarget,
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["targets"] });
            queryClient.invalidateQueries({ queryKey: ["findings"] });
        },
    });

    const updateFindingStatusMutation = useMutation({
        mutationFn: ({ id, status }: { id: string; status: Finding["status"] }) =>
            apiClient.updateFindingStatus(id, status),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["findings"] }),
    });

    const addScopeRuleMutation = useMutation({
        mutationFn: apiClient.addScopeRule,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scopeRules"] }),
    });

    const deleteScopeRuleMutation = useMutation({
        mutationFn: apiClient.deleteScopeRule,
        onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scopeRules"] }),
    });

    // ─── Form States ────────────────────────────────────────────────────────────
    const [newTargetName, setNewTargetName] = useState("");
    const [newTargetHost, setNewTargetHost] = useState("");
    const [newTargetPort, setNewTargetPort] = useState<number | "">("");
    const [newTargetTags, setNewTargetTags] = useState("");
    const [newTargetNotes, setNewTargetNotes] = useState("");
    const [selectedScanProfile, setSelectedScanProfile] = useState("APEX Engine");

    const [newRuleType, setNewRuleType] = useState<"include" | "exclude">("include");
    const [newRulePattern, setNewRulePattern] = useState("");
    const [newRuleDesc, setNewRuleDesc] = useState("");

    // AI Drawer States
    const [aiDrawerOpen, setAiDrawerOpen] = useState(false);
    const [aiDrawerMode, setAiDrawerMode] = useState<"remediation" | "exploit_flow">("remediation");
    const [promptEditorOpen, setPromptEditorOpen] = useState(false);

    // ─── Calculations ───────────────────────────────────────────────────────────
    const activeFinding = useMemo(() => {
        return findings.find((f) => f.id === selectedFindingId) || null;
    }, [findings, selectedFindingId]);

    const stats = useMemo(() => {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        const categories: Record<string, number> = {};

        findings.forEach((f) => {
            if (counts[f.severity] !== undefined) {
                counts[f.severity]++;
            }
            categories[f.category] = (categories[f.category] || 0) + 1;
        });

        return { counts, categories };
    }, [findings]);

    const severityChartData = useMemo(() => {
        return [
            { name: "Critical", value: stats.counts.critical, color: "#ef4444" },
            { name: "High", value: stats.counts.high, color: "#f97316" },
            { name: "Medium", value: stats.counts.medium, color: "#eab308" },
            { name: "Low", value: stats.counts.low, color: "#3b82f6" },
            { name: "Info", value: stats.counts.info, color: "#64748b" },
        ].filter((item) => item.value > 0);
    }, [stats]);

    const categoryChartData = useMemo(() => {
        return Object.entries(stats.categories).map(([name, count]) => ({
            name,
            count,
        }));
    }, [stats]);

    // ─── Action Handlers ────────────────────────────────────────────────────────
    const handleAddTarget = React.useCallback((e: React.FormEvent) => {
        e.preventDefault();
        if (!newTargetName || !newTargetHost) return;
        addTargetMutation.mutate({
            name: newTargetName,
            host: newTargetHost,
            port: newTargetPort === "" ? null : newTargetPort,
            tags: newTargetTags
                .split(",")
                .map((t) => t.trim())
                .filter(Boolean),
            notes: newTargetNotes,
        });
        setNewTargetName("");
        setNewTargetHost("");
        setNewTargetPort("");
        setNewTargetTags("");
        setNewTargetNotes("");
    }, [newTargetName, newTargetHost, newTargetPort, newTargetTags, newTargetNotes, addTargetMutation]);

    const handleLaunchScan = React.useCallback(async () => {
        if (!selectedTargetId) return;
        try {
            await apiClient.triggerScanJob(selectedTargetId, selectedScanProfile);
            alert("Scan execution job initiated successfully.");
        } catch (e) {
            const message = e instanceof Error ? e.message : String(e);
            alert(`Error starting job: ${message}`);
        }
    }, [selectedTargetId, selectedScanProfile]);

    const handleAddScopeRule = React.useCallback((e: React.FormEvent) => {
        e.preventDefault();
        if (!newRulePattern) return;
        addScopeRuleMutation.mutate({
            rule_type: newRuleType,
            pattern_type: newRulePattern.includes("*") ? "wildcard" : "domain",
            pattern: newRulePattern,
            description: newRuleDesc,
        });
        setNewRulePattern("");
        setNewRuleDesc("");
    }, [newRulePattern, newRuleType, newRuleDesc, addScopeRuleMutation]);

    const handleDeleteScopeRule = React.useCallback((id: string) => {
        deleteScopeRuleMutation.mutate(id);
    }, [deleteScopeRuleMutation]);

    return (
        <div className="flex w-screen h-screen overflow-hidden bg-[#050505] text-slate-100 font-sans relative selection:bg-brand-500/30 selection:text-white">
            {/* Ambient Background Glows */}
            {!isEcoMode && (
                <div className="aurora-container" aria-hidden="true">
                    <div className="aurora-blob aurora-purple" />
                    <div className="aurora-blob aurora-emerald" />
                    <div className="aurora-blob aurora-blue" />
                </div>
            )}

            {/* 1. Sidebar Panel */}
            <Sidebar />

            {/* 2. Main Workstation Panel */}
            <div className="flex-1 flex flex-col h-full min-w-0 z-10 relative">
                <Header />
                
                {/* 3. Panel Switcher Workspace - min-h-0 prevents flex collapse */}
                <main className="flex-1 min-h-0 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                    
                    {/* A. DASHBOARD VIEW */}
                    {tab === "dashboard" && (
                        <div className="space-y-4">
                            {/* Stat Cards Grid */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                                <div className="glass-card p-4 select-none flex items-center justify-between shadow-lg">
                                    <div>
                                        <h4 className="text-[10px] text-zinc-500 uppercase font-mono tracking-wider font-bold">
                                            Total Targets
                                        </h4>
                                        <span className="text-xl font-extrabold font-mono text-zinc-200">
                                            {targets.length}
                                        </span>
                                    </div>
                                    <Shield className="w-7 h-7 text-cyan-600/35" />
                                </div>
                                <div className="glass-card p-4 select-none flex items-center justify-between shadow-lg">
                                    <div>
                                        <h4 className="text-[10px] text-zinc-500 uppercase font-mono tracking-wider font-bold">
                                            Critical Vulnerabilities
                                        </h4>
                                        <span className="text-xl font-extrabold font-mono text-red-500">
                                            {stats.counts.critical}
                                        </span>
                                    </div>
                                    <AlertTriangle className="w-7 h-7 text-red-500/40" />
                                </div>
                                <div className="glass-card p-4 select-none flex items-center justify-between shadow-lg">
                                    <div>
                                        <h4 className="text-[10px] text-zinc-500 uppercase font-mono tracking-wider font-bold">
                                            High Severity
                                        </h4>
                                        <span className="text-xl font-extrabold font-mono text-orange-500">
                                            {stats.counts.high}
                                        </span>
                                    </div>
                                    <AlertTriangle className="w-7 h-7 text-orange-500/40" />
                                </div>
                                <div className="glass-card p-4 select-none flex items-center justify-between shadow-lg">
                                    <div>
                                        <h4 className="text-[10px] text-zinc-500 uppercase font-mono tracking-wider font-bold">
                                            Total Ingested
                                        </h4>
                                        <span className="text-xl font-extrabold font-mono text-zinc-300">
                                            {findings.length}
                                        </span>
                                    </div>
                                    <Cpu className="w-7 h-7 text-zinc-700/40" />
                                </div>
                            </div>

                            {/* Data Visualization Charts */}
                            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {/* Severity Distribution Donut */}
                                <div className="glass-card p-5 flex flex-col h-[280px] min-h-[280px]">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 mb-2 uppercase tracking-wider">
                                        Severity Distribution
                                    </h3>
                                    <div className="flex-1 w-full h-full min-h-[200px] min-w-0 relative">
                                        {severityChartData.length === 0 ? (
                                            <div className="h-full flex items-center justify-center text-xs text-zinc-500 italic font-mono">
                                                No vulnerability records to chart.
                                            </div>
                                        ) : (
                                            <ResponsiveContainer width="100%" height="100%">
                                                <PieChart>
                                                    <defs>
                                                        <linearGradient id="grad-Critical" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="0%" stopColor="#ef4444" />
                                                            <stop offset="100%" stopColor="#991b1b" />
                                                        </linearGradient>
                                                        <linearGradient id="grad-High" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="0%" stopColor="#f97316" />
                                                            <stop offset="100%" stopColor="#c2410c" />
                                                        </linearGradient>
                                                        <linearGradient id="grad-Medium" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="0%" stopColor="#eab308" />
                                                            <stop offset="100%" stopColor="#854d0e" />
                                                        </linearGradient>
                                                        <linearGradient id="grad-Low" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="0%" stopColor="#3b82f6" />
                                                            <stop offset="100%" stopColor="#1e3a8a" />
                                                        </linearGradient>
                                                        <linearGradient id="grad-Info" x1="0" y1="0" x2="0" y2="1">
                                                            <stop offset="0%" stopColor="#a855f7" />
                                                            <stop offset="100%" stopColor="#6b21a8" />
                                                        </linearGradient>
                                                    </defs>
                                                    <Pie
                                                        data={severityChartData}
                                                        cx="50%"
                                                        cy="47%"
                                                        innerRadius={55}
                                                        outerRadius={75}
                                                        paddingAngle={4}
                                                        dataKey="value"
                                                        stroke="rgba(0,0,0,0.5)"
                                                        strokeWidth={1.5}
                                                    >
                                                        {severityChartData.map((entry) => (
                                                            <Cell key={entry.name} fill={`url(#grad-${entry.name})`} />
                                                        ))}
                                                    </Pie>
                                                    <Tooltip
                                                        contentStyle={{
                                                            backgroundColor: "rgba(9, 9, 11, 0.95)",
                                                            borderColor: "rgba(255,255,255,0.1)",
                                                            borderRadius: "8px",
                                                            fontSize: "11px",
                                                            fontFamily: "monospace",
                                                            backdropFilter: "blur(8px)",
                                                            boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.5)",
                                                        }}
                                                        itemStyle={{ color: "#cbd5e1" }}
                                                    />
                                                    <Legend
                                                        verticalAlign="bottom"
                                                        height={36}
                                                        iconType="circle"
                                                        iconSize={8}
                                                        wrapperStyle={{
                                                            fontSize: "10px",
                                                            fontFamily: "monospace",
                                                            color: "#a1a1aa",
                                                            paddingTop: "10px",
                                                        }}
                                                    />
                                                </PieChart>
                                            </ResponsiveContainer>
                                        )}
                                    </div>
                                </div>

                                {/* Categories Bar Chart */}
                                <div className="glass-card p-5 flex flex-col h-[280px] min-h-[280px]">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 mb-2 uppercase tracking-wider">
                                        Findings by Category
                                    </h3>
                                    <div className="flex-1 w-full h-full min-h-[200px] min-w-0 relative">
                                        {categoryChartData.length === 0 ? (
                                            <div className="h-full flex items-center justify-center text-xs text-zinc-500 italic font-mono">
                                                No vulnerability records to chart.
                                            </div>
                                        ) : (
                                            <ResponsiveContainer width="100%" height="100%">
                                                <BarChart
                                                    data={categoryChartData}
                                                    layout="vertical"
                                                    margin={{ left: -10, right: 10, top: 5, bottom: 5 }}
                                                >
                                                    <defs>
                                                        <linearGradient id="barGrad" x1="0" y1="0" x2="1" y2="0">
                                                            <stop offset="0%" stopColor="#a855f7" stopOpacity={0.4} />
                                                            <stop offset="100%" stopColor="#d946ef" stopOpacity={0.85} />
                                                        </linearGradient>
                                                    </defs>
                                                    <XAxis
                                                        type="number"
                                                        stroke="rgba(255,255,255,0.15)"
                                                        fontSize={9}
                                                        tickLine={false}
                                                        tick={{ fill: "#71717a", fontFamily: "monospace" }}
                                                    />
                                                    <YAxis
                                                        dataKey="name"
                                                        type="category"
                                                        stroke="rgba(255,255,255,0.15)"
                                                        fontSize={9}
                                                        width={100}
                                                        tickLine={false}
                                                        tick={{ fill: "#d4d4d8", fontFamily: "monospace" }}
                                                    />
                                                    <Tooltip
                                                        contentStyle={{
                                                            backgroundColor: "rgba(9, 9, 11, 0.95)",
                                                            borderColor: "rgba(255,255,255,0.1)",
                                                            borderRadius: "8px",
                                                            fontSize: "11px",
                                                            fontFamily: "monospace",
                                                            backdropFilter: "blur(8px)",
                                                        }}
                                                        itemStyle={{ color: "#cbd5e1" }}
                                                    />
                                                    <Bar
                                                        dataKey="count"
                                                        fill="url(#barGrad)"
                                                        stroke="#d946ef"
                                                        strokeWidth={1}
                                                        radius={[0, 4, 4, 0]}
                                                    />
                                                </BarChart>
                                            </ResponsiveContainer>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Launcher & Stream Terminal side-by-side */}
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                {/* Launcher panel */}
                                <div className="glass-card p-5 space-y-4 shadow-lg">
                                    <h3 className="text-[11px] font-medium font-sans text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                        <div className="w-1.5 h-1.5 rounded-full bg-cyan-500 shadow-[0_0_8px_rgba(6,182,212,0.6)]"></div>
                                        Quick Job Launcher
                                    </h3>

                                    <div className="space-y-3">
                                        <div className="space-y-1.5">
                                            <span className="text-[10px] font-medium text-zinc-500 uppercase font-sans tracking-wide block">
                                                Target Host
                                            </span>
                                            <Select
                                                value={selectedTargetId}
                                                onValueChange={(val) => setSelectedTargetId(val || "")}
                                            >
                                                <SelectTrigger className="w-full bg-black/50 border-white/10 text-xs font-mono text-zinc-300 h-8 focus:ring-1 focus:ring-brand-500/50">
                                                    <SelectValue placeholder="Select target domain..." />
                                                </SelectTrigger>
                                                <SelectContent className="bg-black/90 border-white/10">
                                                    {targets.map((t) => (
                                                        <SelectItem
                                                            key={t.id}
                                                            value={t.id}
                                                            className="text-xs font-mono text-zinc-300 focus:bg-white/10 focus:text-white"
                                                        >
                                                            {t.name}{" "}
                                                            <span className="text-zinc-500 ml-1">
                                                                ({t.host})
                                                            </span>
                                                        </SelectItem>
                                                    ))}
                                                </SelectContent>
                                            </Select>
                                        </div>

                                        <div className="space-y-1.5">
                                            <span className="text-[10px] font-medium text-zinc-500 uppercase font-sans tracking-wide block">
                                                Scan Profile
                                            </span>
                                            <Select
                                                value={selectedScanProfile}
                                                onValueChange={(val) =>
                                                    setSelectedScanProfile(val || "")
                                                }
                                            >
                                                <SelectTrigger className="w-full bg-black/50 border-white/10 text-xs font-mono text-zinc-300 h-8 focus:ring-1 focus:ring-brand-500/50">
                                                    <SelectValue placeholder="Select profile..." />
                                                </SelectTrigger>
                                                <SelectContent className="bg-black/90 border-white/10">
                                                    <SelectItem
                                                        value="APEX Engine"
                                                        className="text-xs font-mono text-zinc-300 focus:bg-white/10 focus:text-white"
                                                    >
                                                        APEX Engine
                                                    </SelectItem>
                                                    <SelectItem
                                                        value="Subdomain Recon"
                                                        className="text-xs font-mono text-zinc-300 focus:bg-white/10 focus:text-white"
                                                    >
                                                        Subdomain Recon
                                                    </SelectItem>
                                                    <SelectItem
                                                        value="Active Auditing"
                                                        className="text-xs font-mono text-slate-300"
                                                    >
                                                        Active Auditing
                                                    </SelectItem>
                                                    <SelectItem
                                                        value="Cognitive AI Recon"
                                                        className="text-xs font-mono text-purple-400 font-bold"
                                                        style={{
                                                            fontFamily:
                                                                "'JetBrains Mono', 'Fira Code', monospace",
                                                        }}
                                                    >
                                                        Cognitive AI Recon
                                                    </SelectItem>
                                                </SelectContent>
                                            </Select>
                                        </div>

                                        <Button
                                            onClick={handleLaunchScan}
                                            disabled={!selectedTargetId}
                                            className="w-full h-8 flex items-center justify-center gap-2 bg-cyan-600/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 hover:text-cyan-300 transition-all font-sans text-[11px] font-medium tracking-wide uppercase shadow-[inset_0_1px_0_0_rgba(6,182,212,0.2)] disabled:opacity-50"
                                        >
                                            <Play className="w-3.5 h-3.5" />
                                            Dispatch Scan
                                        </Button>
                                    </div>
                                </div>

                                {/* Collapsible log view */}
                                <div className="lg:col-span-2">
                                    <TerminalConsole />
                                </div>
                            </div>

                            {/* Live hardware monitoring dashboard */}
                            <HardwareMonitor />
                        </div>
                    )}

                    {/* B. TARGETS MANAGEMENT VIEW */}
                    {tab === "targets" && (
                        <div className="space-y-4">
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                {/* Target CRUD Add form */}
                                <div className="glass-card p-5 space-y-4 shadow-lg">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-white/5 pb-2">
                                        <Plus className="w-4 h-4 text-cyan-500" />
                                        Register New Target
                                    </h3>

                                    <form
                                        onSubmit={handleAddTarget}
                                        className="space-y-3.5 font-mono text-xs"
                                    >
                                        <div className="space-y-1">
                                            <label
                                                htmlFor="friendly-name"
                                                className="text-[10px] text-zinc-500 uppercase font-bold"
                                            >
                                                Friendly Name
                                            </label>
                                            <input
                                                id="friendly-name"
                                                type="text"
                                                placeholder="e.g. Payments API"
                                                value={newTargetName}
                                                onChange={(e) => setNewTargetName(e.target.value)}
                                                className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                                                required
                                            />
                                        </div>

                                        <div className="space-y-1">
                                            <label
                                                htmlFor="host-domain"
                                                className="text-[10px] text-zinc-500 uppercase font-bold"
                                            >
                                                Host / Domain
                                            </label>
                                            <input
                                                id="host-domain"
                                                type="text"
                                                placeholder="e.g. secure.gateway.com"
                                                value={newTargetHost}
                                                onChange={(e) => setNewTargetHost(e.target.value)}
                                                className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                                                required
                                            />
                                        </div>

                                        <div className="space-y-1">
                                            <label
                                                htmlFor="target-port"
                                                className="text-[10px] text-zinc-500 uppercase font-bold"
                                            >
                                                Port (Optional)
                                            </label>
                                            <input
                                                id="target-port"
                                                type="number"
                                                placeholder="e.g. 443"
                                                value={newTargetPort}
                                                onChange={(e) =>
                                                    setNewTargetPort(
                                                        e.target.value === ""
                                                            ? ""
                                                            : parseInt(e.target.value, 10),
                                                    )
                                                }
                                                className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                                            />
                                        </div>

                                        <div className="space-y-1">
                                            <label
                                                htmlFor="target-tags"
                                                className="text-[10px] text-zinc-500 uppercase font-bold"
                                            >
                                                Tags (Comma-separated)
                                            </label>
                                            <input
                                                id="target-tags"
                                                type="text"
                                                placeholder="e.g. prod, external"
                                                value={newTargetTags}
                                                onChange={(e) => setNewTargetTags(e.target.value)}
                                                className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500"
                                            />
                                        </div>

                                        <div className="space-y-1">
                                            <label
                                                htmlFor="operational-notes"
                                                className="text-[10px] text-zinc-500 uppercase font-bold"
                                            >
                                                Operational Notes
                                            </label>
                                            <textarea
                                                id="operational-notes"
                                                placeholder="Enter target scope boundaries..."
                                                value={newTargetNotes}
                                                onChange={(e) => setNewTargetNotes(e.target.value)}
                                                className="w-full h-16 bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-brand-500 focus:ring-1 focus:ring-brand-500 resize-none font-sans"
                                            />
                                        </div>

                                        <button
                                            type="submit"
                                            disabled={addTargetMutation.isPending}
                                            className="w-full py-2 px-3 rounded bg-cyan-600 text-white font-bold hover:bg-cyan-500 transition-colors shadow-md shadow-cyan-600/10"
                                        >
                                            {addTargetMutation.isPending
                                                ? "REGISTERING..."
                                                : "REGISTER TARGET"}
                                        </button>
                                    </form>
                                </div>

                                {/* Targets listing grid */}
                                <div className="lg:col-span-2 space-y-3">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider">
                                        Registered Targets Scope
                                    </h3>
                                    {loadingTargets ? (
                                        <div className="text-xs font-mono text-zinc-500 animate-pulse">
                                            Querying target scopes...
                                        </div>
                                    ) : targets.length === 0 ? (
                                        <div className="glass-card border-white/5 bg-black/20 p-6 text-center text-xs text-zinc-500 italic font-mono">
                                            No targets registered in this workstation context.
                                        </div>
                                    ) : (
                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            {targets.map((target) => (
                                                <div
                                                    key={target.id}
                                                    className="glass-card p-4 space-y-2 flex flex-col justify-between font-mono text-xs select-none shadow-md"
                                                >
                                                    <div className="space-y-1">
                                                        <div className="flex justify-between items-start">
                                                            <h4 className="font-bold text-zinc-200">
                                                                {target.name}
                                                            </h4>
                                                            <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-black/40 text-zinc-400 border border-white/10">
                                                                RISK: {target.risk_score}
                                                            </span>
                                                        </div>
                                                        <p className="text-[10px] text-zinc-500">
                                                            {target.host}
                                                            {target.port ? `:${target.port}` : ""}
                                                        </p>
                                                        <p className="text-[11px] text-zinc-400 font-sans leading-normal line-clamp-2 mt-1">
                                                            {target.notes}
                                                        </p>
                                                    </div>

                                                    <div className="mt-3 flex items-center justify-between border-t border-white/5 pt-2">
                                                        <div className="flex flex-wrap gap-1">
                                                            {target.tags.map((tag) => (
                                                                <span
                                                                    key={tag}
                                                                    className="px-1.5 py-0.5 rounded bg-black/40 text-cyan-500 text-[8px] font-bold border border-white/5"
                                                                >
                                                                    {tag}
                                                                </span>
                                                            ))}
                                                        </div>

                                                        <button
                                                            type="button"
                                                            onClick={() =>
                                                                deleteTargetMutation.mutate(target.id)
                                                            }
                                                            className="p-1 rounded text-zinc-500 hover:text-red-400 hover:bg-zinc-800/40 transition-colors"
                                                            title="Delete target scope"
                                                        >
                                                            <Trash2 className="w-3.5 h-3.5" />
                                                        </button>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* C. FINDINGS VULNERABILITY STREAM */}
                    {tab === "findings" && (
                        <div className="flex flex-col lg:flex-row gap-4 h-[calc(100vh-80px)] overflow-hidden">
                            <div className="flex-1 min-w-0 h-full">
                                {loadingFindings ? (
                                    <div className="text-xs font-mono text-slate-500">
                                        Syncing telemetry data...
                                    </div>
                                ) : (
                                    <DataGrid
                                        findings={findings}
                                        selectedFindingId={selectedFindingId}
                                        onSelectFinding={setSelectedFindingId}
                                        onUpdateStatus={(id, status) =>
                                            updateFindingStatusMutation.mutate({ id, status })
                                        }
                                    />
                                )}
                            </div>

                            {activeFinding && (
                                <div className="shrink-0 h-full lg:h-auto">
                                    <DetailPanel
                                        finding={activeFinding}
                                        onClose={() => setSelectedFindingId(null)}
                                        onAnalyzeExploitFlow={() => {
                                            setPromptEditorOpen(true);
                                        }}
                                        onGenerateRemediation={() => {
                                            setAiDrawerMode("remediation");
                                            setAiDrawerOpen(true);
                                        }}
                                    />
                                </div>
                            )}
                        </div>
                    )}

                    {/* D. SCOPE POLICIES VIEW */}
                    {tab === "scope" && (
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            {/* Scope creation Form */}
                            {/* Scope creation Form */}
                            <div className="glass-card p-5 space-y-4 shadow-lg">
                                <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5 border-b border-white/5 pb-2">
                                    <Plus className="w-4 h-4 text-cyan-500" />
                                    Define Scope Constraint
                                </h3>

                                <form
                                    onSubmit={handleAddScopeRule}
                                    className="space-y-3.5 font-mono text-xs"
                                >
                                    <div className="space-y-1">
                                        <span className="text-[10px] text-zinc-500 uppercase font-bold block">
                                            Rule Action
                                        </span>
                                        <Select
                                            value={newRuleType}
                                            onValueChange={(v) =>
                                                setNewRuleType((v || "include") as "include" | "exclude")
                                            }
                                        >
                                            <SelectTrigger className="w-full bg-black/50 border-white/10 text-zinc-300 h-8">
                                                <SelectValue />
                                            </SelectTrigger>
                                            <SelectContent>
                                                <SelectItem value="include">INCLUDE Scope</SelectItem>
                                                <SelectItem value="exclude">EXCLUDE Scope</SelectItem>
                                            </SelectContent>
                                        </Select>
                                    </div>

                                    <div className="space-y-1">
                                        <label
                                            htmlFor="glob-pattern"
                                            className="text-[10px] text-zinc-500 uppercase font-bold"
                                        >
                                            Glob / Pattern
                                        </label>
                                        <input
                                            id="glob-pattern"
                                            type="text"
                                            placeholder="e.g. *.internal.gateway.com"
                                            value={newRulePattern}
                                            onChange={(e) => setNewRulePattern(e.target.value)}
                                            className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-500"
                                            required
                                        />
                                    </div>

                                    <div className="space-y-1">
                                        <label
                                            htmlFor="rule-desc"
                                            className="text-[10px] text-zinc-500 uppercase font-bold"
                                        >
                                            Description
                                        </label>
                                        <input
                                            id="rule-desc"
                                            type="text"
                                            placeholder="Identify boundary ownership context..."
                                            value={newRuleDesc}
                                            onChange={(e) => setNewRuleDesc(e.target.value)}
                                            className="w-full bg-black/50 border border-white/10 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-500"
                                        />
                                    </div>

                                    <Button
                                        type="submit"
                                        className="w-full bg-cyan-600 text-white font-bold hover:bg-cyan-500 shadow-md shadow-cyan-600/10"
                                    >
                                        ADD SCOPE CONSTRAINT
                                    </Button>
                                </form>
                            </div>

                            {/* Scope rules Table */}
                            <div className="lg:col-span-2 glass-card p-5 space-y-4 shadow-lg select-none">
                                <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider border-b border-white/5 pb-2">
                                    Active Scope Boundaries
                                </h3>
                                <div className="overflow-x-auto border border-white/5 rounded-xl">
                                    <table className="w-full font-mono text-xs text-left">
                                        <thead className="bg-black/40 text-zinc-500 text-[10px] font-bold uppercase tracking-wider border-b border-white/5">
                                            <tr>
                                                <th className="p-2.5">Action</th>
                                                <th className="p-2.5">Pattern</th>
                                                <th className="p-2.5">Description</th>
                                                <th className="p-2.5" />
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/5 text-zinc-300">
                                            {scopeRules.map((rule) => (
                                                <tr key={rule.id} className="hover:bg-white/[0.02] transition-colors">
                                                    <td className="p-2.5 font-bold">
                                                        <span
                                                            className={`px-1.5 py-0.5 rounded text-[10px] tracking-wide uppercase ${
                                                                rule.rule_type === "include"
                                                                    ? "text-emerald-400 bg-emerald-950/20 border border-emerald-900/40"
                                                                    : "text-red-400 bg-red-950/20 border border-red-900/40"
                                                            }`}
                                                        >
                                                            {rule.rule_type}
                                                        </span>
                                                    </td>
                                                    <td className="p-2.5 text-zinc-200 font-semibold">
                                                        {rule.pattern}
                                                    </td>
                                                    <td className="p-2.5 text-zinc-400 font-sans">
                                                        {rule.description}
                                                    </td>
                                                    <td className="p-2.5 text-right pr-4">
                                                        <button
                                                            type="button"
                                                            onClick={() => handleDeleteScopeRule(rule.id)}
                                                            className="p-1 rounded text-zinc-500 hover:text-red-400 hover:bg-zinc-800/40 transition-colors"
                                                            title="Delete Scope Rule"
                                                            aria-label="Delete Scope Rule"
                                                        >
                                                            <Trash2 className="w-3.5 h-3.5" />
                                                        </button>
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* G. EVASION CONFIG VIEW */}
                    {tab === "evasion" && (
                        <EvasionConfigPanel />
                    )}

                    {/* E. TOPOLOGY GRAPH VIEW */}
                    {tab === "topology" && (
                        <div className="space-y-4">
                            <div className="glass-card p-5 flex flex-col h-[540px] shadow-lg">
                                <div className="p-2 border-b border-white/5 bg-black/20 flex items-center justify-between select-none">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider">
                                        Infrastructure Surface Graph Map
                                    </h3>
                                    <div className="flex gap-2">
                                        <span className="flex items-center gap-1.5 text-[9px] font-mono text-zinc-500">
                                            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
                                            Domain
                                        </span>
                                        <span className="flex items-center gap-1.5 text-[9px] font-mono text-zinc-500">
                                            <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                                            Alert Triggered
                                        </span>
                                    </div>
                                </div>

                                {/* Embedded React Flow Graph Map */}
                                <div className="flex-1 min-h-0 bg-black/40 rounded-xl border border-white/5 mt-3 relative">
                                    <ArchitectureMap data={topologyData} />
                                </div>
                            </div>

                            {/* Sub-pane with logic state transitions */}
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                                <div className="lg:col-span-1 glass-card p-4 select-none flex flex-col shadow-lg">
                                    <h3 className="text-xs font-bold font-mono text-zinc-400 uppercase tracking-wider mb-2">
                                        Select Target Logic Diagram
                                    </h3>
                                    <Select
                                        value={selectedTargetId}
                                        onValueChange={(v) => setSelectedTargetId(v || "")}
                                    >
                                        <SelectTrigger className="w-full bg-black/50 border-white/10 text-zinc-300 h-8 text-xs font-mono">
                                            <SelectValue placeholder="Choose target..." />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="">Choose target...</SelectItem>
                                            {targets.map((t) => (
                                                <SelectItem key={t.id} value={t.id}>
                                                    {t.name} ({t.host})
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>
                                <div className="lg:col-span-2">
                                    {selectedTargetId ? (
                                        <div className="glass-card p-4 shadow-lg">
                                            <LogicMapViewer targetId={selectedTargetId} />
                                        </div>
                                    ) : (
                                        <div className="glass-card border-white/5 bg-black/20 p-6 text-center text-xs text-zinc-500 italic font-mono shadow-inner">
                                            Choose a target to load its business logic flowchart.
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {/* F. TERMINAL STREAM OUTPUT VIEW (FULL SCREEN) */}
                    {tab === "terminal" && (
                        <div className="h-[calc(100vh-80px)] overflow-hidden">
                            <TerminalConsole />
                        </div>
                    )}

                    {/* G. PLATFORM SETTINGS VIEW */}
                    {tab === "settings" && (
                        <SettingsView />
                    )}

                </main>
            </div>
            
            {/* Inline Context-Aware AI Drawer */}
            <AiDrawer
                open={aiDrawerOpen}
                onOpenChange={setAiDrawerOpen}
                findingId={activeFinding?.id || null}
                findingTitle={activeFinding?.title || ""}
                findingSeverity={activeFinding?.severity || "info"}
                mode={aiDrawerMode}
            />

            <PromptEditor
                open={promptEditorOpen}
                onOpenChange={setPromptEditorOpen}
                findingId={activeFinding?.id || null}
            />
        </div>
    );
}