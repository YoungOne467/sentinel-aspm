import React, { useMemo } from "react";
import { useSecurityStore } from "../store";
import { useShallow } from "zustand/react/shallow";
import { Cpu, Database, Activity } from "lucide-react";
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    CartesianGrid,
} from "recharts";

export default function HardwareMonitor() {
    const { telemetryHistory } = useSecurityStore(
        useShallow((state) => ({
            telemetryHistory: state.telemetryHistory || [],
        }))
    );

    // ⚡ Memoize data processing so we don't recalculate the entire array on every tick
    const { latestTick, chartData } = useMemo(() => {
        const last = telemetryHistory[telemetryHistory.length - 1] || {
            cpu: 0,
            ram: 0,
            tasks: 0,
            ts: new Date().toISOString(),
        };

        const formattedData = telemetryHistory.map((tick) => ({
            ...tick,
            timeStr: new Date(tick.ts).toLocaleTimeString("en-US", {
                hour12: false,
                minute: "2-digit",
                second: "2-digit",
            }),
            ramGB: tick.ram / 1024, // Pre-calculate GB for cleaner charts
        }));

        return { latestTick: last, chartData: formattedData };
    }, [telemetryHistory]);

    return (
        <div className="floating-panel p-5 flex flex-col gap-5 select-none transition-all duration-300">
            {/* Header Status Bar */}
            <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-white/5 pb-4 gap-3">
                <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded-lg bg-brand-500/20 border border-brand-500/30">
                        <Activity className="w-5 h-5 text-brand-400 animate-pulse" />
                    </div>
                    <div>
                        <h2 className="text-sm font-bold text-zinc-100 tracking-wider">
                            Hardware Telemetry
                        </h2>
                        <p className="text-[10px] text-zinc-500 font-mono tracking-widest uppercase">
                            Real-time resource utilization
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <div className="flex items-center gap-2 bg-black/40 border border-white/10 px-3 py-1.5 rounded-lg text-[11px] font-mono shadow-inner">
                        <Cpu className="w-3.5 h-3.5 text-brand-400" />
                        <span className="text-zinc-500">CPU:</span>
                        <span className="text-zinc-100 font-bold">{latestTick.cpu.toFixed(1)}%</span>
                    </div>
                    <div className="flex items-center gap-2 bg-black/40 border border-white/10 px-3 py-1.5 rounded-lg text-[11px] font-mono shadow-inner">
                        <Database className="w-3.5 h-3.5 text-fuchsia-400" />
                        <span className="text-zinc-500">RAM:</span>
                        <span className="text-zinc-100 font-bold">{(latestTick.ram / 1024).toFixed(2)} GB</span>
                    </div>
                    <div className="flex items-center gap-2 bg-black/40 border border-white/10 px-3 py-1.5 rounded-lg text-[11px] font-mono shadow-inner">
                        <span className="text-zinc-500">TASKS:</span>
                        <span className="text-zinc-100 font-bold">{latestTick.tasks}</span>
                    </div>
                </div>
            </div>

            {/* Charts Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5 h-64 min-h-[250px]">
                {/* CPU Area Chart */}
                <div
                    className="flex flex-col h-full bg-black/40 border border-white/5 rounded-xl p-3 shadow-inner"
                    role="img"
                    aria-label="CPU Load History Area Chart"
                >
                    <div className="text-[10px] text-zinc-500 font-bold font-mono tracking-widest uppercase mb-2 flex items-center justify-between px-1" aria-hidden="true">
                        <div className="flex items-center gap-2">
                            <div className="w-1.5 h-1.5 rounded-full bg-brand-500 shadow-[0_0_8px_rgba(168,85,247,0.6)]" />
                            CPU Load History
                        </div>
                        <span className="text-brand-400 font-bold">{latestTick.cpu.toFixed(0)}%</span>
                    </div>
                    <div className="flex-1 w-full h-full min-h-[200px] min-w-0 relative">
                        <ResponsiveContainer width="100%" height="100%">
                            {/* eslint-disable-next-line logical-properties/no-physical */}
                            <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="cpuGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#a855f7" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff" opacity={0.05} vertical={false} />
                                <XAxis dataKey="timeStr" tick={{ fill: "#71717a", fontSize: 9, fontFamily: "monospace" }} stroke="transparent" />
                                <YAxis domain={[0, 100]} tick={{ fill: "#71717a", fontSize: 9, fontFamily: "monospace" }} stroke="transparent" />
                                <Tooltip
                                    contentStyle={{ background: "rgba(9, 9, 11, 0.9)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 10, fontFamily: "monospace", backdropFilter: "blur(8px)" }}
                                    // eslint-disable-next-line logical-properties/no-physical
                                    labelStyle={{ color: "#a855f7", fontWeight: "bold", marginBottom: "4px" }}
                                    formatter={(value: any) => [`${Number(value).toFixed(1)}%`, "Utilization"]}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="cpu"
                                    stroke="#a855f7"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#cpuGrad)"
                                    isAnimationActive={false}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* RAM Area Chart */}
                <div
                    className="flex flex-col h-full bg-black/40 border border-white/5 rounded-xl p-3 shadow-inner"
                    role="img"
                    aria-label="Memory Usage History Area Chart"
                >
                    <div className="text-[10px] text-zinc-500 font-bold font-mono tracking-widest uppercase mb-2 flex items-center justify-between px-1" aria-hidden="true">
                        <div className="flex items-center gap-2">
                            <div className="w-1.5 h-1.5 rounded-full bg-fuchsia-500 shadow-[0_0_8px_rgba(217,70,239,0.6)]" />
                            Memory History
                        </div>
                        <span className="text-fuchsia-400 font-bold">{(latestTick.ram / 1024).toFixed(1)} GB</span>
                    </div>
                    <div className="flex-1 w-full h-full min-h-[200px] min-w-0 relative">
                        <ResponsiveContainer width="100%" height="100%">
                            {/* eslint-disable-next-line logical-properties/no-physical */}
                            <AreaChart data={chartData} margin={{ top: 5, right: 5, left: -10, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="ramGrad" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#d946ef" stopOpacity={0.3} />
                                        <stop offset="95%" stopColor="#d946ef" stopOpacity={0.0} />
                                    </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff" opacity={0.05} vertical={false} />
                                <XAxis dataKey="timeStr" tick={{ fill: "#71717a", fontSize: 9, fontFamily: "monospace" }} stroke="transparent" />
                                <YAxis 
                                    domain={['auto', 'auto']} 
                                    tick={{ fill: "#71717a", fontSize: 9, fontFamily: "monospace" }} 
                                    stroke="transparent" 
                                />
                                <Tooltip
                                    contentStyle={{ background: "rgba(9, 9, 11, 0.9)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: 10, fontFamily: "monospace", backdropFilter: "blur(8px)" }}
                                    // eslint-disable-next-line logical-properties/no-physical
                                    labelStyle={{ color: "#d946ef", fontWeight: "bold", marginBottom: "4px" }}
                                    formatter={(value: any) => [`${Number(value).toFixed(2)} GB`, "Allocation"]}
                                />
                                <Area
                                    type="monotone"
                                    dataKey="ramGB"
                                    stroke="#d946ef"
                                    strokeWidth={2}
                                    fillOpacity={1}
                                    fill="url(#ramGrad)"
                                    isAnimationActive={false}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
}