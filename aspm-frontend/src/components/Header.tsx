import { Activity, Cpu, Menu, Radio, Wifi, WifiOff, Zap, ZapOff } from "lucide-react";
import { useShallow } from "zustand/react/shallow";
import { useSecurityStore } from "../store";
import React from "react";

const Header = React.memo(function Header() {
	const { wsConnected, health, isEcoMode, setEcoMode, sidebarOpen, setSidebarOpen } = useSecurityStore(
		useShallow((state) => ({
			wsConnected: state.wsConnected,
			health: state.health,
			isEcoMode: state.isEcoMode,
			setEcoMode: state.setEcoMode,
			sidebarOpen: state.sidebarOpen,
			setSidebarOpen: state.setSidebarOpen,
		}))
	);

	return (
		<header className="h-14 w-full border-b border-white/5 px-6 flex items-center justify-between shrink-0 select-none z-30">
			<div className="flex items-center gap-4">
				<button
					type="button"
					onClick={() => setSidebarOpen(!sidebarOpen)}
					className="p-1.5 rounded-lg text-zinc-400 hover:text-zinc-200 hover:bg-white/5 transition-colors md:hidden"
					title="Toggle sidebar"
					aria-label="Toggle sidebar"
				>
					<Menu className="w-5 h-5" />
				</button>
				<span className="text-[11px] text-zinc-500 font-semibold tracking-widest uppercase flex items-center gap-2">
					<div className="w-1.5 h-1.5 rounded-full bg-zinc-600" />
					Engine Version:{" "}
					<span className="text-zinc-300 bg-white/5 px-2 py-0.5 rounded-md border border-white/10 font-mono">
						{health?.version || "2.0.0"}
					</span>
				</span>

				{/* Active Scan Indicator */}
				{health && health.active_jobs > 0 && (
					<div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-fuchsia-500/10 border border-fuchsia-500/20 shadow-[0_0_15px_rgba(217,70,239,0.15)]">
						<Radio className="w-3.5 h-3.5 text-fuchsia-400 animate-pulse" />
						<span className="text-[10px] text-fuchsia-400 font-bold tracking-widest uppercase">
							{health.active_jobs} Active Jobs
						</span>
					</div>
				)}
			</div>

			<div className="flex items-center gap-5">
				{/* Performance Mode Toggle */}
				<button
					type="button"
					onClick={() => setEcoMode(!isEcoMode)}
					className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all border ${
						isEcoMode
							? "bg-amber-500/10 text-amber-400 border-amber-500/30"
							: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
					}`}
					title={isEcoMode ? "Disable Eco Mode (restores premium layout animations/glows)" : "Enable Eco Mode (reduces graphics resource utilization)"}
				>
					{isEcoMode ? (
						<>
							<ZapOff className="w-3.5 h-3.5" />
							<span>Eco Mode</span>
						</>
					) : (
						<>
							<Zap className="w-3.5 h-3.5" />
							<span>Perf Mode</span>
						</>
					)}
				</button>

				{/* System Badges */}
				{health?.system && (
					<div className="hidden lg:flex items-center gap-4 bg-white/5 px-3 py-1.5 rounded-lg border border-white/10">
						<div className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-400">
							<Cpu className="w-3.5 h-3.5 text-zinc-500" />
							<span>CPU:</span>
							<span className={health.system.cpu_percent > 80 ? "text-rose-400 font-bold glow-red" : "text-zinc-200 font-semibold"}>
								{health.system.cpu_percent}%
							</span>
						</div>
						<div className="w-px h-3 bg-white/10" />
						<div className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-400">
							<Activity className="w-3.5 h-3.5 text-zinc-500" />
							<span>RAM:</span>
							<span className="text-zinc-200 font-semibold">
								{health.system.memory_total_mb} MB
							</span>
						</div>
					</div>
				)}

				<div className="w-px h-4 bg-white/10 hidden lg:block" />

				{/* Live Websocket Connection Status */}
				<div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-black/40 border border-white/5">
					{wsConnected ? (
						<>
							<div className="relative flex items-center justify-center">
								<Wifi className="w-4 h-4 text-emerald-400 z-10" />
								<div className="absolute w-4 h-4 bg-emerald-400/40 blur-md rounded-full animate-pulse" />
							</div>
							<span className="text-[10px] font-bold text-emerald-400 tracking-widest uppercase">
								Online
							</span>
						</>
					) : (
						<>
							<WifiOff className="w-4 h-4 text-rose-500" />
							<span className="text-[10px] font-bold text-rose-500 tracking-widest uppercase animate-pulse">
								Offline
							</span>
						</>
					)}
				</div>
			</div>
		</header>
	);
});

export default Header;
