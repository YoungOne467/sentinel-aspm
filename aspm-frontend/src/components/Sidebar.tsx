import {
	Cpu,
	LayoutDashboard,
	Moon,
	Network,
	Power,
	Settings,
	Shield,
	ShieldAlert,
	Sun,
	Target,
	Terminal,
	X,
} from "lucide-react";
import type React from "react";
import { fetchWithAuth } from "../apiClient";
import { API_BASE_URL } from "../config";
import { useShallow } from "zustand/react/shallow";
import { type Tab, useSecurityStore } from "../store";

export default function Sidebar() {
	const { tab, setTab, darkMode, setDarkMode, isEcoMode, setEcoMode, health, sidebarOpen, setSidebarOpen } = useSecurityStore(
		useShallow((state) => ({
			tab: state.tab,
			setTab: state.setTab,
			darkMode: state.darkMode,
			setDarkMode: state.setDarkMode,
			isEcoMode: state.isEcoMode,
			setEcoMode: state.setEcoMode,
			health: state.health,
			sidebarOpen: state.sidebarOpen,
			setSidebarOpen: state.setSidebarOpen,
		}))
	);

	const navItems: {
		id: Tab;
		label: string;
		icon: React.ComponentType<{ className?: string }>;
	}[] = [
		{ id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
		{ id: "targets", label: "Targets", icon: Target },
		{ id: "findings", label: "Findings", icon: ShieldAlert },
		{ id: "terminal", label: "Terminal", icon: Terminal },
		{ id: "scope", label: "Scope Rules", icon: Shield },
		{ id: "evasion", label: "Evasion Config", icon: Cpu },
		{ id: "topology", label: "Topology Map", icon: Network },
		{ id: "settings", label: "Settings", icon: Settings },
	];

	const triggerShutdown = async () => {
		if (!window.confirm("Initiate system shutdown sequence?")) return;
		try {
			await fetchWithAuth(`${API_BASE_URL}/api/shutdown`, { method: "POST" });
			alert("Shutdown signal transmitted.");
		} catch {
			alert("Communication failed. Is the backend offline?");
		}
	};

	const triggerHibernate = async () => {
		if (
			!window.confirm(
				"Initiate offline AI hibernation? This pauses API listener states.",
			)
		)
			return;
		try {
			await fetchWithAuth(`${API_BASE_URL}/api/system/hibernate`, {
				method: "POST",
			});
			alert("AI Hibernation initiated.");
		} catch {
			alert("Communication failed.");
		}
	};

	return (
		<>
			{/* Mobile Sidebar backdrop */}
			{sidebarOpen && (
				<button
					type="button"
					onClick={() => setSidebarOpen(false)}
					className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 md:hidden w-full h-full border-0 outline-none cursor-default"
					aria-label="Close Sidebar Backdrop"
				/>
			)}
			<aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-[#050505]/95 md:bg-transparent flex flex-col justify-between shrink-0 h-screen transition-transform duration-300 select-none p-4 md:sticky md:top-0 md:w-16 md:w-64 md:translate-x-0 ${
				sidebarOpen ? "translate-x-0" : "-translate-x-full"
			}`}>
				<div className="floating-panel flex-1 flex flex-col justify-between h-full overflow-hidden bg-zinc-950/40 md:bg-transparent">
					<div className="flex flex-col">
						{/* Brand Banner */}
						<div className="p-5 border-b border-white/5 flex items-center justify-between md:justify-start gap-4">
							<div className="flex items-center gap-4">
								<div className="w-10 h-10 rounded-xl bg-gradient-to-br from-brand-500 to-fuchsia-600 flex items-center justify-center shadow-lg shadow-brand-500/20 ring-1 ring-white/10 shrink-0">
									<Shield className="w-5 h-5 text-white drop-shadow-md" />
								</div>
								<div className="hidden md:block">
									<h1 className="text-sm font-bold text-zinc-100 tracking-wide">
										SENTINEL
									</h1>
									<p className="text-[10px] text-fuchsia-400 font-semibold tracking-widest uppercase">
										SecOps AI Engine
									</p>
								</div>
							</div>
							<button
								type="button"
								onClick={() => setSidebarOpen(false)}
								className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-white/5 transition-colors md:hidden"
								title="Close sidebar"
								aria-label="Close sidebar"
							>
								<X className="w-5 h-5" />
							</button>
						</div>

						{/* Actionable Nav Links */}
						<nav className="p-3 space-y-1.5">
							{navItems.map((item) => {
								const Icon = item.icon;
								const isActive = tab === item.id;
								return (
									<button
										type="button"
										key={item.id}
										onClick={() => {
											setTab(item.id);
											setSidebarOpen(false);
										}}
										className={`w-full flex items-center justify-center md:justify-start gap-3.5 px-3 md:px-4 py-3 rounded-xl text-left transition-all duration-300 group border-l-2 relative ${
											isActive
												? "bg-white/10 text-white font-bold ring-1 ring-white/10 border-l-fuchsia-500 shadow-lg shadow-fuchsia-500/10"
												: "text-zinc-400 hover:bg-white/5 hover:text-zinc-200 border-l-transparent"
										}`}
										title={item.label}
										aria-current={isActive ? "page" : undefined}
									>
										<Icon className={`w-5 h-5 shrink-0 transition-colors ${isActive ? "text-fuchsia-400" : "group-hover:text-fuchsia-400/70"}`} />
										<span className="hidden md:inline text-[13px] font-medium tracking-wide">
											{item.label}
										</span>
									</button>
								);
							})}
						</nav>
					</div>

					{/* System Telemetry & Control Panel */}
					<div className="p-3 border-t border-white/5 space-y-3 bg-black/20">
						{health?.system && (
							<div className="hidden md:flex flex-col gap-2 px-1">
								<div className="flex justify-between items-center text-[10px] font-mono text-zinc-500 tracking-wider">
									<span>ENGINE LOAD</span>
									<span
										className={
											health.system.cpu_percent > 80
												? "text-rose-400 font-bold"
												: "text-fuchsia-400 font-bold"
										}
									>
										{health.system.cpu_percent}%
									</span>
								</div>
								<div className="h-1.5 w-full bg-zinc-900 rounded-full overflow-hidden ring-1 ring-white/5">
									<div
										className={`h-full rounded-full transition-all duration-1000 ${health.system.cpu_percent > 80 ? 'bg-rose-500' : 'bg-gradient-to-r from-brand-600 to-fuchsia-500'}`}
										style={{ width: `${Math.min(100, Math.max(0, health.system.cpu_percent))}%` }}
									/>
								</div>
							</div>
						)}

						{/* Global Utilities Footer */}
						<div className="flex flex-col md:flex-row gap-2 items-center justify-between pt-2">
							<button
								type="button"
								onClick={() => setDarkMode(!darkMode)}
								className="p-2.5 rounded-lg bg-zinc-900/50 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors w-full md:w-auto flex justify-center ring-1 ring-white/5"
								title="Toggle theme"
								aria-label="Toggle theme"
							>
								{darkMode ? (
									<Sun className="w-4 h-4" />
								) : (
									<Moon className="w-4 h-4" />
								)}
							</button>

							<button
								type="button"
								onClick={() => setEcoMode(!isEcoMode)}
								className={`p-2.5 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors w-full md:w-auto flex justify-center items-center gap-1.5 ring-1 ring-white/5 ${
									isEcoMode
										? "bg-emerald-500/10 text-emerald-400 ring-emerald-500/20 hover:bg-emerald-500/20"
										: "bg-zinc-900/50 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
								}`}
								title="Toggle Eco Performance Mode"
								aria-label="Toggle Eco Mode"
							>
								<Cpu className="w-3.5 h-3.5" />
								<span className="md:hidden lg:inline text-[9px]">Eco</span>
							</button>

							<button
								type="button"
								onClick={triggerHibernate}
								className="hidden md:flex flex-1 items-center justify-center gap-2 py-2.5 px-3 rounded-lg bg-yellow-500/10 text-yellow-500 ring-1 ring-yellow-500/20 hover:bg-yellow-500/20 hover:ring-yellow-500/30 text-[10px] font-bold uppercase tracking-wider transition-all"
								title="Trigger AI Hibernation"
							>
								<Cpu className="w-3.5 h-3.5" />
								<span>Hibernate</span>
							</button>

							<button
								type="button"
								onClick={triggerShutdown}
								className="p-2.5 rounded-lg bg-rose-500/10 text-rose-500 ring-1 ring-rose-500/20 hover:bg-rose-500/20 hover:ring-rose-500/30 transition-colors w-full md:w-auto flex justify-center"
								title="Power off system"
								aria-label="Power off system"
							>
								<Power className="w-4 h-4" />
							</button>
						</div>
					</div>
				</div>
			</aside>
		</>
	);
}
