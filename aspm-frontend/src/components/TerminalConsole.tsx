import { ChevronDown, ChevronUp, Terminal, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useSecurityStore } from "../store";
import { useShallow } from "zustand/react/shallow";
import { useVirtualizer } from "@tanstack/react-virtual";

export default function TerminalConsole() {
	const { termLines, clearTermLines } = useSecurityStore(
		useShallow((state) => ({
			termLines: state.termLines,
			clearTermLines: state.clearTermLines,
		}))
	);
	const [collapsed, setCollapsed] = useState(false);
	const parentRef = useRef<HTMLDivElement>(null);

	const rowVirtualizer = useVirtualizer({
		count: termLines.length,
		getScrollElement: () => parentRef.current,
		estimateSize: () => 24,
		overscan: 5,
	});

	// Auto-scroll to the bottom of the logs on update
	useEffect(() => {
		if (!collapsed && termLines.length > 0) {
			rowVirtualizer.scrollToIndex(termLines.length - 1);
		}
	}, [termLines.length, collapsed, rowVirtualizer]);

	const streamColors = {
		stdout: "text-zinc-300",
		stderr: "text-rose-400 font-bold glow-red",
		system: "text-brand-400 font-bold glow-cyan",
	};

	return (
		<div className="floating-panel flex flex-col overflow-hidden font-mono select-none shadow-2xl transition-all duration-300">
			{/* Terminal Title Bar */}
			{/* biome-ignore lint/a11y/useKeyWithClickEvents: title bar toggle */}
			{/* biome-ignore lint/a11y/noStaticElementInteractions: title bar toggle */}
			<div
				onClick={() => setCollapsed(!collapsed)}
				className="px-5 py-3 bg-black/60 border-b border-white/5 flex items-center justify-between cursor-pointer select-none backdrop-blur-md hover:bg-white/5 transition-colors"
			>
				<div className="flex items-center gap-3">
					<div className="p-1.5 rounded-md bg-brand-500/20 border border-brand-500/30">
						<Terminal className="w-4 h-4 text-brand-400" />
					</div>
					<span className="text-[11px] font-bold text-zinc-100 tracking-widest uppercase">
						Engine Output Stream
					</span>
					<span className="px-2 py-0.5 rounded-md bg-white/10 text-zinc-300 text-[10px] font-bold border border-white/5 shadow-inner">
						{termLines.length} lines
					</span>
				</div>

				{/* biome-ignore lint/a11y/useKeyWithClickEvents: stop propagation wrapper */}
				{/* biome-ignore lint/a11y/noStaticElementInteractions: stop propagation wrapper */}
				<div
					className="flex items-center gap-2"
					onClick={(e) => e.stopPropagation()}
				>
					<button
						type="button"
						onClick={clearTermLines}
						className="p-1.5 rounded-lg text-zinc-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
						title="Clear all log lines"
						aria-label="Clear all log lines"
					>
						<Trash2 className="w-4 h-4" />
					</button>

					<button
						type="button"
						onClick={() => setCollapsed(!collapsed)}
						className="p-1.5 rounded-lg text-zinc-500 hover:text-zinc-200 hover:bg-white/10 transition-colors"
						title={collapsed ? "Expand terminal" : "Collapse terminal"}
						aria-label={collapsed ? "Expand terminal" : "Collapse terminal"}
					>
						{collapsed ? (
							<ChevronUp className="w-4 h-4" />
						) : (
							<ChevronDown className="w-4 h-4" />
						)}
					</button>
				</div>
			</div>

			{/* Log Console Display */}
			{!collapsed && (
				<div
					ref={parentRef}
					className="h-56 overflow-y-auto p-4 bg-[#050505]/90 text-[11px] leading-relaxed relative custom-scrollbar shadow-inner"
				>
					{termLines.length === 0 ? (
						<div className="h-full flex flex-col gap-3 items-center justify-center text-zinc-600 italic">
							<Terminal className="w-10 h-10 opacity-20" />
							Awaiting task orchestration. Output will stream here.
						</div>
					) : (
						<div
							style={{
								height: `${rowVirtualizer.getTotalSize()}px`,
								width: "100%",
								position: "relative",
							}}
						>
							{rowVirtualizer.getVirtualItems().map((virtualItem) => {
								const line = termLines[virtualItem.index];
								if (!line) return null;
								return (
									<div
										key={line.id}
										ref={rowVirtualizer.measureElement}
										data-index={virtualItem.index}
										style={{
											position: "absolute",
											top: 0,
											left: 0,
											width: "100%",
											transform: `translateY(${virtualItem.start}px)`,
										}}
										className="flex gap-2.5 hover:bg-white/5 py-0.5 px-2 rounded transition-colors"
									>
										<span className="text-zinc-600 font-medium shrink-0 select-none">
											{new Date(line.ts).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
										</span>

										{line.tool && (
											<span className="text-fuchsia-400 font-bold shrink-0">
												[{line.tool.toUpperCase()}]
											</span>
										)}

										<span
											className={`whitespace-pre-wrap ${streamColors[line.stream] || "text-slate-300"}`}
										>
											{line.line}
										</span>
									</div>
								);
							})}
						</div>
					)}
				</div>
			)}
		</div>
	);
}
