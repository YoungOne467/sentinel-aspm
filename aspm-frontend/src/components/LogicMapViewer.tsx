import mermaid from "mermaid";
import { useEffect, useRef, useState } from "react";
import { fetchWithAuth } from "../apiClient";
import { API_URL } from "../config";

// Initialize mermaid
mermaid.initialize({
	startOnLoad: false,
	theme: "dark",
	securityLevel: "loose",
	flowchart: {
		useMaxWidth: true,
		htmlLabels: true,
	},
});

import React from "react";

interface LogicMapViewerProps {
	targetId: string;
}

const LogicMapViewer = React.memo(function LogicMapViewer({ targetId }: LogicMapViewerProps) {
	const [logicMap, setLogicMap] = useState<string>("");
	const [loading, setLoading] = useState<boolean>(false);
	const [error, setError] = useState<string | null>(null);
	const containerRef = useRef<HTMLDivElement>(null);
	const renderId = useRef<string>(
		`mermaid-${Math.floor(Math.random() * 1000000)}`,
	);

	useEffect(() => {
		if (!targetId) return;

		let isMounted = true;
		const fetchAndRender = async () => {
			setLoading(true);
			setError(null);
			setLogicMap("");
			if (containerRef.current) {
				containerRef.current.innerHTML = "";
			}

			try {
				// Fetch the logic map from the API
				const response = await fetchWithAuth(
					`${API_URL}/targets/${targetId}/logic-map`,
				);

				if (!response.ok) {
					throw new Error(`Failed to fetch logic map: ${response.statusText}`);
				}
				const data = await response.json();
				const mapText = data.logic_map;

				if (!isMounted) return;

				if (!mapText || mapText.trim() === "") {
					setError("No logic map data available.");
					setLoading(false);
					return;
				}

				setLogicMap(mapText);

				// Render using mermaid
				try {
					const { svg } = await mermaid.render(renderId.current, mapText);
					if (isMounted && containerRef.current) {
						containerRef.current.innerHTML = svg;
						// Make SVG responsive
						const svgElement = containerRef.current.querySelector("svg");
						if (svgElement) {
							svgElement.setAttribute("width", "100%");
							svgElement.setAttribute("height", "100%");
							svgElement.style.maxWidth = "100%";
							svgElement.style.maxHeight = "500px";
						}
					}
				} catch (renderError) {
					console.error("Mermaid render error:", renderError);
					if (isMounted) {
						const msg =
							renderError instanceof Error
								? renderError.message
								: String(renderError);
						setError(`Mermaid Render Error: ${msg}`);
					}
				}
			} catch (err) {
				console.error("Fetch error:", err);
				if (isMounted) {
					const msg =
						err instanceof Error
							? err.message
							: "An error occurred while fetching the logic map.";
					setError(msg);
				}
			} finally {
				if (isMounted) {
					setLoading(false);
				}
			}
		};

		fetchAndRender();

		return () => {
			isMounted = false;
		};
	}, [targetId]);

	return (
		<div className="floating-panel p-6 min-h-[500px] flex flex-col relative overflow-hidden transition-all duration-300">
			{/* Violet glowing accent background overlay */}
			<div className="absolute -top-24 -right-24 w-48 h-48 rounded-full bg-brand-500/10 blur-3xl pointer-events-none" />

			<div className="flex items-center justify-between mb-6 pb-4 border-b border-white/5 z-10">
				<div>
					<h3 className="text-sm font-semibold text-zinc-100 flex items-center gap-2 tracking-wide">
						<span className="text-fuchsia-400 animate-pulse drop-shadow-md">☍</span> Business
						Logic State Machine
					</h3>
					<p className="text-[10px] text-zinc-500 mt-1 uppercase tracking-widest font-mono">
						Chronological flow analysis synthesized by AI
					</p>
				</div>
			</div>

			<div className="flex-1 flex flex-col justify-center items-center relative z-10">
				{loading && (
					<div className="flex flex-col items-center justify-center space-y-4 py-20">
						<div className="w-10 h-10 border-4 border-fuchsia-500/20 border-t-fuchsia-400 rounded-full animate-spin shadow-[0_0_15px_rgba(217,70,239,0.2)]" />
						<div className="flex flex-col items-center">
							<span className="text-[11px] text-fuchsia-400 font-mono animate-pulse tracking-wider">
								GENERATING LOGIC MODEL...
							</span>
							<span className="text-[10px] text-zinc-500 mt-1.5 font-sans">
								Analyzing target telemetry sequences...
							</span>
						</div>
					</div>
				)}

				{error && !loading && (
					<div className="flex flex-col items-center justify-center p-6 text-center max-w-md bg-rose-500/10 border border-rose-500/20 rounded-2xl shadow-inner">
						<span className="text-2xl mb-2">⚠</span>
						<h4 className="text-sm font-semibold text-rose-400 mb-1 tracking-wide">
							Visualization Failed
						</h4>
						<p className="text-[11px] text-zinc-400 mb-4">{error}</p>
						{logicMap && (
							<pre className="w-full overflow-x-auto text-[10px] text-zinc-500 font-mono bg-black/60 p-4 rounded-xl border border-white/5 text-left shadow-inner">
								{logicMap}
							</pre>
						)}
					</div>
				)}

				{!targetId && !loading && !error && (
					<div className="flex flex-col items-center justify-center space-y-4 py-20 text-center">
						<span className="text-4xl text-zinc-800 drop-shadow-sm">☍</span>
						<p className="text-[11px] text-zinc-500 font-mono tracking-widest uppercase">
							Select a target to render flowchart
						</p>
					</div>
				)}

				{targetId && !loading && !error && (
					<div
						ref={containerRef}
						className="w-full h-full min-h-[400px] overflow-auto flex items-center justify-center bg-black/40 rounded-2xl p-6 border border-white/5 shadow-inner"
					/>
				)}
			</div>
		</div>
	);
});

export default LogicMapViewer;
