import React from "react";
import { CheckCircle, Cpu, X } from "lucide-react";
import { useEffect } from "react";
import type { Finding } from "../store";

interface DetailPanelProps {
	finding: Finding;
	onClose: () => void;
	onAnalyzeExploitFlow?: (finding: Finding) => void;
	onGenerateRemediation?: (finding: Finding) => void;
}

// ⚡ Bolt: Hoist static data outside of component to prevent redundant memory
// allocations on every render.
const thoughtTree = [
    {
        title: "Phase 1: Cloud Recon",
        desc: "Endpoint discovered via target mapping and structure scraping. Status: cloud_ingested.",
    },
    {
        title: "Phase 2: LLM Mutation",
        desc: "Local 4B model query completed. Parameter mutations injected OAST tracking payloads.",
    },
    {
        title: "Phase 3: Targeted Injection",
        desc: "Asynchronous injections dispatched (<=10 requests). Live Interactsh polling active.",
    },
    {
        title: "OAST Verification",
        desc: "Out-Of-Band DNS/HTTP callback log captured matching oast_token. Status: exploit_verified.",
    },
];

export default function DetailPanel({
	finding,
	onClose,
	onAnalyzeExploitFlow,
	onGenerateRemediation,
}: DetailPanelProps) {
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === "Escape") {
                onClose();
            }
        };
        window.addEventListener("keydown", handleKeyDown);
        return () => window.removeEventListener("keydown", handleKeyDown);
    }, [onClose]);
// ⚡ Bolt: Memoize JSON.parse so we only pay the CPU cost when the finding actually changes.
    // biome-ignore lint/suspicious/noExplicitAny: JSON.parse output has any type
    const proof: any = React.useMemo(() => {
        try {
            return JSON.parse(finding.evidence);
        } catch (_e) {
            return null;
        }
    }, [finding.evidence]);

    const sevColors = {
        critical: "text-rose-400 border-rose-500/20 bg-rose-500/10 shadow-[0_0_10px_rgba(225,29,72,0.15)]",
        high: "text-orange-400 border-orange-500/20 bg-orange-500/10",
        medium: "text-yellow-400 border-yellow-500/20 bg-yellow-500/10",
        low: "text-blue-400 border-blue-500/20 bg-blue-500/10",
        info: "text-zinc-400 border-white/10 bg-white/5",
    };

	return (
		<div className="w-full lg:w-[450px] floating-panel flex flex-col h-full overflow-hidden select-none relative font-sans shadow-2xl transform transition-transform duration-300 ml-4 mb-4 mt-0">
			{/* Decorative gradient blob */}
			<div className="absolute top-0 right-0 w-32 h-32 rounded-full bg-brand-500/10 blur-2xl pointer-events-none" />

			{/* Header panel */}
			<div className="p-4 border-b border-white/5 bg-black/40 flex items-center justify-between z-10 backdrop-blur-md">
				<div className="min-w-0 flex-1 pr-3">
					<h3
						className="text-sm font-bold text-zinc-100 truncate tracking-wide"
						title={finding.title}
					>
						{finding.title}
					</h3>
					<span className="text-[10px] text-zinc-500 font-mono tracking-widest uppercase mt-0.5 block">
						ID: {finding.id.slice(0, 8)}
					</span>
				</div>
				<button
					type="button"
					onClick={onClose}
					className="text-zinc-500 hover:text-zinc-200 hover:bg-white/10 transition-colors p-1.5 rounded-lg"
					title="Close detail panel"
					aria-label="Close detail panel"
				>
					<X className="w-4 h-4" />
				</button>
			</div>

			{/* Content panel */}
			<div className="flex-1 overflow-y-auto p-5 space-y-6 custom-scrollbar">
				{/* Severity & Category summary */}
				<div className="flex gap-2.5">
					<span
						className={`text-[10px] font-extrabold px-2 py-0.5 rounded-md border font-mono tracking-widest uppercase ${sevColors[finding.severity]}`}
					>
						{finding.severity}
					</span>
					<span className="text-[10px] font-semibold text-zinc-400 border border-white/10 bg-black/40 rounded-md px-2 py-0.5 uppercase tracking-widest font-mono">
						{finding.category}
					</span>
				</div>

				{/* Description */}
				<div className="space-y-2">
					<h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest font-mono flex items-center gap-2">
						<div className="w-1 h-1 rounded-full bg-zinc-500" />
						Abstract
					</h4>
					<p className="text-[13px] text-zinc-300 leading-relaxed font-sans bg-black/20 border border-white/5 p-3 rounded-xl shadow-inner">
						{finding.description}
					</p>
				</div>

				{/* Cognitive Thought Tree */}
				{finding.ai_triaged && (
					<div className="space-y-3">
						<h4 className="text-[10px] font-bold text-fuchsia-400 uppercase tracking-widest font-mono flex items-center gap-2">
							<Cpu className="w-3.5 h-3.5 animate-pulse" />
							AI Triage Flow
						</h4>
						<ul className="space-y-4 relative border-l border-white/10 ml-2 pl-4 list-none">
							{thoughtTree.map((step) => (
								<li key={step.title} className="relative">
									<span className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-fuchsia-500 border-2 border-[#09090b] shadow-[0_0_8px_rgba(217,70,239,0.5)]" />
									<div className="text-[11px] font-bold text-zinc-200 font-mono tracking-tight">
										{step.title}
									</div>
									<div className="text-[10px] text-zinc-500 mt-1 leading-relaxed font-sans">
										{step.desc}
									</div>
								</li>
							))}
						</ul>
					</div>
				)}

				{/* HTTP Request/Response Diffs */}
				<div className="space-y-3">
					<h4 className="text-[10px] font-bold text-zinc-500 uppercase tracking-widest font-mono flex items-center gap-2">
						<div className="w-1 h-1 rounded-full bg-zinc-500" />
						Verification Proof
					</h4>
					{proof?.request ? (
						<div className="space-y-3 font-mono text-[10px]">
							<div className="bg-black/50 border border-white/10 p-3 rounded-xl overflow-x-auto shadow-inner">
								<div className="text-brand-400 font-bold mb-2 tracking-wider flex items-center gap-2">
									<span className="w-1.5 h-1.5 rounded-full bg-brand-400" />
									REQUEST
								</div>
								<pre className="whitespace-pre-wrap text-zinc-300">{`${proof.request.method} ${proof.request.url} HTTP/1.1\nHost: target-application\nContent-Type: application/json\n\n${JSON.stringify(proof.request.parameters, null, 2)}`}</pre>
							</div>
							<div className="bg-black/50 border border-white/10 p-3 rounded-xl overflow-x-auto shadow-inner">
								<div className="text-emerald-400 font-bold mb-2 tracking-wider flex items-center gap-2">
									<span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
									RESPONSE
								</div>
								<pre className="whitespace-pre-wrap text-zinc-300">{`HTTP/1.1 ${proof.response.status} OK\nContent-Type: application/json\n\n${proof.response.body}`}</pre>
							</div>
						</div>
					) : (
						<div className="bg-black/20 border border-white/5 rounded-xl p-4 font-mono text-[11px] text-zinc-500 italic shadow-inner">
							{finding.evidence ? (
								<pre className="whitespace-pre-wrap font-mono text-[10px] text-zinc-400">
									{finding.evidence}
								</pre>
							) : (
								"No HTTP validation diff recorded for this vulnerability."
							)}
						</div>
					)}
				</div>

				{/* Remediations */}
				<div className="space-y-3 pb-4">
					<h4 className="text-[10px] font-bold text-emerald-500 uppercase tracking-widest font-mono flex items-center gap-1.5">
						<CheckCircle className="w-3.5 h-3.5" />
						Remediation
					</h4>
					<p className="text-[13px] text-emerald-100/70 leading-relaxed font-sans bg-emerald-500/10 border border-emerald-500/20 p-3 rounded-xl shadow-inner mb-3">
						{finding.solution}
					</p>
					
					{/* Inline AI Actions */}
					<div className="flex gap-2">
						<button
							type="button"
							onClick={() => onAnalyzeExploitFlow?.(finding)}
							className="flex-1 py-2 px-3 rounded-lg bg-fuchsia-600/20 text-fuchsia-400 border border-fuchsia-500/30 hover:bg-fuchsia-500/30 transition-colors text-xs font-semibold uppercase tracking-wider font-mono flex items-center justify-center gap-1.5"
						>
							<Cpu className="w-3.5 h-3.5" />
							Analyze Exploit Flow
						</button>
						<button
							type="button"
							onClick={() => onGenerateRemediation?.(finding)}
							className="flex-1 py-2 px-3 rounded-lg bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/30 transition-colors text-xs font-semibold uppercase tracking-wider font-mono flex items-center justify-center gap-1.5"
						>
							<CheckCircle className="w-3.5 h-3.5" />
							Generate Remediation
						</button>
					</div>
				</div>
			</div>
		</div>
	);
}
