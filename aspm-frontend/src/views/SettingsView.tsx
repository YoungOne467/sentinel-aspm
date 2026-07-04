import React, { useEffect, useState } from "react";
import {
	Cpu,
	Globe,
	Key,
	Sliders,
	Webhook,
	Eye,
	EyeOff,
	Save,
	Check,
	Loader2,
	RefreshCw,
	AlertCircle,
} from "lucide-react";
import { fetchWithAuth } from "../apiClient";
import { API_BASE_URL } from "../config";

type TabID = "ai" | "auth" | "routing" | "webhooks" | "rates";

interface HeaderItem {
	key: string;
	value: string;
}

interface CookieItem {
	name: string;
	value: string;
}

export default function SettingsView() {
	const [activeTab, setActiveTab] = useState<TabID>("ai");
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [testing, setTesting] = useState<Record<string, boolean>>({});
	const [testResult, setTestResult] = useState<Record<string, { success: boolean; msg: string }>>({});
	const [error, setError] = useState<string | null>(null);
	const [successMsg, setSuccessMsg] = useState<string | null>(null);

	// Settings State
	const [openaiKey, setOpenaiKey] = useState("");
	const [anthropicKey, setAnthropicKey] = useState("");
	const [ollamaBaseUrl, setOllamaBaseUrl] = useState("");
	
	const [customHeaders, setCustomHeaders] = useState<HeaderItem[]>([]);
	const [sessionCookies, setSessionCookies] = useState<CookieItem[]>([]);
	
	const [upstreamProxy, setUpstreamProxy] = useState("");
	const [userAgent, setUserAgent] = useState("");
	
	const [jiraHost, setJiraHost] = useState("");
	const [jiraEmail, setJiraEmail] = useState("");
	const [jiraPat, setJiraPat] = useState("");
	const [githubPat, setGithubPat] = useState("");
	const [discordWebhook, setDiscordWebhook] = useState("");
	const [slackWebhook, setSlackWebhook] = useState("");
	
	const [maxConcurrentWorkers, setMaxConcurrentWorkers] = useState(5);
	const [rateLimitRps, setRateLimitRps] = useState(10);
	const [globalBlacklist, setGlobalBlacklist] = useState("");

	// Key visibility state
	const [visibleKeys, setVisibleKeys] = useState<Record<string, boolean>>({});

	useEffect(() => {
		loadSettings();
	}, []);

	const loadSettings = async () => {
		try {
			setLoading(true);
			setError(null);
			const resp = await fetchWithAuth(`${API_BASE_URL}/api/settings`);
			if (!resp.ok) throw new Error("Failed to load settings from server");
			const data = await resp.json();
			
			setOpenaiKey(data.openai_key || "");
			setAnthropicKey(data.anthropic_key || "");
			setOllamaBaseUrl(data.ollama_base_url || "");
			setCustomHeaders(data.custom_headers || []);
			setSessionCookies(data.session_cookies || []);
			setUpstreamProxy(data.upstream_proxy || "");
			setUserAgent(data.user_agent || "");
			setJiraHost(data.jira_host || "");
			setJiraEmail(data.jira_email || "");
			setJiraPat(data.jira_pat || "");
			setGithubPat(data.github_pat || "");
			setDiscordWebhook(data.discord_webhook || "");
			setSlackWebhook(data.slack_webhook || "");
			setMaxConcurrentWorkers(data.max_concurrent_workers ?? 5);
			setRateLimitRps(data.rate_limit_rps ?? 10);
			setGlobalBlacklist(data.global_blacklist || "");
		} catch (e: any) {
			setError(e.message || "Failed to contact API");
		} finally {
			setLoading(false);
		}
	};

	const handleSave = async (e: React.FormEvent) => {
		e.preventDefault();
		try {
			setSaving(true);
			setError(null);
			setSuccessMsg(null);
			
			const payload = {
				openai_key: openaiKey,
				anthropic_key: anthropicKey,
				ollama_base_url: ollamaBaseUrl,
				custom_headers: customHeaders,
				session_cookies: sessionCookies,
				upstream_proxy: upstreamProxy,
				user_agent: userAgent,
				jira_host: jiraHost,
				jira_email: jiraEmail,
				jira_pat: jiraPat,
				github_pat: githubPat,
				discord_webhook: discordWebhook,
				slack_webhook: slackWebhook,
				max_concurrent_workers: maxConcurrentWorkers,
				rate_limit_rps: rateLimitRps,
				global_blacklist: globalBlacklist
			};

			const resp = await fetchWithAuth(`${API_BASE_URL}/api/settings`, {
				method: "PUT",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify(payload),
			});

			if (!resp.ok) throw new Error("Server rejected settings configuration update");
			setSuccessMsg("System configuration committed successfully.");
			
			// Reload to update masked states
			await loadSettings();
		} catch (e: any) {
			setError(e.message || "Failed to save settings");
		} finally {
			setSaving(false);
		}
	};

	const handleTest = async (target: string, extraParams: Record<string, string> = {}) => {
		try {
			setTesting(prev => ({ ...prev, [target]: true }));
			setTestResult(prev => {
				const next = { ...prev };
				delete next[target];
				return next;
			});

			const resp = await fetchWithAuth(`${API_BASE_URL}/api/settings/test`, {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ target, ...extraParams }),
			});
			const resData = await resp.json();
			if (!resp.ok) {
				throw new Error(resData.detail || "Integration check returned an error");
			}

			setTestResult(prev => ({ ...prev, [target]: { success: true, msg: resData.message || "OK" } }));
		} catch (e: any) {
			setTestResult(prev => ({ ...prev, [target]: { success: false, msg: e.message || "Failed" } }));
		} finally {
			setTesting(prev => ({ ...prev, [target]: false }));
		}
	};

	const toggleKeyVisibility = (key: string) => {
		setVisibleKeys(prev => ({ ...prev, [key]: !prev[key] }));
	};

	if (loading) {
		return (
			<div className="flex-1 flex flex-col items-center justify-center h-full gap-4 text-zinc-400 font-mono">
				<Loader2 className="w-8 h-8 animate-spin text-brand-500" />
				<span>LOADING CONFIGURATION MATRIX...</span>
			</div>
		);
	}

	return (
		<div className="flex-1 overflow-y-auto px-4 md:px-8 py-6 max-w-5xl mx-auto space-y-6 select-none font-mono">
			<div className="flex items-center justify-between border-b border-white/5 pb-4">
				<div>
					<h2 className="text-xl font-bold text-zinc-100 tracking-wider">PLATFORM CONFLICT CONTROLS</h2>
					<p className="text-[11px] text-zinc-500 mt-1 uppercase">Configure AI provider bindings, upstream proxy structures, and webhook alert integrations.</p>
				</div>
				<button 
					type="button"
					onClick={loadSettings}
					className="p-2 text-zinc-400 hover:text-white bg-white/5 rounded-lg border border-white/5 hover:bg-white/10 transition-all"
					title="Reload settings"
				>
					<RefreshCw className="w-4 h-4" />
				</button>
			</div>

			{error && (
				<div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-xl flex items-start gap-3">
					<AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
					<div className="text-xs uppercase tracking-wide leading-relaxed">
						<span className="font-bold">Error Matrix Failure:</span> {error}
					</div>
				</div>
			)}

			{successMsg && (
				<div className="p-4 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded-xl flex items-start gap-3">
					<Check className="w-5 h-5 shrink-0 mt-0.5" />
					<div className="text-xs uppercase tracking-wide leading-relaxed">
						{successMsg}
					</div>
				</div>
			)}

			<div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-start">
				{/* Settings Sidebar Tabs */}
				<div className="flex flex-col gap-1">
					{[
						{ id: "ai", label: "AI Engine", icon: Cpu },
						{ id: "auth", label: "Credentials", icon: Key },
						{ id: "routing", label: "Proxy Route", icon: Globe },
						{ id: "webhooks", label: "Integrations", icon: Webhook },
						{ id: "rates", label: "Throttles", icon: Sliders },
					].map(t => {
						const Icon = t.icon;
						const active = activeTab === t.id;
						return (
							<button
								type="button"
								key={t.id}
								onClick={() => setActiveTab(t.id as TabID)}
								className={`flex items-center gap-3 px-4 py-3 rounded-lg text-left text-xs uppercase tracking-wider transition-all border ${
									active
										? "bg-brand-500/10 border-brand-500/30 text-zinc-100 font-bold"
										: "bg-zinc-950/20 border-white/5 text-zinc-500 hover:text-zinc-300 hover:bg-zinc-950/40"
								}`}
							>
								<Icon className={`w-4 h-4 shrink-0 ${active ? "text-brand-500" : ""}`} />
								<span>{t.label}</span>
							</button>
						);
					})}
				</div>

				{/* Settings Form Body */}
				<form onSubmit={handleSave} className="md:col-span-3 space-y-6">
					<div className="floating-panel p-6 bg-zinc-950/30 border border-white/5 rounded-xl space-y-6">
						{activeTab === "ai" && (
							<div className="space-y-4">
								<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest border-b border-white/5 pb-2">AI ENGINE PROVIDERS</h3>
								
								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">OpenAI API Key</label>
									<div className="relative">
										<input
											type={visibleKeys["openai"] ? "text" : "password"}
											value={openaiKey}
											onChange={e => setOpenaiKey(e.target.value)}
											className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none transition-colors"
											placeholder="sk-..."
										/>
										<button
											type="button"
											onClick={() => toggleKeyVisibility("openai")}
											className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
										>
											{visibleKeys["openai"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
										</button>
									</div>
								</div>

								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">Anthropic API Key</label>
									<div className="relative">
										<input
											type={visibleKeys["anthropic"] ? "text" : "password"}
											value={anthropicKey}
											onChange={e => setAnthropicKey(e.target.value)}
											className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none transition-colors"
											placeholder="sk-..."
										/>
										<button
											type="button"
											onClick={() => toggleKeyVisibility("anthropic")}
											className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
										>
											{visibleKeys["anthropic"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
										</button>
									</div>
								</div>

								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">Local Ollama Endpoint</label>
									<input
										type="text"
										value={ollamaBaseUrl}
										onChange={e => setOllamaBaseUrl(e.target.value)}
										className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 px-4 text-zinc-200 outline-none transition-colors"
										placeholder="http://localhost:11434"
									/>
								</div>
							</div>
						)}

						{activeTab === "auth" && (
							<div className="space-y-6">
								<div>
									<div className="flex justify-between items-center border-b border-white/5 pb-2 mb-4">
										<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest">HTTP Headers</h3>
										<button
											type="button"
											onClick={() => setCustomHeaders(prev => [...prev, { key: "", value: "" }])}
											className="px-2 py-1 text-[10px] uppercase font-bold text-zinc-400 hover:text-white bg-white/5 rounded hover:bg-white/10"
										>
											+ Add
										</button>
									</div>
									{customHeaders.length === 0 ? (
										<div className="text-[11px] text-zinc-600 uppercase italic py-2">No custom request headers defined.</div>
									) : (
										<div className="space-y-2">
											{customHeaders.map((hdr, idx) => (
												<div key={idx} className="flex gap-2 items-center">
													<input
														type="text"
														placeholder="Header Key"
														value={hdr.key}
														onChange={e => {
															const next = [...customHeaders];
															next[idx].key = e.target.value;
															setCustomHeaders(next);
														}}
														className="flex-1 text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2 px-3 text-zinc-200 outline-none"
													/>
													<input
														type="text"
														placeholder="Header Value"
														value={hdr.value}
														onChange={e => {
															const next = [...customHeaders];
															next[idx].value = e.target.value;
															setCustomHeaders(next);
														}}
														className="flex-1 text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2 px-3 text-zinc-200 outline-none"
													/>
													<button
														type="button"
														onClick={() => setCustomHeaders(prev => prev.filter((_, i) => i !== idx))}
														className="px-2 py-1.5 text-xs text-rose-500 hover:bg-rose-500/10 rounded"
													>
														Delete
													</button>
												</div>
											))}
										</div>
									)}
								</div>

								<div>
									<div className="flex justify-between items-center border-b border-white/5 pb-2 mb-4">
										<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest">Session Cookies</h3>
										<button
											type="button"
											onClick={() => setSessionCookies(prev => [...prev, { name: "", value: "" }])}
											className="px-2 py-1 text-[10px] uppercase font-bold text-zinc-400 hover:text-white bg-white/5 rounded hover:bg-white/10"
										>
											+ Add
										</button>
									</div>
									{sessionCookies.length === 0 ? (
										<div className="text-[11px] text-zinc-600 uppercase italic py-2">No session cookies defined.</div>
									) : (
										<div className="space-y-2">
											{sessionCookies.map((cookie, idx) => (
												<div key={idx} className="flex gap-2 items-center">
													<input
														type="text"
														placeholder="Cookie Name"
														value={cookie.name}
														onChange={e => {
															const next = [...sessionCookies];
															next[idx].name = e.target.value;
															setSessionCookies(next);
														}}
														className="flex-1 text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2 px-3 text-zinc-200 outline-none"
													/>
													<input
														type="text"
														placeholder="Cookie Value"
														value={cookie.value}
														onChange={e => {
															const next = [...sessionCookies];
															next[idx].value = e.target.value;
															setSessionCookies(next);
														}}
														className="flex-1 text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2 px-3 text-zinc-200 outline-none"
													/>
													<button
														type="button"
														onClick={() => setSessionCookies(prev => prev.filter((_, i) => i !== idx))}
														className="px-2 py-1.5 text-xs text-rose-500 hover:bg-rose-500/10 rounded"
													>
														Delete
													</button>
												</div>
											))}
										</div>
									)}
								</div>
							</div>
						)}

						{activeTab === "routing" && (
							<div className="space-y-4">
								<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest border-b border-white/5 pb-2">UPSTREAM TRAFFIC ROUTING</h3>
								
								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">SOCKS5/HTTP Upstream Proxy</label>
									<input
										type="text"
										value={upstreamProxy}
										onChange={e => setUpstreamProxy(e.target.value)}
										className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 px-4 text-zinc-200 outline-none transition-colors"
										placeholder="socks5://127.0.0.1:9050"
									/>
								</div>

								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">Spoof User-Agent String</label>
									<textarea
										rows={3}
										value={userAgent}
										onChange={e => setUserAgent(e.target.value)}
										className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg p-4 text-zinc-200 outline-none transition-colors resize-none"
										placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."
									/>
								</div>
							</div>
						)}

						{activeTab === "webhooks" && (
							<div className="space-y-6">
								<div className="space-y-4 border-b border-white/5 pb-6">
									<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest">Issue Trackers</h3>
									
									<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
										<div className="space-y-2">
											<label className="text-[10px] text-zinc-500 uppercase font-semibold">Jira Cloud Host</label>
											<input
												type="text"
												value={jiraHost}
												onChange={e => setJiraHost(e.target.value)}
												className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 px-4 text-zinc-200 outline-none"
												placeholder="https://your-domain.atlassian.net"
											/>
										</div>

										<div className="space-y-2">
											<label className="text-[10px] text-zinc-500 uppercase font-semibold">Jira Account Email</label>
											<input
												type="email"
												value={jiraEmail}
												onChange={e => setJiraEmail(e.target.value)}
												className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 px-4 text-zinc-200 outline-none"
												placeholder="user@domain.com"
											/>
										</div>
									</div>

									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">Jira API Token</label>
										<div className="flex gap-2">
											<div className="relative flex-1">
												<input
													type={visibleKeys["jira"] ? "text" : "password"}
													value={jiraPat}
													onChange={e => setJiraPat(e.target.value)}
													className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none"
													placeholder="pat-..."
												/>
												<button
													type="button"
													onClick={() => toggleKeyVisibility("jira")}
													className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
												>
													{visibleKeys["jira"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
												</button>
											</div>
											<button
												type="button"
												onClick={() => handleTest("jira", { host: jiraHost, email: jiraEmail, pat: jiraPat })}
												disabled={testing["jira"]}
												className="px-4 text-xs font-bold uppercase tracking-wider text-zinc-400 bg-white/5 rounded-lg border border-white/5 hover:bg-white/10 hover:text-white"
											>
												{testing["jira"] ? "Testing..." : "Test"}
											</button>
										</div>
										{testResult["jira"] && (
											<span className={`text-[10px] font-bold ${testResult["jira"].success ? "text-emerald-400" : "text-rose-400"}`}>
												{testResult["jira"].success ? "JIRA VERIFIED" : `JIRA ERROR: ${testResult["jira"].msg}`}
											</span>
										)}
									</div>

									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">GitHub PAT Token (Issue Creation)</label>
										<div className="flex gap-2">
											<div className="relative flex-1">
												<input
													type={visibleKeys["github"] ? "text" : "password"}
													value={githubPat}
													onChange={e => setGithubPat(e.target.value)}
													className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none"
													placeholder="ghp-..."
												/>
												<button
													type="button"
													onClick={() => toggleKeyVisibility("github")}
													className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
												>
													{visibleKeys["github"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
												</button>
											</div>
											<button
												type="button"
												onClick={() => handleTest("github", { pat: githubPat })}
												disabled={testing["github"]}
												className="px-4 text-xs font-bold uppercase tracking-wider text-zinc-400 bg-white/5 rounded-lg border border-white/5 hover:bg-white/10 hover:text-white"
											>
												{testing["github"] ? "Testing..." : "Test"}
											</button>
										</div>
										{testResult["github"] && (
											<span className={`text-[10px] font-bold ${testResult["github"].success ? "text-emerald-400" : "text-rose-400"}`}>
												{testResult["github"].success ? "GITHUB VERIFIED" : `GITHUB ERROR: ${testResult["github"].msg}`}
											</span>
										)}
									</div>
								</div>

								<div className="space-y-4">
									<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest">Chat Webhooks</h3>

									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">Discord Alert Webhook URL</label>
										<div className="flex gap-2">
											<div className="relative flex-1">
												<input
													type={visibleKeys["discord"] ? "text" : "password"}
													value={discordWebhook}
													onChange={e => setDiscordWebhook(e.target.value)}
													className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none"
													placeholder="disc-..."
												/>
												<button
													type="button"
													onClick={() => toggleKeyVisibility("discord")}
													className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
												>
													{visibleKeys["discord"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
												</button>
											</div>
											<button
												type="button"
												onClick={() => handleTest("discord", { url: discordWebhook })}
												disabled={testing["discord"]}
												className="px-4 text-xs font-bold uppercase tracking-wider text-zinc-400 bg-white/5 rounded-lg border border-white/5 hover:bg-white/10 hover:text-white"
											>
												{testing["discord"] ? "Testing..." : "Test"}
											</button>
										</div>
										{testResult["discord"] && (
											<span className={`text-[10px] font-bold ${testResult["discord"].success ? "text-emerald-400" : "text-rose-400"}`}>
												{testResult["discord"].success ? "DISCORD CONNECTED" : `DISCORD ERROR: ${testResult["discord"].msg}`}
											</span>
										)}
									</div>

									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">Slack Alert Webhook URL</label>
										<div className="flex gap-2">
											<div className="relative flex-1">
												<input
													type={visibleKeys["slack"] ? "text" : "password"}
													value={slackWebhook}
													onChange={e => setSlackWebhook(e.target.value)}
													className="w-full text-xs font-mono bg-zinc-950 border border-white/5 rounded-lg py-2.5 pl-4 pr-10 text-zinc-200 outline-none"
													placeholder="slack-..."
												/>
												<button
													type="button"
													onClick={() => toggleKeyVisibility("slack")}
													className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300"
												>
													{visibleKeys["slack"] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
												</button>
											</div>
											<button
												type="button"
												onClick={() => handleTest("slack", { url: slackWebhook })}
												disabled={testing["slack"]}
												className="px-4 text-xs font-bold uppercase tracking-wider text-zinc-400 bg-white/5 rounded-lg border border-white/5 hover:bg-white/10 hover:text-white"
											>
												{testing["slack"] ? "Testing..." : "Test"}
											</button>
										</div>
										{testResult["slack"] && (
											<span className={`text-[10px] font-bold ${testResult["slack"].success ? "text-emerald-400" : "text-rose-400"}`}>
												{testResult["slack"].success ? "SLACK CONNECTED" : `SLACK ERROR: ${testResult["slack"].msg}`}
											</span>
										)}
									</div>
								</div>
							</div>
						)}

						{activeTab === "rates" && (
							<div className="space-y-4">
								<h3 className="text-xs uppercase text-zinc-400 font-bold tracking-widest border-b border-white/5 pb-2">GLOBAL RATE CONTROLS</h3>
								
								<div className="grid grid-cols-1 md:grid-cols-2 gap-4">
									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">Max Concurrent Workers</label>
										<input
											type="number"
											value={maxConcurrentWorkers}
											onChange={e => setMaxConcurrentWorkers(parseInt(e.target.value) || 1)}
											min={1}
											max={100}
											className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 px-4 text-zinc-200 outline-none transition-colors"
										/>
									</div>

									<div className="space-y-2">
										<label className="text-[10px] text-zinc-500 uppercase font-semibold">Max Requests Per Second (RPS)</label>
										<input
											type="number"
											value={rateLimitRps}
											onChange={e => setRateLimitRps(parseInt(e.target.value) || 1)}
											min={1}
											max={5000}
											className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg py-2.5 px-4 text-zinc-200 outline-none transition-colors"
										/>
									</div>
								</div>

								<div className="space-y-2">
									<label className="text-[10px] text-zinc-500 uppercase font-semibold">Global Scopes Blacklist (CIDRs / IPs)</label>
									<textarea
										rows={3}
										value={globalBlacklist}
										onChange={e => setGlobalBlacklist(e.target.value)}
										className="w-full text-xs font-mono bg-zinc-950 border border-white/5 focus:border-brand-500/50 rounded-lg p-4 text-zinc-200 outline-none transition-colors resize-none"
										placeholder="10.0.0.0/8, 192.168.1.1, 127.0.0.1"
									/>
								</div>
							</div>
						)}
					</div>

					{/* Save Configuration Trigger */}
					<div className="flex justify-end pt-2">
						<button
							type="submit"
							disabled={saving}
							className="px-6 py-3 rounded-lg bg-brand-500 hover:bg-brand-600 text-white flex items-center gap-2 text-xs font-bold uppercase tracking-wider disabled:opacity-50 transition-colors shadow-lg shadow-brand-500/10 ring-1 ring-white/10 cursor-pointer"
						>
							{saving ? (
								<>
									<Loader2 className="w-4 h-4 animate-spin" />
									<span>Saving settings...</span>
								</>
							) : (
								<>
									<Save className="w-4 h-4" />
									<span>Save Changes</span>
								</>
							)}
						</button>
					</div>
				</form>
			</div>
		</div>
	);
}
