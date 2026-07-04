import type {
	HealthData,
	LogMessage,
	ScanResult,
	ScanStatus,
	Tab,
} from "../types";

export interface TermLine {
	id: number;
	job_id: string;
	stream: "stdout" | "stderr" | "system";
	line: string;
	tool: string;
	ts: string;
}

export interface Target {
	id: string;
	name: string;
	host: string;
	port: number | null;
	tags: string[];
	notes: string;
	tech_stack: string[];
	risk_score: number;
	known_cves: string[];
	created_at: string;
	updated_at: string | null;
}

export interface Finding {
	id: string;
	job_id: string | null;
	target_id: string;
	title: string;
	severity: "critical" | "high" | "medium" | "low" | "info";
	category: string;
	description: string;
	evidence: string;
	solution: string;
	status: "open" | "confirmed" | "false_positive" | "resolved";
	ai_triaged: boolean;
	first_seen: string;
	last_seen: string;
}

export interface UiSlice {
	tab: Tab;
	darkMode: boolean;
	isEcoMode: boolean;
	sidebarOpen: boolean;
	selectedTargetId: string;
	selectedFindingId: string | null;
	setTab: (tab: Tab) => void;
	setDarkMode: (dark: boolean) => void;
	setEcoMode: (eco: boolean) => void;
	setSidebarOpen: (open: boolean) => void;
	setSelectedTargetId: (id: string) => void;
	setSelectedFindingId: (id: string | null) => void;
}

export interface ScanSlice {
	scanStatus: ScanStatus;
	scanLogs: LogMessage[];
	scanProgress: number;
	scanResults: ScanResult | null;
	scanError: string | null;
	setScanStatus: (status: ScanStatus) => void;
	setScanLogs: (logs: LogMessage[]) => void;
	setScanProgress: (progress: number) => void;
	setScanResults: (results: ScanResult | null) => void;
	setScanError: (error: string | null) => void;
}

export interface LogSlice {
	termLines: TermLine[];
	wsConnected: boolean;
	addTermLine: (line: Omit<TermLine, "id" | "ts">) => void;
	clearTermLines: () => void;
	setWsConnected: (connected: boolean) => void;
	connectWebSocket: () => void;
	disconnectWebSocket: () => void;
}

export interface TelemetryTick {
	cpu: number;
	ram: number;
	tasks: number;
	ts: string;
}

export interface HealthSlice {
	health: HealthData | null;
	setHealth: (health: HealthData | null) => void;
	startHealthPolling: () => void;
	stopHealthPolling: () => void;
	telemetryHistory: TelemetryTick[];
	addTelemetryTick: (tick: TelemetryTick) => void;
}

export interface FilterSlice {
	severity: Set<string>;
	cvssRange: [number, number];
	techniques: Set<string>;
	toggleSeverity: (sev: string) => void;
	setCvssRange: (range: [number, number]) => void;
	toggleTechnique: (tech: string) => void;
}

export type SecurityState = UiSlice & HealthSlice & ScanSlice & LogSlice & FilterSlice;
