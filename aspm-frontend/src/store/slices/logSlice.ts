import type { StateCreator } from "zustand";
import { WS_URL } from "../../config";
import type {
	LogMessage,
	ScanResult,
	ScanStatus,
	SurfaceGraph,
	Vulnerability,
} from "../../types";
import type { LogSlice, SecurityState, TermLine } from "../storeTypes";

let nextLineId = 1;
let logBuffer: Omit<TermLine, "id" | "ts">[] = [];
let scanLogBuffer: LogMessage[] = [];
let pendingScanStatus: ScanStatus | null = null;
let pendingScanProgress: number | null = null;
let pendingScanResults: ScanResult | null = null;
let pendingScanError: string | null = null;
let hasPendingScanUpdates = false;
let telemetryBuffer: { cpu: number; ram: number; tasks: number; ts: string }[] = [];

let flushIntervalId: number | NodeJS.Timeout | null = null;
let socket: WebSocket | null = null;
let reconnectAttempts = 0;
let reconnectTimeoutId: number | NodeJS.Timeout | null = null;
let _isConnecting = false;
let shouldReconnect = true;

interface SeverityCounts {
	critical: number;
	high: number;
	medium: number;
	low: number;
}

interface RawScanResult {
	total?: number;
	vulnerabilities?: Vulnerability[];
	active_scan?: {
		total?: number;
		by_severity?: Record<string, number>;
		module_results?: Record<string, Vulnerability[]>;
		surface_graph?: SurfaceGraph;
	};
	module_results?: Record<string, Vulnerability[]>;
	surface_graph?: SurfaceGraph;
	attack_paths?: unknown[];
}

interface WsMessage {
	type: string;
	job_id?: string;
	stream?: "stdout" | "stderr" | "system";
	line?: string;
	tool?: string;
	message?: string;
	level?: "info" | "warning" | "critical" | "success" | "system";
	value?: number;
	results?: unknown;
	error?: string;
	status?: string;
	cpu?: number;
	ram?: number;
	tasks?: number;
}

/**
 * Counts the severities in the vulnerabilities list.
 * Extracted helper to reduce cognitive complexity.
 */
function countSeverities(vulns: Vulnerability[]): SeverityCounts {
	const counts = { critical: 0, high: 0, medium: 0, low: 0 };
	for (let i = 0; i < vulns.length; i++) {
		const v = vulns[i];
		if (!v) continue;
		const severity = v.severity;
		if (severity === "Critical") {
			counts.critical++;
		} else if (severity === "High") {
			counts.high++;
		} else if (severity === "Medium") {
			counts.medium++;
		} else if (severity === "Low" || severity === "Info") {
			counts.low++;
		}
	}
	return counts;
}

/**
 * Obtains default count mapping from active_scan summary by_severity.
 * Extracted helper to reduce cognitive complexity.
 */
function getFallbackCounts(
	bySeverity: Record<string, number> | undefined,
): SeverityCounts {
	const b = bySeverity || {};
	return {
		critical: b.Critical || 0,
		high: b.High || 0,
		medium: b.Medium || 0,
		low: (b.Low || 0) + (b.Info || 0),
	};
}

/**
 * Transforms raw backend results into the expected ScanResult format.
 * Written with reduced branches to keep cyclomatic complexity minimal.
 */
function transformBackendResults(raw: RawScanResult | undefined): ScanResult {
	if (!raw) {
		return {
			total: 0,
			critical: 0,
			high: 0,
			medium: 0,
			lowInfo: 0,
			vulnerabilities: [],
		};
	}

	const { total, vulnerabilities, active_scan, attack_paths } = raw;

	if (typeof total === "number" && Array.isArray(vulnerabilities)) {
		return raw as ScanResult;
	}

	const vulns: Vulnerability[] = Array.isArray(vulnerabilities)
		? vulnerabilities
		: [];
	const summary = active_scan || {};
	const bySeverity = summary.by_severity || {};

	const counts =
		vulns.length > 0 ? countSeverities(vulns) : getFallbackCounts(bySeverity);

	return {
		total: vulns.length || summary.total || 0,
		critical: counts.critical,
		high: counts.high,
		medium: counts.medium,
		lowInfo: counts.low,
		vulnerabilities: vulns,
		module_results: summary.module_results || raw.module_results,
		surface_graph: summary.surface_graph || raw.surface_graph,
		attack_paths: attack_paths,
	};
}

// ─── WebSocket Event Dispatcher Helpers ─────────────────────────────────────

function handleTerminalLog(data: WsMessage) {
	logBuffer.push({
		job_id: data.job_id || "unknown",
		stream: data.stream || "stdout",
		line: data.line || "",
		tool: data.tool || "Engine",
	});
}

function handleJobStatus(data: WsMessage) {
	window.dispatchEvent(
		new CustomEvent("sentinel_job_status", { detail: data }),
	);
}

function handleSystemAlert(data: WsMessage) {
	logBuffer.push({
		job_id: "system",
		stream: "system",
		line: `[ALERT] ${data.message}`,
		tool: "SYSTEM",
	});
}

function handleLog(data: WsMessage) {
	scanLogBuffer.push({
		id: Math.random().toString(36).substring(2, 11),
		timestamp: new Date().toLocaleTimeString("en-US", { hour12: false }),
		level: data.level || "info",
		message: data.message || "",
	});
	hasPendingScanUpdates = true;
}

function handleScanProgress(data: WsMessage) {
	pendingScanProgress = data.value !== undefined ? data.value : null;
	hasPendingScanUpdates = true;
}

function handleScanCompleted(data: WsMessage) {
	pendingScanStatus = "completed";
	pendingScanError = null;
	pendingScanResults = transformBackendResults(data.results as RawScanResult);
	hasPendingScanUpdates = true;
}

function handleScanFailed(data: WsMessage) {
	pendingScanStatus = "failed";
	pendingScanError = data.error || "Scan failed.";
	hasPendingScanUpdates = true;
}

function handleStatusUpdate(data: WsMessage) {
	if (data.status === "running") {
		pendingScanStatus = "running";
		hasPendingScanUpdates = true;
	}
}

function handleFinding(data: WsMessage) {
	window.dispatchEvent(new CustomEvent("sentinel_finding", { detail: data }));
}

function handleSystemTelemetry(data: WsMessage) {
	telemetryBuffer.push({
		cpu: data.cpu !== undefined ? data.cpu : 0,
		ram: data.ram !== undefined ? data.ram : 0,
		tasks: data.tasks !== undefined ? data.tasks : 0,
		ts: new Date().toISOString(),
	});
}

type MessageHandler = (data: WsMessage) => void;

const handlers: Record<string, MessageHandler> = {
	terminal_output: handleTerminalLog,
	job_status: handleJobStatus,
	system_alert: handleSystemAlert,
	log: handleLog,
	progress: handleScanProgress,
	scan_completed: handleScanCompleted,
	scan_failed: handleScanFailed,
	status_update: handleStatusUpdate,
	finding: handleFinding,
	system_telemetry: handleSystemTelemetry,
};

export const createLogSlice: StateCreator<SecurityState, [], [], LogSlice> = (
	set,
	get,
) => {
	const flushLogs = () => {
		const hasLogs = logBuffer.length > 0;
		const hasScanUpdates = hasPendingScanUpdates;

		if (!hasLogs && !hasScanUpdates) return;

		const nextState: Partial<SecurityState> = {};
		const currentState = get();

		if (hasLogs) {
			const rawLines = [...logBuffer];
			logBuffer = [];

			const linesToAppend: Omit<TermLine, "id" | "ts">[] = [];
			// Deduplicate contiguous duplicate messages
			for (let i = 0; i < rawLines.length; i++) {
				const current = rawLines[i];
				const prev = linesToAppend[linesToAppend.length - 1];
				if (
					prev &&
					prev.line === current.line &&
					prev.stream === current.stream
				) {
					continue;
				}
				linesToAppend.push(current);
			}

			if (linesToAppend.length > 0) {
				let currentId = nextLineId;
				const newLines = linesToAppend.map((line) => ({
					...line,
					id: currentId++,
					ts: new Date().toISOString(),
				}));
				nextLineId = currentId;
				const merged = [...currentState.termLines, ...newLines];
				nextState.termLines = merged.slice(-500);
			}
		}

		if (scanLogBuffer.length > 0) {
			const newScanLogs = [...scanLogBuffer];
			scanLogBuffer = [];
			nextState.scanLogs = [...currentState.scanLogs, ...newScanLogs];
		}

		if (pendingScanStatus !== null) {
			nextState.scanStatus = pendingScanStatus;
			pendingScanStatus = null;
		}
		if (pendingScanProgress !== null) {
			nextState.scanProgress = pendingScanProgress;
			pendingScanProgress = null;
		}
		if (pendingScanResults !== null) {
			nextState.scanResults = pendingScanResults;
			pendingScanResults = null;
		}
		if (pendingScanError !== null) {
			nextState.scanError = pendingScanError;
			pendingScanError = null;
		}

		if (telemetryBuffer.length > 0) {
			const newTicks = [...telemetryBuffer];
			telemetryBuffer = [];
			nextState.telemetryHistory = [...currentState.telemetryHistory, ...newTicks].slice(-50);
		}

		hasPendingScanUpdates = false;

		set(nextState);
	};

	return {
		termLines: [],
		wsConnected: false,

		addTermLine: (line) => {
			logBuffer.push(line);
			if (!flushIntervalId) {
				flushLogs();
			}
		},

		clearTermLines: () => set({ termLines: [] }),
		setWsConnected: (wsConnected) => set({ wsConnected }),

		connectWebSocket: () => {
			if (
				socket &&
				(socket.readyState === WebSocket.OPEN ||
					socket.readyState === WebSocket.CONNECTING)
			)
				return;
			shouldReconnect = true;
			_isConnecting = true;

			console.log(`[SENTINEL WS] Connecting to ${WS_URL}...`);
			socket = new WebSocket(WS_URL);

			socket.onopen = () => {
				_isConnecting = false;
				reconnectAttempts = 0;
				set({ wsConnected: true });
				console.log("[SENTINEL WS] Connection established.");

				if (!flushIntervalId) {
					flushIntervalId = setInterval(() => flushLogs(), 100);
				}
			};

			socket.onmessage = (event) => {
				let data: WsMessage;
				try {
					data = JSON.parse(event.data);
				} catch (_e) {
					return;
				}

				window.dispatchEvent(
					new CustomEvent("aspm_ws_message", { detail: data }),
				);

				const handler = handlers[data.type];
				if (handler) {
					handler(data);
				}
			};

			socket.onclose = () => {
				_isConnecting = false;
				set({ wsConnected: false });
				socket = null;

				if (shouldReconnect) {
					const delay =
						Math.min(1000 * 2 ** reconnectAttempts, 30000) +
						Math.random() * 1000;
					console.warn(
						`[SENTINEL WS] Disconnected. Reconnecting in ${(delay / 1000).toFixed(1)}s...`,
					);
					reconnectAttempts++;
					reconnectTimeoutId = setTimeout(
						() => get().connectWebSocket(),
						delay,
					);
				}
			};

			socket.onerror = (error) => {
				console.error("[SENTINEL WS] WebSocket error encountered:", error);
			};
		},

		disconnectWebSocket: () => {
			shouldReconnect = false;
			_isConnecting = false;
			if (reconnectTimeoutId) {
				clearTimeout(reconnectTimeoutId);
				reconnectTimeoutId = null;
			}
			if (socket) {
				socket.close();
				socket = null;
			}
			if (flushIntervalId) {
				clearInterval(flushIntervalId);
				flushIntervalId = null;
			}
			set({ wsConnected: false });
			console.log("[SENTINEL WS] WebSocket disconnected manually.");
		},
	};
};
