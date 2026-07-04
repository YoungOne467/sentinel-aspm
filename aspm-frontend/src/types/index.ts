export type Tab =
	| "dashboard"
	| "targets"
	| "findings"
	| "terminal"
	| "settings"
	| "scope"
	| "topology"
	| "evasion";

export interface HealthData {
	status: "online" | "offline" | "degraded";
	version: string;
	active_jobs: number;
	ws_connections: number;
	system: {
		cpu_percent: number;
		memory_percent: number;
		memory_total_mb: number;
		memory_available_mb: number;
	};
}

export type SeverityLevel = "Critical" | "High" | "Medium" | "Low" | "Info";
export type ScanStatus =
	| "idle"
	| "running"
	| "completed"
	| "failed"
	| "interrupted";

export interface LogMessage {
	id: string;
	timestamp: string;
	level: "info" | "warning" | "critical" | "success" | "system";
	message: string;
}

export interface ExploitGuide {
	title: string;
	severity: string;
	danger_explanation: string;
	steps: {
		step: number;
		title: string;
		description: string;
		command: string;
		result: string;
	}[];
	attacker_scenarios: {
		scenario: string;
		description: string;
		severity: string;
	}[];
	remediation: string[];
	secrets_found?: { type: string; value: string }[];
}

export interface RemediationReport {
	vuln_type: string;
	explanation: string;
	code_patch: string;
	config_remediation: string;
	remediation_steps: string[];
}

export interface ExploitResult {
	success: boolean;
	target_url?: string;
	vuln_type?: string;
	vector?: string;
	final_payload: string;
	response_snippet?: string;
	evidence?:
		| {
				summary: string;
				data: Record<string, unknown>;
				mode?: string;
				raw_output?: string;
		  }
		| string; // Handle legacy strings
	reproduction_script?: string;
	logs: { time: string; level: string; msg: string }[];
	ai_feedback?: string;
	exploit_guide?: ExploitGuide;
	remediation_report?: RemediationReport;
	operator_handoff?: {
		state: string;
		stop_reason: string;
		next_owner: string;
		access_proven: boolean;
		access_level: string;
		action_mode: string;
		proof_signals?: string[];
		confidence_score?: number;
		exposure_score?: number;
		response_fingerprint?: string;
		command_channel?: {
			available: boolean;
			reason: string;
			allowed_commands: string[];
		};
		available_actions?: {
			id: string;
			label: string;
			description: string;
			requires_confirmation?: boolean;
			parameters?: Record<string, string[]>;
		}[];
		replay?: Record<string, unknown>;
		[key: string]: unknown;
	};
	available_actions?: {
		id: string;
		label: string;
		description: string;
		requires_confirmation?: boolean;
		parameters?: Record<string, string[]>;
	}[];
	request_replay?: Record<string, unknown>;
}

export interface Vulnerability {
	id: string;
	type: string;
	severity: SeverityLevel;
	description: string;
	vector: string;
	module?: string;
	payload: string;
	remediation?: string;
	patch_provided?: boolean;
	verified?: boolean;
	real_work?: boolean;
	verification_state?: "candidate" | "observed" | "verified";
	confidence?: "low" | "medium" | "high" | string;
	risk_score?: number;
	confidence_score?: number;
	affected_identity?: string;
	surface_node?: string | null;
	proof_chain?: { phase: string; [key: string]: unknown }[];
	replay?: Record<string, unknown>;
	verification_notes?: string[];
	evidence?: string;
	verification_results?: ExploitResult | null;
	target_url?: string;
	wstg?: string;
	cwe?: string[];
	owasp_category?: string;
	references?: { title: string; url: string }[];
}

export interface SurfaceNode {
	id: string;
	kind: string;
	url: string;
	method: string;
	classification: string;
	params: string[];
	sources: string[];
	metadata: Record<string, unknown>;
}

export interface SurfaceGraph {
	root_url: string;
	node_count: number;
	nodes: SurfaceNode[];
	counts_by_kind?: Record<string, number>;
	scope?: Record<string, unknown>;
}

export interface ScanResult {
	total: number;
	critical: number;
	high: number;
	medium: number;
	lowInfo: number;
	contract_version?: number;
	vulnerabilities: Vulnerability[];
	module_results?: Record<string, Vulnerability[]>;
	surface_graph?: SurfaceGraph;
	attack_paths?: unknown[];
}
