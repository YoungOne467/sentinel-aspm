import { Finding, Target } from "../store";
import { fetchWithAuth } from "../apiClient";
import { API_URL } from "../config";

export interface ScopeRule {
	id: string;
	rule_type: "include" | "exclude";
	pattern: string;
	description: string;
}

export interface TopologyData {
	nodes: any[];
	edges: any[];
}

export const apiClient = {
	getTargets: async (): Promise<Target[]> => {
		const response = await fetchWithAuth(`${API_URL}/targets`);
		if (!response.ok) throw new Error("Failed to fetch targets");
		return response.json();
	},
	addTarget: async (target: Omit<Target, "id" | "created_at" | "updated_at" | "risk_score" | "known_cves" | "tech_stack">): Promise<Target> => {
		const response = await fetchWithAuth(`${API_URL}/targets`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(target),
		});
		if (!response.ok) throw new Error("Failed to add target");
		return response.json();
	},
	deleteTarget: async (id: string): Promise<void> => {
		const response = await fetchWithAuth(`${API_URL}/targets/${id}`, {
			method: "DELETE",
		});
		if (!response.ok) throw new Error("Failed to delete target");
	},
	getFindings: async (): Promise<Finding[]> => {
		const response = await fetchWithAuth(`${API_URL}/findings`);
		if (!response.ok) throw new Error("Failed to fetch findings");
		const data = await response.json();
		return data.findings || [];
	},
	updateFindingStatus: async (id: string, status: Finding["status"]): Promise<void> => {
		const response = await fetchWithAuth(`${API_URL}/findings/${id}`, {
			method: "PUT",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ status }),
		});
		if (!response.ok) throw new Error("Failed to update finding status");
	},
	getScopeRules: async (): Promise<ScopeRule[]> => {
		const response = await fetchWithAuth(`${API_URL}/scope`);
		if (!response.ok) throw new Error("Failed to fetch scope rules");
		return response.json();
	},
	addScopeRule: async (rule: any): Promise<ScopeRule> => {
		const response = await fetchWithAuth(`${API_URL}/scope`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(rule),
		});
		if (!response.ok) throw new Error("Failed to add scope rule");
		const data = await response.json();
		return { ...rule, id: data.id };
	},
	deleteScopeRule: async (id: string): Promise<void> => {
		const response = await fetchWithAuth(`${API_URL}/scope/${id}`, {
			method: "DELETE",
		});
		if (!response.ok) throw new Error("Failed to delete scope rule");
	},
	getTopology: async (targetId: string): Promise<TopologyData> => {
		const response = await fetchWithAuth(`${API_URL}/topology?target_id=${targetId}`);
		if (!response.ok) throw new Error("Failed to fetch topology data");
		return response.json();
	},
	getProxyHistory: async (limit: number, offset: number, hostFilter?: string): Promise<any[]> => {
		const url = new URL(`${API_URL}/proxy/history`);
		url.searchParams.append("limit", limit.toString());
		url.searchParams.append("offset", offset.toString());
		if (hostFilter) {
			url.searchParams.append("host", hostFilter);
		}
		const response = await fetchWithAuth(url.toString());
		if (!response.ok) throw new Error("Failed to fetch proxy history");
		return response.json();
	},
	getProxyRecord: async (id: string): Promise<any> => {
		const response = await fetchWithAuth(`${API_URL}/proxy/history/${id}`);
		if (!response.ok) throw new Error("Failed to fetch proxy record");
		return response.json();
	},
	replayRequest: async (recordId: string, mods: any): Promise<any> => {
		const response = await fetchWithAuth(`${API_URL}/exploit/replay`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ record_id: recordId, modifications: mods }),
		});
		if (!response.ok) throw new Error("Failed to replay request");
		return response.json();
	},
	fuzzRequest: async (params: any): Promise<any> => {
		const response = await fetchWithAuth(`${API_URL}/exploit/fuzz`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(params),
		});
		if (!response.ok) throw new Error("Failed to fuzz request");
		return response.json();
	},
	updateEvasionSettings: async (settings: any): Promise<void> => {
		const response = await fetchWithAuth(`${API_URL}/settings/evasion`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify(settings),
		});
		if (!response.ok) throw new Error("Failed to update evasion settings");
	},
	getEvasionSettings: async (): Promise<any> => {
		const response = await fetchWithAuth(`${API_URL}/settings/evasion`);
		if (!response.ok) throw new Error("Failed to fetch evasion settings");
		return response.json();
	},
	triggerScanJob: async (id: string, types: string): Promise<void> => {
		const response = await fetchWithAuth(`${API_URL}/jobs`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ target_id: id, scan_profile: types }),
		});
		if (!response.ok) throw new Error("Failed to trigger scan job");
	},
};
