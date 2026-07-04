import type { StateCreator } from "zustand";
import { API_URL } from "../../config";
import type { HealthSlice, SecurityState } from "../storeTypes";

let healthIntervalId: number | NodeJS.Timeout | null = null;

export const createHealthSlice: StateCreator<
	SecurityState,
	[],
	[],
	HealthSlice
> = (set) => ({
	health: null,
	setHealth: (health) => set({ health }),
	telemetryHistory: [],
	addTelemetryTick: (tick) =>
		set((state) => ({
			telemetryHistory: [...state.telemetryHistory, tick].slice(-50),
		})),

	startHealthPolling: () => {
		if (healthIntervalId) return;

		const poll = async () => {
			try {
				const response = await fetch(`${API_URL}/health`);
				if (response.ok) {
					const healthData = await response.json();
					set({ health: healthData });
				}
			} catch (_e) {
				set({
					health: {
						status: "offline",
						version: "2.0.0",
						active_jobs: 0,
						ws_connections: 0,
						system: {
							cpu_percent: 0,
							memory_percent: 0,
							memory_total_mb: 0,
							memory_available_mb: 0,
						},
					},
				});
			}
		};

		poll();
		healthIntervalId = setInterval(poll, 10000);
	},

	stopHealthPolling: () => {
		if (healthIntervalId) {
			clearInterval(healthIntervalId);
			healthIntervalId = null;
		}
	},
});
