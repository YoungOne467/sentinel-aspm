import type { StateCreator } from "zustand";
import type { ScanSlice, SecurityState } from "../storeTypes";

export const createScanSlice: StateCreator<SecurityState, [], [], ScanSlice> = (
	set,
) => ({
	scanStatus: "idle",
	scanLogs: [],
	scanProgress: 0,
	scanResults: null,
	scanError: null,

	setScanStatus: (scanStatus) => set({ scanStatus }),
	setScanLogs: (scanLogs) => set({ scanLogs }),
	setScanProgress: (scanProgress) => set({ scanProgress }),
	setScanResults: (scanResults) => set({ scanResults }),
	setScanError: (scanError) => set({ scanError }),
});
