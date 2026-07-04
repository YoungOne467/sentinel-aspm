import type { StateCreator } from "zustand";
import type { SecurityState, UiSlice } from "../storeTypes";

export const createUiSlice: StateCreator<SecurityState, [], [], UiSlice> = (
	set,
) => ({
	tab: "dashboard",
	darkMode: true,
	isEcoMode: typeof window !== "undefined" ? localStorage.getItem("aspm_eco_mode") === "true" : false,
	sidebarOpen: false,
	selectedTargetId: "",
	selectedFindingId: null,

	setTab: (tab) => set({ tab }),
	setDarkMode: (darkMode) => set({ darkMode }),
	setEcoMode: (isEcoMode) => {
		if (typeof window !== "undefined") {
			localStorage.setItem("aspm_eco_mode", String(isEcoMode));
		}
		set({ isEcoMode });
	},
	setSidebarOpen: (sidebarOpen) => set({ sidebarOpen }),
	setSelectedTargetId: (selectedTargetId) =>
		set({ selectedTargetId, selectedFindingId: null }),
	setSelectedFindingId: (selectedFindingId) => set({ selectedFindingId }),
});
