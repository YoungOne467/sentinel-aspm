import type { StateCreator } from "zustand";
import type { FilterSlice, SecurityState } from "../storeTypes";

export const createFilterSlice: StateCreator<
    SecurityState,
    [],
    [],
    FilterSlice
> = (set) => ({
    severity: new Set(),
    cvssRange: [0, 10],
    techniques: new Set(),
    toggleSeverity: (sev: string) =>
        set((state) => {
            const newSeverity = new Set(state.severity);
            if (newSeverity.has(sev)) {
                newSeverity.delete(sev);
            } else {
                newSeverity.add(sev);
            }
            return { severity: newSeverity };
        }),
    setCvssRange: (range: [number, number]) => set({ cvssRange: range }),
    toggleTechnique: (tech: string) =>
        set((state) => {
            const newTechniques = new Set(state.techniques);
            if (newTechniques.has(tech)) {
                newTechniques.delete(tech);
            } else {
                newTechniques.add(tech);
            }
            return { techniques: newTechniques };
        }),
});
