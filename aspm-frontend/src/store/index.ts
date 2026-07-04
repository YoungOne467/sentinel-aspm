import { create } from "zustand";
import type { Tab } from "../types";
import { createHealthSlice } from "./slices/healthSlice";
import { createLogSlice } from "./slices/logSlice";
import { createScanSlice } from "./slices/scanSlice";
import { createUiSlice } from "./slices/uiSlice";
import { createFilterSlice } from "./slices/filterSlice";
import type { Finding, SecurityState, Target } from "./storeTypes";

export type { Finding, Tab, Target };

export const useSecurityStore = create<SecurityState>()((set, get, store) => ({
	...createUiSlice(set, get, store),
	...createHealthSlice(set, get, store),
	...createScanSlice(set, get, store),
	...createLogSlice(set, get, store),
	...createFilterSlice(set, get, store),
}));
