import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";
import { PerformanceProvider } from "./contexts/PerformanceContext";

// ─── Initialize Query Client ──────────────────────────────────────────────────

const queryClient = new QueryClient({
	defaultOptions: {
		queries: {
			refetchOnWindowFocus: false,
			retry: 1,
			staleTime: 5000,
		},
	},
});

// ─── Render Root ──────────────────────────────────────────────────────────────

// biome-ignore lint/style/noNonNullAssertion: root element is guaranteed to exist in index.html
ReactDOM.createRoot(document.getElementById("root")!).render(
	<React.StrictMode>
		<QueryClientProvider client={queryClient}>
			<PerformanceProvider>
				<App />
			</PerformanceProvider>
		</QueryClientProvider>
	</React.StrictMode>,
);
