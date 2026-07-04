import { API_URL } from "./config";

let cachedToken: string | null = null;

const getToken = async (): Promise<string> => {
	if (cachedToken !== null) return cachedToken;

	const formData = new URLSearchParams();
	formData.append("username", import.meta.env.VITE_API_USER || "admin");
	formData.append("password", import.meta.env.VITE_API_PASS || "admin");

	try {
		const response = await fetch(`${API_URL}/auth/login`, {
			method: "POST",
			headers: {
				"Content-Type": "application/x-www-form-urlencoded",
			},
			body: formData,
		});

		if (response.ok) {
			const data = await response.json();
			cachedToken = data.access_token;
			return data.access_token;
		} else {
			// Backend does not enforce auth or route is missing, cache empty token to avoid spamming
			cachedToken = "";
		}
	} catch (e) {
		console.error("Failed to get token", e);
		cachedToken = "";
	}
	return cachedToken;
};

export const fetchWithAuth = async (
	url: string,
	options: RequestInit = {},
): Promise<Response> => {
	const token = await getToken();

	const headers = new Headers(options.headers);
	if (token) {
		headers.set("Authorization", `Bearer ${token}`);
	}

	const response = await fetch(url, {
		...options,
		headers,
	});

	// If we receive a 401 Unauthorized, invalidate the cached token so the next request re-authenticates.
	if (response.status === 401) {
		cachedToken = null;
	}

	return response;
};
