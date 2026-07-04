// Detect the current window host to make API paths relative and proxy-friendly
const isSecure = window.location.protocol === "https:";
const protocol = isSecure ? "https:" : "http:";

export const API_BASE_URL = `${protocol}//${window.location.host}`;
export const API_URL = `${API_BASE_URL}/api`;

// Explicitly point to the FastAPI backend port 8000 for WebSockets in local development
export const WS_URL = `${isSecure ? "wss:" : "ws:"}//${window.location.host}/api/ws`;
