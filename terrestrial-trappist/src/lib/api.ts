/**
 * Shared API client for the GymOpsSaaS frontend.
 *
 * Base URL points at the FastAPI backend on :8080 (port 8000 is taken by the
 * kiro-gateway). Override at build time with PUBLIC_API_BASE_URL in a .env file.
 */
export const API_BASE_URL =
	import.meta.env.PUBLIC_API_BASE_URL ?? 'http://localhost:8080';

const TOKEN_KEY = 'gymops_token';
const PRINCIPAL_KEY = 'gymops_principal';

export interface TokenResponse {
	access_token: string;
	token_type: string;
	role: 'owner' | 'member';
	portal: 'owner' | 'member';
	gym_id: string;
	user_id: string;
}

/** POST JSON to the API. Throws an Error carrying the API's `detail` on failure. */
export async function apiPost<T>(path: string, body: unknown): Promise<T> {
	let res: Response;
	try {
		res = await fetch(`${API_BASE_URL}${path}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		});
	} catch {
		// Network-level failure: server down, wrong port, CORS, DNS, etc.
		throw new Error(
			`Could not reach the API at ${API_BASE_URL}. Is the backend running on port 8080?`,
		);
	}

	if (!res.ok) {
		let detail = `Request failed (${res.status})`;
		try {
			const data = await res.json();
			if (data?.detail) detail = String(data.detail);
		} catch {
			/* non-JSON error body — keep the generic message */
		}
		throw new Error(detail);
	}
	return res.json() as Promise<T>;
}

/** Persist the session and return the portal to route to. */
export function storeSession(t: TokenResponse): void {
	localStorage.setItem(TOKEN_KEY, t.access_token);
	localStorage.setItem(
		PRINCIPAL_KEY,
		JSON.stringify({ role: t.role, gym_id: t.gym_id, user_id: t.user_id }),
	);
}

/** Map the API's portal field to the frontend route. */
export function portalPath(portal: 'owner' | 'member'): string {
	return portal === 'owner' ? '/owner' : '/member';
}
