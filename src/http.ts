import {
	CliError,
	codeForHttp,
	exitForHttp,
} from "./error.ts";
import {
	cookieHeaderFor,
	deleteJar,
	loadJar,
	mergeSetCookies,
} from "./cookies.ts";

export type HttpClient = {
	baseUrl: string;
	cookieJar: string;
	timeoutMs: number;
	fetchImpl: typeof fetch;
};

export function createHttp(opts: {
	baseUrl: string;
	cookieJar: string;
	timeoutMs: number;
	fetchImpl?: typeof fetch;
}): HttpClient {
	return {
		baseUrl: opts.baseUrl,
		cookieJar: opts.cookieJar,
		timeoutMs: opts.timeoutMs,
		fetchImpl: opts.fetchImpl ?? fetch,
	};
}

export async function requestJson(
	client: HttpClient,
	method: string,
	path: string,
	opts?: {
		body?: unknown;
		headers?: Record<string, string>;
		withCookies?: boolean;
		saveCookies?: boolean;
		replaceCookies?: boolean;
	}
): Promise<{ status: number; headers: Headers; json: unknown; text: string }> {
	const url = `${client.baseUrl}${path}`;
	const headers = new Headers(opts?.headers);
	if (opts?.body !== undefined && !headers.has("content-type")) {
		headers.set("content-type", "application/json");
	}
	if (opts?.withCookies) {
		const cookie = cookieHeaderFor(url, loadJar(client.cookieJar));
		if (cookie) {
			headers.set("cookie", cookie);
		}
	}
	const response = await client.fetchImpl(url, {
		method,
		redirect: "error",
		headers,
		body:
			opts?.body === undefined
				? undefined
				: typeof opts.body === "string"
					? opts.body
					: JSON.stringify(opts.body),
		signal: AbortSignal.timeout(client.timeoutMs),
	});
	if (opts?.saveCookies) {
		if (opts.replaceCookies) deleteJar(client.cookieJar);
		mergeSetCookies(client.cookieJar, url, response.headers);
	}
	const text = await response.text();
	let json: unknown = null;
	if (text) {
		try {
			json = JSON.parse(text);
		} catch {
			json = null;
		}
	}
	return { status: response.status, headers: response.headers, json, text };
}

export function throwHttp(
	path: string,
	status: number,
	json: unknown,
	text: string,
	headers?: Headers
): never {
	const record = json && typeof json === "object" ? (json as Record<string, unknown>) : {};
	let message =
		(typeof record.error_description === "string" && record.error_description) ||
		(typeof record.message === "string" && record.message) ||
		(typeof record.error === "string" && record.error) ||
		text ||
		`${path} failed with ${status}`;
	const retryAfter = headers?.get("retry-after");
	if (retryAfter) {
		message = `${message} (Retry-After: ${retryAfter})`;
	}
	throw new CliError(exitForHttp(status), codeForHttp(status), message, status);
}
