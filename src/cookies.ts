import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname } from "node:path";
import { ensureDir } from "./fsutil.ts";

export type Cookie = {
	domain: string;
	includeSubdomains: boolean;
	path: string;
	secure: boolean;
	expires: number;
	name: string;
	value: string;
};

function parseSetCookie(header: string, requestUrl: string): Cookie | null {
	const parts = header.split(";").map((part) => part.trim());
	const nv = parts[0];
	if (!nv) {
		return null;
	}
	const eq = nv.indexOf("=");
	if (eq <= 0) {
		return null;
	}
	const name = nv.slice(0, eq);
	const value = nv.slice(eq + 1);
	const url = new URL(requestUrl);
	let domain = url.hostname;
	let path = "/";
	let secure = false;
	let expires = 0;
	for (const part of parts.slice(1)) {
		const [k, v] = part.split("=").map((item) => item.trim());
		const key = k?.toLowerCase();
		if (key === "domain" && v) {
			domain = v.replace(/^\./, "");
		} else if (key === "path" && v) {
			path = v;
		} else if (key === "secure") {
			secure = true;
		} else if (key === "max-age" && v) {
			expires = Math.floor(Date.now() / 1000) + Number.parseInt(v, 10);
		}
	}
	return {
		domain,
		includeSubdomains: domain !== "localhost",
		path,
		secure,
		expires,
		name,
		value,
	};
}

export function loadJar(path: string): Cookie[] {
	if (!existsSync(path)) {
		return [];
	}
	const cookies: Cookie[] = [];
	for (const line of readFileSync(path, "utf8").split("\n")) {
		if (!line || line.startsWith("#")) {
			continue;
		}
		const cols = line.split("\t");
		if (cols.length < 7) {
			continue;
		}
		const [domain, flag, path, secure, expires, name, value] = cols;
		if (!domain || !path || !name || value === undefined) {
			continue;
		}
		cookies.push({
			domain: domain.replace(/^\./, ""),
			includeSubdomains: flag === "TRUE",
			path,
			secure: secure === "TRUE",
			expires: Number.parseInt(expires ?? "0", 10) || 0,
			name,
			value,
		});
	}
	return cookies;
}

export function saveJar(path: string, cookies: Cookie[]): void {
	ensureDir(dirname(path));
	const lines = [
		"# Netscape HTTP Cookie File",
		"# https://curl.se/docs/http-cookies.html",
		"",
	];
	for (const cookie of cookies) {
		const domain = cookie.includeSubdomains ? `.${cookie.domain}` : cookie.domain;
		lines.push(
			[
				domain,
				cookie.includeSubdomains ? "TRUE" : "FALSE",
				cookie.path,
				cookie.secure ? "TRUE" : "FALSE",
				String(cookie.expires),
				cookie.name,
				cookie.value,
			].join("\t")
		);
	}
	writeFileSync(path, `${lines.join("\n")}\n`, { encoding: "utf8", mode: 0o600 });
	chmodSync(path, 0o600);
}

export function mergeSetCookies(
	jarPath: string,
	requestUrl: string,
	headers: Headers
): Cookie[] {
	const cookies = loadJar(jarPath);
	const setCookies =
		typeof headers.getSetCookie === "function"
			? headers.getSetCookie()
			: headers.get("set-cookie")
				? [headers.get("set-cookie") as string]
				: [];
	for (const header of setCookies) {
		const parsed = parseSetCookie(header, requestUrl);
		if (!parsed) {
			continue;
		}
		const idx = cookies.findIndex(
			(item) => item.name === parsed.name && item.domain === parsed.domain
		);
		if (idx >= 0) {
			cookies[idx] = parsed;
		} else {
			cookies.push(parsed);
		}
	}
	saveJar(jarPath, cookies);
	return cookies;
}

export function cookieHeaderFor(url: string, cookies: Cookie[]): string {
	const target = new URL(url);
	const now = Math.floor(Date.now() / 1000);
	return cookies
		.filter((cookie) => {
			if (cookie.expires > 0 && cookie.expires < now) {
				return false;
			}
			if (cookie.secure && target.protocol !== "https:") {
				return false;
			}
			const host = target.hostname;
			const domainOk =
				host === cookie.domain ||
				(cookie.includeSubdomains && host.endsWith(`.${cookie.domain}`));
			const pathOk =
				target.pathname === cookie.path ||
				target.pathname.startsWith(
					cookie.path.endsWith("/") ? cookie.path : `${cookie.path}/`
				) ||
				cookie.path === "/";
			return domainOk && pathOk;
		})
		.map((cookie) => `${cookie.name}=${cookie.value}`)
		.join("; ");
}

export function sessionCookieNames(cookies: Cookie[]): string[] {
	return cookies.map((cookie) => cookie.name);
}
