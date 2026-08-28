import { homedir } from "node:os";
import { join } from "node:path";
import type { ParsedArgs } from "./args.ts";
import { boolFlag, flag } from "./args.ts";
import { envFail } from "./error.ts";

export const DEFAULT_BASE_URL = "https://auth.sigmaidentity.com";
export const MIN_PASSWORD_LENGTH = 8;

function envRaw(name: string): string | undefined {
	if (!(name in process.env)) {
		return undefined;
	}
	return process.env[name];
}

function envMustBeNonEmpty(name: string, value: string | undefined): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	if (value === "") {
		envFail(`${name} is set but empty`);
	}
	return value;
}

export type RuntimeConfig = {
	baseUrl: string;
	home: string;
	cookieJar: string;
	json: boolean;
	quiet: boolean;
	force: boolean;
	timeoutMs: number;
};

export function loadConfig(args: ParsedArgs): RuntimeConfig {
	const urlFlag = flag(args, "base-url");
	const urlEnv = envMustBeNonEmpty("SIGMA_AUTH_URL", envRaw("SIGMA_AUTH_URL"));
	const baseUrl = urlFlag ?? urlEnv ?? DEFAULT_BASE_URL;
	if (baseUrl === "") {
		envFail("SIGMA_AUTH_URL is set but empty");
	}

	const homeFlag = flag(args, "home");
	const homeEnv = envMustBeNonEmpty("SIGMA_HOME", envRaw("SIGMA_HOME"));
	const home = homeFlag ?? homeEnv ?? join(homedir(), ".sigma");
	if (home === "") {
		envFail("SIGMA_HOME is set but empty");
	}

	const jarFlag = flag(args, "cookie-jar");
	const jarEnv = envMustBeNonEmpty("SIGMA_COOKIE_JAR", envRaw("SIGMA_COOKIE_JAR"));
	const cookieJar = jarFlag ?? jarEnv ?? join(home, "cookies.txt");
	if (cookieJar === "") {
		envFail("SIGMA_COOKIE_JAR is set but empty");
	}

	const timeoutRaw = flag(args, "timeout");
	const timeoutMs = timeoutRaw ? Number.parseInt(timeoutRaw, 10) : 10_000;
	if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
		envFail("--timeout must be a positive number of milliseconds");
	}

	return {
		baseUrl: baseUrl.replace(/\/$/, ""),
		home,
		cookieJar,
		json: boolFlag(args, "json"),
		quiet: boolFlag(args, "quiet"),
		force: boolFlag(args, "force"),
		timeoutMs,
	};
}

export function backupPath(args: ParsedArgs, home: string): string {
	return flag(args, "backup") ?? join(home, "identity.bep");
}
