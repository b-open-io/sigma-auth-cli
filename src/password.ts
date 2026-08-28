import { readFileSync } from "node:fs";
import type { ParsedArgs } from "./args.ts";
import { boolFlag, flag } from "./args.ts";
import { MIN_PASSWORD_LENGTH } from "./config.ts";
import { cryptoFail, usage } from "./error.ts";

function isAllWhitespace(value: string): boolean {
	for (const ch of value) {
		if (!/\s/.test(ch)) {
			return false;
		}
	}
	return true;
}

function envPassword(): string | undefined {
	if (!("SIGMA_BACKUP_PASSWORD" in process.env)) {
		return undefined;
	}
	const value = process.env.SIGMA_BACKUP_PASSWORD;
	if (value === undefined || value === "") {
		usage("SIGMA_BACKUP_PASSWORD is set but empty");
	}
	if (isAllWhitespace(value)) {
		usage("SIGMA_BACKUP_PASSWORD is whitespace-only");
	}
	return value;
}

export async function resolvePassword(
	args: ParsedArgs,
	required: boolean
): Promise<string | undefined> {
	const fromFile = flag(args, "password-file");
	const fromStdin = boolFlag(args, "password-stdin");
	const fromEnv = envPassword();
	const sources = [fromFile, fromStdin ? "stdin" : undefined, fromEnv].filter(
		(item) => item !== undefined
	);
	if (sources.length > 1) {
		usage("use exactly one of --password-file, --password-stdin, or SIGMA_BACKUP_PASSWORD");
	}
	if (sources.length === 0) {
		if (required) {
			usage("password required: --password-file, --password-stdin, or SIGMA_BACKUP_PASSWORD");
		}
		return undefined;
	}

	let password: string;
	if (fromFile) {
		password = readFileSync(fromFile, "utf8").trim();
	} else if (fromStdin) {
		password = (await Bun.stdin.text()).trim();
	} else {
		password = fromEnv as string;
	}

	if (password === "") {
		usage("password is empty");
	}
	if (password.length < MIN_PASSWORD_LENGTH) {
		cryptoFail(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
	}
	return password;
}
