#!/usr/bin/env bun

import { boolFlag, parseArgs } from "./args.ts";
import {
	authSignIn,
	backupEncrypt,
	backupPush,
	doctor,
	HELP,
	identityCreate,
	identityInfo,
	oauthRegister,
} from "./commands.ts";
import {
	diagnoseBap,
	diagnoseClient,
	diagnoseIdentities,
	diagnoseLastOauth,
} from "./diagnose.ts";
import { loadConfig } from "./config.ts";
import { usage } from "./error.ts";
import { reportError } from "./output.ts";

export async function run(argv: string[]): Promise<number> {
	const json = argv.includes("--json");
	const quiet = argv.includes("--quiet");
	try {
		const args = parseArgs(argv);
		const cfg = loadConfig(args);
		if (boolFlag(args, "help") || args.positional[0] === "help") {
			process.stdout.write(HELP);
			return 0;
		}
		const [group, command] = args.positional;
		if (group === "identity" && command === "create") {
			return await identityCreate(args, cfg);
		}
		if (group === "identity" && command === "info") {
			return await identityInfo(args, cfg);
		}
		if (group === "backup" && command === "encrypt") {
			return await backupEncrypt(args, cfg);
		}
		if (group === "backup" && command === "push") {
			return await backupPush(args, cfg);
		}
		if (group === "auth" && command === "sign-in") {
			return await authSignIn(args, cfg);
		}
		if (group === "oauth" && command === "register") {
			return await oauthRegister(args, cfg);
		}
		if (group === "doctor") {
			return await doctor(args, cfg);
		}
		if (group === "diagnose" && command === "bap") {
			return await diagnoseBap(args, cfg);
		}
		if (group === "diagnose" && command === "identities") {
			return await diagnoseIdentities(args, cfg);
		}
		if (group === "diagnose" && command === "last-oauth") {
			return await diagnoseLastOauth(args, cfg);
		}
		if (group === "diagnose" && command === "client") {
			return await diagnoseClient(args, cfg);
		}
		if (!group) {
			process.stdout.write(HELP);
			return 0;
		}
		usage(`unknown command: ${args.positional.join(" ")}`);
	} catch (error) {
		return reportError({ json, quiet }, error);
	}
}

if (import.meta.main) {
	process.exit(await run(process.argv.slice(2)));
}
