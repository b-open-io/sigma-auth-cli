import { usage } from "./error.ts";

const BOOL_FLAGS = new Set([
	"json",
	"quiet",
	"force",
	"help",
	"signin",
	"push-backup",
	"show-mnemonic",
	"public",
	"password-stdin",
]);

const REPEATABLE = new Set(["redirect-uri", "grant-type"]);

export type ParsedArgs = {
	positional: string[];
	flags: Record<string, string[]>;
};

export function flag(args: ParsedArgs, name: string): string | undefined {
	const values = args.flags[name];
	return values?.[0];
}

export function flagList(args: ParsedArgs, name: string): string[] {
	return args.flags[name] ?? [];
}

export function boolFlag(args: ParsedArgs, name: string): boolean {
	return args.flags[name]?.[0] === "true";
}

export function parseArgs(argv: string[]): ParsedArgs {
	const positional: string[] = [];
	const flags: Record<string, string[]> = {};

	for (let i = 0; i < argv.length; i++) {
		const token = argv[i];
		if (token === undefined) {
			break;
		}
		if (token === "--password" || token.startsWith("--password=")) {
			usage("--password is not allowed; use --password-file, --password-stdin, or SIGMA_BACKUP_PASSWORD");
		}
		if (token === "-h") {
			flags.help = ["true"];
			continue;
		}
		if (token === "--") {
			positional.push(...argv.slice(i + 1));
			break;
		}
		if (!token.startsWith("--")) {
			positional.push(token);
			continue;
		}
		const eq = token.indexOf("=");
		const name = (eq === -1 ? token.slice(2) : token.slice(2, eq)).trim();
		if (!name) {
			usage("empty flag");
		}
		if (BOOL_FLAGS.has(name)) {
			const raw = eq === -1 ? "true" : token.slice(eq + 1);
			flags[name] = [raw === "false" ? "false" : "true"];
			continue;
		}
		const value = eq === -1 ? argv[++i] : token.slice(eq + 1);
		if (value === undefined || value.startsWith("--")) {
			usage(`missing value for --${name}`);
		}
		if (REPEATABLE.has(name)) {
			flags[name] = [...(flags[name] ?? []), value];
		} else {
			flags[name] = [value];
		}
	}

	return { positional, flags };
}
