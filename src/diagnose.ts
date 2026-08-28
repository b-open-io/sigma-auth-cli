import type { ParsedArgs } from "./args.ts";
import { flag } from "./args.ts";
import type { RuntimeConfig } from "./config.ts";
import { usage } from "./error.ts";
import { createHttp, requestJson, throwHttp } from "./http.ts";
import { printHuman, printJson, type OutputMode } from "./output.ts";

function mode(cfg: RuntimeConfig): OutputMode {
	return { json: cfg.json, quiet: cfg.quiet };
}

function succeed(cfg: RuntimeConfig, data: Record<string, unknown>, human: string): number {
	if (cfg.json) {
		printJson(true, data);
	} else {
		printHuman(mode(cfg), human);
	}
	return 0;
}

function record(json: unknown): Record<string, unknown> {
	return json && typeof json === "object" ? (json as Record<string, unknown>) : {};
}

export async function diagnoseBap(args: ParsedArgs, cfg: RuntimeConfig): Promise<number> {
	const bapId = flag(args, "bap-id");
	if (!bapId) {
		usage("--bap-id is required");
	}
	const pubkey = flag(args, "pubkey");
	const client = createHttp(cfg);
	const profileRes = await requestJson(
		client,
		"GET",
		`/api/bap/profile?bapId=${encodeURIComponent(bapId)}`
	);
	if (profileRes.status >= 500) {
		throwHttp(
			"/api/bap/profile",
			profileRes.status,
			profileRes.json,
			profileRes.text,
			profileRes.headers
		);
	}
	const found = profileRes.status === 200 && record(profileRes.json).status === "OK";
	const profile = found ? record(profileRes.json).result ?? record(profileRes.json) : null;

	let registeredToPubkey: boolean | null = null;
	let identities: unknown[] | undefined;
	if (pubkey) {
		const listRes = await requestJson(
			client,
			"GET",
			`/api/user/bap-ids?pubkey=${encodeURIComponent(pubkey)}`
		);
		if (listRes.status >= 400) {
			throwHttp(
				"/api/user/bap-ids",
				listRes.status,
				listRes.json,
				listRes.text,
				listRes.headers
			);
		}
		const bapIds = record(listRes.json).bapIds;
		identities = Array.isArray(bapIds) ? bapIds : [];
		registeredToPubkey = identities.some((row) => {
			const item = record(row);
			return item.identity_key === bapId || item.id === bapId || item.bapId === bapId;
		});
	}

	let hint: string;
	if (registeredToPubkey === true && found) {
		hint = "registered to this pubkey and has a published profile";
	} else if (registeredToPubkey === true && !found) {
		hint = "registered to this pubkey but no published BAP profile";
	} else if (registeredToPubkey === false && found) {
		hint = "published profile exists but this BAP is not in this pubkey's registered list";
	} else if (registeredToPubkey === false && !found) {
		hint = "not in this pubkey's registered list and no published BAP profile (typical leftover HD identity)";
	} else if (found) {
		hint = "published BAP profile found";
	} else {
		hint = "no published BAP profile (404). Pass --pubkey to also check GET /api/user/bap-ids";
	}

	const data: Record<string, unknown> = {
		bapId,
		found,
		profile,
		hint,
	};
	if (pubkey) {
		data.pubkey = pubkey;
		data.registeredToPubkey = registeredToPubkey;
		data.registeredCount = identities?.length ?? 0;
	}

	const lines = [
		`bapId  ${bapId}`,
		`found  ${found}`,
		pubkey ? `registeredToPubkey  ${registeredToPubkey}` : null,
		hint,
	].filter((line): line is string => line !== null);
	return succeed(cfg, data, lines.join("\n"));
}

export async function diagnoseIdentities(
	args: ParsedArgs,
	cfg: RuntimeConfig
): Promise<number> {
	const pubkey = flag(args, "pubkey");
	const client = createHttp(cfg);
	const path = pubkey
		? `/api/user/bap-ids?pubkey=${encodeURIComponent(pubkey)}`
		: "/api/user/bap-ids";
	const result = await requestJson(client, "GET", path, {
		withCookies: !pubkey,
	});
	if (result.status >= 400) {
		throwHttp(path, result.status, result.json, result.text, result.headers);
	}
	const bapIds = record(result.json).bapIds;
	const list = Array.isArray(bapIds) ? bapIds : [];
	const names = list
		.map((row) => {
			const item = record(row);
			const id = String(item.identity_key ?? item.id ?? "");
			const name = typeof item.name === "string" ? item.name : "";
			const primary = item.is_primary === true ? " (primary)" : "";
			return `${id}${name ? `  ${name}` : ""}${primary}`;
		})
		.join("\n");
	return succeed(
		cfg,
		{ pubkey: pubkey ?? null, count: list.length, bapIds: list },
		names || "(none)"
	);
}

export async function diagnoseLastOauth(
	args: ParsedArgs,
	cfg: RuntimeConfig
): Promise<number> {
	const pubkey = flag(args, "pubkey");
	const clientId = flag(args, "client-id");
	if (!pubkey || !clientId) {
		usage("--pubkey and --client-id are required");
	}
	const client = createHttp(cfg);
	const path = `/api/user/last-oauth-identity?pubkey=${encodeURIComponent(pubkey)}&clientId=${encodeURIComponent(clientId)}`;
	const result = await requestJson(client, "GET", path);
	if (result.status >= 400) {
		throwHttp(path, result.status, result.json, result.text, result.headers);
	}
	const lastSelectedBapId = record(result.json).lastSelectedBapId ?? null;
	return succeed(
		cfg,
		{ pubkey, clientId, lastSelectedBapId },
		typeof lastSelectedBapId === "string" ? lastSelectedBapId : "(none)"
	);
}

export async function diagnoseClient(
	args: ParsedArgs,
	cfg: RuntimeConfig
): Promise<number> {
	const clientId = flag(args, "client-id");
	if (!clientId) {
		usage("--client-id is required");
	}
	const client = createHttp(cfg);
	const path = `/api/oauth-clients?clientId=${encodeURIComponent(clientId)}`;
	const result = await requestJson(client, "GET", path);
	if (result.status >= 400) {
		throwHttp(path, result.status, result.json, result.text, result.headers);
	}
	const payload = record(result.json);
	const clients = Array.isArray(payload.clients) ? payload.clients : [];
	const first = clients[0] ? record(clients[0]) : payload;
	if (!first.clientId && !first.name) {
		return succeed(cfg, { clientId, client: null }, "(not found)");
	}
	return succeed(
		cfg,
		{ clientId, client: first },
		`${String(first.clientId ?? clientId)}  ${String(first.name ?? "")}`
	);
}
