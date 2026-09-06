import { readFileSync } from "node:fs";
import { getAuthToken } from "bitcoin-auth";
import type { BapMasterBackup } from "bitcoin-backup";
import { isLegacyBackup, isType42Backup } from "bitcoin-backup";
import type { ParsedArgs } from "./args.ts";
import { boolFlag, flag, flagList } from "./args.ts";
import { backupPath, type RuntimeConfig } from "./config.ts";
import { deleteJar, loadJar, sessionCookieNames } from "./cookies.ts";
import { cryptoFail, usage } from "./error.ts";
import { ensureDir, pathExists, readText, writeSecretFile } from "./fsutil.ts";
import { createHttp, requestJson, throwHttp } from "./http.ts";
import {
	assertBitcoinBackupCiphertext,
	bapFromBackup,
	createMasterBackup,
	decryptMaster,
	encryptMaster,
	looksLikePlaintextBackup,
	memberWif,
	publicFields,
	rootPubkey,
} from "./identity.ts";
import { type OutputMode, printHuman, printJson, printWarn } from "./output.ts";
import { resolvePassword } from "./password.ts";

function mode(cfg: RuntimeConfig): OutputMode {
	return { json: cfg.json, quiet: cfg.quiet };
}

function succeed(
	cfg: RuntimeConfig,
	data: Record<string, unknown>,
	human: string,
): number {
	if (cfg.json) {
		printJson(true, data);
	} else {
		printHuman(mode(cfg), human);
	}
	return 0;
}

async function loadBackup(
	args: ParsedArgs,
	cfg: RuntimeConfig,
	password: string,
): Promise<{ path: string; backup: BapMasterBackup; ciphertext: string }> {
	const path = backupPath(args, cfg.home);
	const ciphertext = readText(path);
	const backup = await decryptMaster(ciphertext, password);
	return { path, backup, ciphertext };
}

export async function identityCreate(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const label = flag(args, "label");
	if (!label) {
		usage("--label is required");
	}
	const password = await resolvePassword(args, true);
	if (!password) {
		usage("password required");
	}
	const created = createMasterBackup(label);
	const encrypted = await encryptMaster(created.backup, password);
	const out = flag(args, "out") ?? `${cfg.home}/identity.bep`;
	writeSecretFile(out, encrypted, cfg.force);

	let userId: string | undefined;
	if (boolFlag(args, "signin") || boolFlag(args, "push-backup")) {
		const signinArgs: ParsedArgs = {
			positional: args.positional,
			flags: { ...args.flags, backup: [out] },
		};
		const code = await authSignIn(signinArgs, cfg, false, password);
		if (code !== 0) {
			return code;
		}
		if (boolFlag(args, "push-backup")) {
			const pushCode = await backupPush(signinArgs, cfg, false);
			if (pushCode !== 0) {
				return pushCode;
			}
		}
	}

	return succeed(
		cfg,
		{
			bapId: created.bapId,
			pubkey: created.pubkey,
			address: created.address,
			backupPath: out,
			userId,
		},
		`created ${created.bapId}\n${out}`,
	);
}

export async function identityInfo(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const password = await resolvePassword(args, true);
	if (!password) {
		usage("password required");
	}
	const { backup } = await loadBackup(args, cfg, password);
	const fields = publicFields(backup, flag(args, "bap-id"));
	return succeed(
		cfg,
		fields,
		`${fields.bapId}\n${fields.pubkey}\n${fields.address}`,
	);
}

export async function backupEncrypt(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const input = flag(args, "in");
	const out = flag(args, "out");
	if (!input || !out) {
		usage("--in and --out are required");
	}
	const password = await resolvePassword(args, true);
	if (!password) {
		usage("password required");
	}
	const raw = readText(input);
	if (!looksLikePlaintextBackup(raw)) {
		cryptoFail("--in does not look like a decrypted master backup JSON");
	}
	const parsed = JSON.parse(raw) as BapMasterBackup;
	if (!(isType42Backup(parsed) || isLegacyBackup(parsed))) {
		cryptoFail("--in is not a Type42 or legacy master backup");
	}
	let warning: string | undefined;
	const bap = bapFromBackup(parsed);
	if (bap.listIds().length === 0) {
		warning = "ids is empty; auth sign-in will reject this backup";
		printWarn(mode(cfg), warning);
	}
	const encrypted = await encryptMaster(parsed, password);
	writeSecretFile(out, encrypted, cfg.force);
	return succeed(cfg, { backupPath: out, warning }, out);
}

export async function authSignIn(
	args: ParsedArgs,
	cfg: RuntimeConfig,
	emit = true,
	resolvedPassword?: string,
): Promise<number> {
	const password = resolvedPassword ?? (await resolvePassword(args, true));
	if (!password) {
		usage("password required");
	}
	const { backup } = await loadBackup(args, cfg, password);
	const ids = bapFromBackup(backup).listIds();
	if (ids.length === 0) {
		cryptoFail("backup has no identities; run identity create");
	}
	const member = memberWif(backup, flag(args, "bap-id"));
	const body = { bapId: member.bapId };
	const token = getAuthToken({
		privateKeyWif: member.wif,
		requestPath: "/api/auth/sign-in/sigma",
		scheme: "brc77",
	});
	const client = createHttp(cfg);
	ensureDir(cfg.home);
	const signed = await requestJson(client, "POST", "/api/auth/sign-in/sigma", {
		body,
		headers: { "x-auth-token": token },
		saveCookies: true,
	});
	if (signed.status >= 400) {
		throwHttp(
			"/api/auth/sign-in/sigma",
			signed.status,
			signed.json,
			signed.text,
			signed.headers,
		);
	}
	const payload = signed.json as {
		user?: { id?: string; pubkey?: string };
	};
	const name = ("label" in backup && backup.label) || "Identity 1";
	const registered = await requestJson(client, "POST", "/api/user/bap-ids", {
		body: {
			bapId: member.bapId,
			name,
			isPrimary: true,
			accountPubkey: member.pubkey,
			counter: 0,
		},
		withCookies: true,
	});
	if (registered.status >= 400) {
		await requestJson(client, "POST", "/api/auth/sign-out", {
			withCookies: true,
		});
		deleteJar(client.cookieJar);
		throwHttp(
			"/api/user/bap-ids",
			registered.status,
			registered.json,
			registered.text,
			registered.headers,
		);
	}
	if (!emit) {
		return 0;
	}
	return succeed(
		cfg,
		{
			userId: payload.user?.id,
			pubkey: member.pubkey,
			bapId: member.bapId,
			cookieJar: cfg.cookieJar,
		},
		`signed in as ${member.bapId}`,
	);
}

export async function backupPush(
	args: ParsedArgs,
	cfg: RuntimeConfig,
	emit = true,
): Promise<number> {
	const path = backupPath(args, cfg.home);
	const ciphertext = readText(path).replace(/\n+$/, "");
	assertBitcoinBackupCiphertext(ciphertext);
	const client = createHttp(cfg);
	const result = await requestJson(client, "POST", "/api/backup", {
		body: { encryptedBackup: ciphertext },
		withCookies: true,
	});
	if (result.status >= 400) {
		throwHttp(
			"/api/backup",
			result.status,
			result.json,
			result.text,
			result.headers,
		);
	}
	const payload = result.json as { bapId?: string; message?: string };
	if (!emit) {
		return 0;
	}
	return succeed(
		cfg,
		{ bapId: payload.bapId, message: payload.message },
		payload.message ?? "backup stored",
	);
}

export async function oauthRegister(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const name = flag(args, "name");
	const redirectUris = flagList(args, "redirect-uri");
	if (!name) {
		usage("--name is required");
	}
	if (redirectUris.length === 0) {
		usage("at least one --redirect-uri is required");
	}
	const signingPubkey = flag(args, "signing-pubkey");
	const client = createHttp(cfg);
	if (signingPubkey) {
		const ownerBapId = flag(args, "owner-bap-id");
		const clientId = flag(args, "client-id");
		if (!ownerBapId || !clientId) {
			usage(
				"--owner-bap-id and --client-id are required with --signing-pubkey",
			);
		}
		const result = await requestJson(client, "POST", "/api/oauth-clients", {
			body: {
				clientId,
				ownerBapId,
				name,
				redirectUris,
				accountPubkey: signingPubkey,
			},
			withCookies: true,
		});
		if (result.status >= 400) {
			throwHttp(
				"/api/oauth-clients",
				result.status,
				result.json,
				result.text,
				result.headers,
			);
		}
		const payload = result.json as {
			client?: {
				clientId?: string;
				accountPubkey?: string;
				ownerBapId?: string;
			};
		};
		return succeed(
			cfg,
			{
				clientId: payload.client?.clientId ?? clientId,
				accountPubkey: signingPubkey,
				ownerBapId,
				redirectUris,
				public: true,
				path: "session",
			},
			payload.client?.clientId ?? clientId,
		);
	}

	const grantTypes = flagList(args, "grant-type");
	const result = await requestJson(
		client,
		"POST",
		"/api/auth/oauth2/register",
		{
			body: {
				client_name: name,
				redirect_uris: redirectUris,
				grant_types:
					grantTypes.length > 0
						? grantTypes
						: ["authorization_code", "refresh_token"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			},
		},
	);
	if (result.status >= 400) {
		throwHttp(
			"/api/auth/oauth2/register",
			result.status,
			result.json,
			result.text,
			result.headers,
		);
	}
	const payload = result.json as {
		client_id?: string;
		client_secret?: string;
	};
	printWarn(
		mode(cfg),
		"DCR client has no memberPubkey; POST /api/auth/oauth2/token will reject this client. Register with --signing-pubkey after auth sign-in to store the member key.",
	);
	return succeed(
		cfg,
		{
			clientId: payload.client_id,
			public: true,
			path: "dcr",
			client_secret: payload.client_secret,
		},
		payload.client_id ?? "registered",
	);
}

type Check = {
	id: string;
	ok: boolean;
	required: boolean;
	detail: string;
	skipped?: boolean;
};

export async function doctor(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const checks: Check[] = [];
	const add = (check: Check) => {
		checks.push(check);
		if (cfg.json) {
			return;
		}
		const mark = check.skipped ? "skip" : check.ok ? "ok" : "FAIL";
		printHuman(mode(cfg), `${mark}  ${check.id}  ${check.detail}`);
	};

	add({
		id: "env.base_url",
		ok: Boolean(cfg.baseUrl),
		required: true,
		detail: cfg.baseUrl,
	});
	try {
		ensureDir(cfg.home);
		add({ id: "env.home", ok: true, required: true, detail: cfg.home });
	} catch (error) {
		add({
			id: "env.home",
			ok: false,
			required: true,
			detail: error instanceof Error ? error.message : "home failed",
		});
	}

	let password: string | undefined;
	try {
		password = await resolvePassword(args, false);
		add({
			id: "env.password",
			ok: true,
			required: false,
			detail: password ? "present" : "unset",
			skipped: !password,
		});
	} catch (error) {
		add({
			id: "env.password",
			ok: false,
			required: false,
			detail: error instanceof Error ? error.message : "password failed",
		});
	}

	const backup = backupPath(args, cfg.home);
	if (pathExists(backup)) {
		add({
			id: "fs.backup",
			ok: true,
			required: false,
			detail: backup,
		});
	} else {
		add({
			id: "fs.backup",
			ok: true,
			required: false,
			detail: "missing",
			skipped: true,
		});
	}
	if (pathExists(cfg.cookieJar)) {
		add({
			id: "fs.cookie_jar",
			ok: true,
			required: false,
			detail: cfg.cookieJar,
		});
	} else {
		add({
			id: "fs.cookie_jar",
			ok: true,
			required: false,
			detail: "missing",
			skipped: true,
		});
	}

	const client = createHttp(cfg);
	try {
		const meta = await requestJson(
			client,
			"GET",
			"/.well-known/oauth-authorization-server",
		);
		const body = meta.json as {
			issuer?: string;
			token_endpoint?: string;
			authorization_endpoint?: string;
			registration_endpoint?: string;
			code_challenge_methods_supported?: string[];
		};
		const ok =
			meta.status === 200 &&
			Boolean(body.issuer) &&
			Boolean(body.token_endpoint) &&
			Boolean(body.authorization_endpoint) &&
			Boolean(body.registration_endpoint);
		add({
			id: "http.rfc8414",
			ok,
			required: true,
			detail: ok
				? `token_endpoint=${body.token_endpoint}`
				: `status ${meta.status}`,
		});
		add({
			id: "http.pkce",
			ok: Boolean(body.code_challenge_methods_supported?.includes("S256")),
			required: true,
			detail: (body.code_challenge_methods_supported ?? []).join(","),
		});
	} catch (error) {
		add({
			id: "http.rfc8414",
			ok: false,
			required: true,
			detail: error instanceof Error ? error.message : "rfc8414 failed",
		});
		add({
			id: "http.pkce",
			ok: false,
			required: true,
			detail: "skipped; rfc8414 failed",
			skipped: true,
		});
	}

	if (password && pathExists(backup)) {
		try {
			const ciphertext = readFileSync(backup, "utf8");
			const decrypted = await decryptMaster(ciphertext, password);
			const bap = bapFromBackup(decrypted);
			const ids = bap.listIds();
			add({
				id: "crypto.backup",
				ok: ids.length >= 1,
				required: true,
				detail: `${ids.length} identities`,
			});
			if (ids.length >= 1) {
				const member = memberWif(decrypted);
				const root = rootPubkey(decrypted);
				add({
					id: "crypto.member_key",
					ok: !root || root !== member.pubkey,
					required: true,
					detail: member.pubkey,
				});
			}
		} catch (error) {
			add({
				id: "crypto.backup",
				ok: false,
				required: true,
				detail: error instanceof Error ? error.message : "decrypt failed",
			});
		}
	}

	if (pathExists(cfg.cookieJar)) {
		const cookies = loadJar(cfg.cookieJar);
		const names = sessionCookieNames(cookies);
		const sessionNameOk = names.some(
			(name) =>
				name === "better-auth.session_token" ||
				name === "__Secure-better-auth.session_token",
		);
		add({
			id: "session.cookie",
			ok: sessionNameOk,
			required: false,
			detail: names.join(",") || "no cookies",
		});
		try {
			const session = await requestJson(
				client,
				"GET",
				"/api/auth/get-session",
				{
					withCookies: true,
				},
			);
			const body = session.json as { user?: { id?: string } } | null;
			add({
				id: "session.get",
				ok: session.status === 200 && Boolean(body?.user?.id),
				required: false,
				detail: body?.user?.id ?? `status ${session.status}`,
			});
		} catch (error) {
			add({
				id: "session.get",
				ok: false,
				required: false,
				detail: error instanceof Error ? error.message : "session failed",
			});
		}
	}

	const failed = checks.some(
		(check) => check.required && !check.ok && !check.skipped,
	);
	if (cfg.json) {
		printJson(!failed, { baseUrl: cfg.baseUrl, checks });
	}
	return failed ? 1 : 0;
}

export const HELP = `sigma — Sigma Auth CLI

Create a Bitcoin (BAP) identity key locally, sign in with Bitcoin-Auth, push
encrypted bitcoin-backup ciphertext, and register OAuth clients.

Commands:
  agent capabilities [--json]
  agent connect --name NAME --capability NAME [--capability NAME] [--json]
  agent status --agent-id ID [--json]
  agent execute --agent-id ID --capability NAME --args-file FILE [--json]
  agent disconnect --agent-id ID [--json]
  identity create    Create Type42 master + first BAP, encrypt, write .bep
  identity info      Decrypt local backup; print public fields
  backup encrypt     Encrypt a BapMasterBackup JSON file to .bep
  auth sign-in       Member-key Bitcoin-Auth sign-in; save cookies; register BAP
  backup push        POST ciphertext with session; never decrypt
  oauth register     Register an OAuth client (session path or DCR)
  doctor             Non-interactive health check
  diagnose bap       Public BAP profile (+ --pubkey registered-list check)
  diagnose identities  GET /api/user/bap-ids [--pubkey]
  diagnose last-oauth  Last selected BAP for --pubkey --client-id
  diagnose client    Public OAuth client metadata --client-id

Global flags:
  --base-url <url>   SIGMA_AUTH_URL (default https://auth.sigmaidentity.com)
  --home <dir>       SIGMA_HOME (default ~/.sigma)
  --cookie-jar <path>
  --json             Machine output
  --quiet
  -h, --help

Password: --password-file, --password-stdin, or SIGMA_BACKUP_PASSWORD.
--password on argv is rejected.

This CLI never sends private keys to the server. Identity is a BAP key, not an API key.
`;
