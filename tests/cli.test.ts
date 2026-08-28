import { afterEach, describe, expect, mock, test } from "bun:test";
import { mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decryptBackup } from "bitcoin-backup";
import { PrivateKey } from "@bsv/sdk";
import { run } from "../src/index.ts";
import { bapFromBackup, memberWif } from "../src/identity.ts";

const PASSWORD = "correct-horse";

function tmp(): string {
	return mkdtempSync(join(tmpdir(), "sigma-cli-"));
}

async function capture(argv: string[], env: Record<string, string | undefined> = {}) {
	const prev: Record<string, string | undefined> = {};
	for (const [key, value] of Object.entries(env)) {
		prev[key] = process.env[key];
		if (value === undefined) {
			delete process.env[key];
		} else {
			process.env[key] = value;
		}
	}
	const stdout: string[] = [];
	const stderr: string[] = [];
	const origOut = process.stdout.write.bind(process.stdout);
	const origErr = process.stderr.write.bind(process.stderr);
	process.stdout.write = ((chunk: string | Uint8Array) => {
		stdout.push(String(chunk));
		return true;
	}) as typeof process.stdout.write;
	process.stderr.write = ((chunk: string | Uint8Array) => {
		stderr.push(String(chunk));
		return true;
	}) as typeof process.stderr.write;
	try {
		const code = await run(argv);
		return { code, stdout: stdout.join(""), stderr: stderr.join("") };
	} finally {
		process.stdout.write = origOut;
		process.stderr.write = origErr;
		for (const [key, value] of Object.entries(prev)) {
			if (value === undefined) {
				delete process.env[key];
			} else {
				process.env[key] = value;
			}
		}
	}
}

describe("help and package", () => {
	test("AT-001 sigma --help lists v1 commands and forbids mint/clawnet/api key identity", async () => {
		const { code, stdout } = await capture(["--help"]);
		expect(code).toBe(0);
		expect(stdout).toContain("identity create");
		expect(stdout).toContain("auth sign-in");
		expect(stdout).toContain("oauth register");
		expect(stdout).toContain("doctor");
		expect(stdout.toLowerCase()).not.toContain("mint");
		expect(stdout.toLowerCase()).not.toContain("clawnet");
		expect(stdout.toLowerCase()).toContain("not an api key");
	});

	test("rejects --password on argv", async () => {
		const { code, stderr } = await capture([
			"identity",
			"create",
			"--label",
			"x",
			"--password",
			"nope",
		]);
		expect(code).toBe(1);
		expect(stderr).toContain("--password is not allowed");
	});
});

describe("identity create", () => {
	test("AT-003 create is local and writes a 0600 Type42 backup", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		const fetchMock = mock(() => {
			throw new Error("network should not be used");
		});
		const original = globalThis.fetch;
		globalThis.fetch = fetchMock as unknown as typeof fetch;
		try {
			const { code, stdout } = await capture(
				[
					"identity",
					"create",
					"--label",
					"agent",
					"--out",
					out,
					"--json",
					"--home",
					dir,
				],
				{ SIGMA_BACKUP_PASSWORD: PASSWORD }
			);
			expect(code).toBe(0);
			expect(fetchMock).not.toHaveBeenCalled();
			const mode = statSync(out).mode & 0o777;
			expect(mode).toBe(0o600);
			const decrypted = (await decryptBackup(
				readFileSync(out, "utf8"),
				PASSWORD
			)) as {
				rootPk: string;
				ids: string;
				label: string;
			};
			expect(decrypted.label).toBe("agent");
			expect(decrypted.rootPk).toMatch(/^[5KL]/);
			expect(bapFromBackup(decrypted).listIds().length).toBe(1);
			const data = JSON.parse(stdout) as {
				data: { bapId: string; pubkey: string };
			};
			expect(data.data.bapId.length).toBeGreaterThan(10);
			const member = memberWif(decrypted);
			const rootPub = PrivateKey.fromWif(decrypted.rootPk)
				.toPublicKey()
				.toString();
			expect(member.pubkey).not.toBe(rootPub);
			expect(member.pubkey).toBe(data.data.pubkey);
		} finally {
			globalThis.fetch = original;
		}
	});

	test("AT-005 refuses overwrite without --force", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		writeFileSync(out, "keep-me");
		const { code } = await capture(
			["identity", "create", "--label", "agent", "--out", out, "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(1);
		expect(readFileSync(out, "utf8")).toBe("keep-me");
	});

	test("AT-006 mnemonic is opt-in on stderr only", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		const { code, stdout, stderr } = await capture(
			[
				"identity",
				"create",
				"--label",
				"agent",
				"--out",
				out,
				"--json",
				"--show-mnemonic",
				"--home",
				dir,
			],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(0);
		expect(JSON.parse(stdout).data.mnemonic).toBeUndefined();
		expect(stderr.trim().split(" ").length).toBeGreaterThanOrEqual(12);
	});
});

describe("password and env", () => {
	test("AT-007 two password sources fail", async () => {
		const dir = tmp();
		const pwfile = join(dir, "pw");
		writeFileSync(pwfile, PASSWORD);
		const { code } = await capture(
			["identity", "info", "--backup", join(dir, "missing.bep"), "--password-file", pwfile],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(1);
	});

	test("AT-008 empty SIGMA_AUTH_URL fails closed", async () => {
		const { code, stderr } = await capture(["doctor"], {
			SIGMA_AUTH_URL: "",
		});
		expect(code).toBe(1);
		expect(stderr).toContain("SIGMA_AUTH_URL is set but empty");
	});
});

describe("identity info and encrypt", () => {
	test("AT-009 info is public-only", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
			["identity", "create", "--label", "agent", "--out", out, "--json", "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		const { code, stdout } = await capture(
			["identity", "info", "--backup", out, "--json", "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(0);
		const data = JSON.parse(stdout).data as Record<string, unknown>;
		expect(data.bapId).toBeDefined();
		expect(data.pubkey).toBeDefined();
		expect(data.ids).toBeArray();
		expect(JSON.stringify(data)).not.toContain("rootPk");
		expect(JSON.stringify(data)).not.toContain("wif");
	});

	test("AT-010 backup encrypt round-trip", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
			["identity", "create", "--label", "agent", "--out", out, "--json", "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		const decrypted = await decryptBackup(readFileSync(out, "utf8"), PASSWORD);
		const jsonPath = join(dir, "plain.json");
		const bep2 = join(dir, "round.bep");
		writeFileSync(jsonPath, JSON.stringify(decrypted));
		const { code } = await capture(
			["backup", "encrypt", "--in", jsonPath, "--out", bep2, "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(0);
		const again = await decryptBackup(readFileSync(bep2, "utf8"), PASSWORD);
		expect(again).toEqual(decrypted);
	});
});

describe("auth sign-in HTTP", () => {
	test("AT-011 posts Bitcoin-Auth to sign-in then registers bap-ids", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
			["identity", "create", "--label", "agent", "--out", out, "--json", "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		const calls: Array<{ url: string; init?: RequestInit }> = [];
		const original = globalThis.fetch;
		globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			calls.push({ url, init });
			if (url.endsWith("/api/auth/sign-in/sigma")) {
				return new Response(
					JSON.stringify({ token: "sess", user: { id: "user-1", pubkey: "02ab" } }),
					{
						status: 200,
						headers: {
							"set-cookie":
								"better-auth.session_token=abc; Path=/; HttpOnly",
						},
					}
				);
			}
			if (url.endsWith("/api/user/bap-ids")) {
				return new Response(JSON.stringify({ success: true }), { status: 200 });
			}
			return new Response("nope", { status: 404 });
		}) as typeof fetch;
		try {
			const { code, stdout } = await capture(
				[
					"auth",
					"sign-in",
					"--backup",
					out,
					"--json",
					"--home",
					dir,
					"--cookie-jar",
					join(dir, "cookies.txt"),
					"--base-url",
					"https://auth.sigmaidentity.com",
				],
				{ SIGMA_BACKUP_PASSWORD: PASSWORD, SIGMA_AUTH_URL: undefined }
			);
			expect(code).toBe(0);
			expect(calls[0]?.url).toContain("/api/auth/sign-in/sigma");
			const headers = new Headers(calls[0]?.init?.headers);
			expect(headers.get("x-auth-token")).toBeTruthy();
			expect(calls[0]?.init?.body).toContain("bapId");
			expect(calls[1]?.url).toContain("/api/user/bap-ids");
			const body = JSON.parse(String(calls[1]?.init?.body)) as {
				isPrimary: boolean;
				accountPubkey: string;
			};
			expect(body.isPrimary).toBe(true);
			expect(body.accountPubkey.length).toBeGreaterThan(10);
			expect(JSON.parse(stdout).data.userId).toBe("user-1");
		} finally {
			globalThis.fetch = original;
		}
	});

	test("AT-014 backup push refuses plaintext", async () => {
		const dir = tmp();
		const plain = join(dir, "plain.json");
		writeFileSync(plain, JSON.stringify({ rootPk: "L1fake" }));
		const { code, stderr } = await capture(
			["backup", "push", "--backup", plain, "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD }
		);
		expect(code).toBe(7);
		expect(stderr).toContain("plaintext");
	});
});

afterEach(() => {
	delete process.env.SIGMA_BACKUP_PASSWORD;
});
