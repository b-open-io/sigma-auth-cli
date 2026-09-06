import { afterEach, describe, expect, mock, spyOn, test } from "bun:test";
import {
	existsSync,
	mkdtempSync,
	readFileSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { HD, Mnemonic, PrivateKey } from "@bsv/sdk";
import { decryptBackup, isType42Backup } from "bitcoin-backup";
import {
	bapFromBackup,
	createMasterBackup,
	decryptMaster,
	memberWif,
	publicFields,
} from "../src/identity.ts";
import { run } from "../src/index.ts";

const PASSWORD = "correct-horse";

function tmp(): string {
	return mkdtempSync(join(tmpdir(), "sigma-cli-"));
}

async function capture(
	argv: string[],
	env: Record<string, string | undefined> = {},
) {
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
		expect(stdout.toLowerCase()).not.toContain("mnemonic");
		expect(stdout.toLowerCase()).not.toContain("hd wallet");
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
				{ SIGMA_BACKUP_PASSWORD: PASSWORD },
			);
			expect(code).toBe(0);
			expect(fetchMock).not.toHaveBeenCalled();
			const mode = statSync(out).mode & 0o777;
			expect(mode).toBe(0o600);
			const decrypted = (await decryptBackup(
				readFileSync(out, "utf8"),
				PASSWORD,
			)) as {
				rootPk: string;
				ids: string;
				label: string;
			};
			expect(decrypted.label).toBe("agent");
			expect(isType42Backup(decrypted)).toBe(true);
			expect(decrypted.rootPk).toMatch(/^[5KL]/);
			expect("xprv" in decrypted).toBe(false);
			expect("mnemonic" in decrypted).toBe(false);
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		expect(code).toBe(1);
		expect(readFileSync(out, "utf8")).toBe("keep-me");
	});

	test("create mints Type42 rootPk without HD or Mnemonic", async () => {
		const mnemonicSpy = spyOn(Mnemonic, "fromRandom");
		const seedSpy = spyOn(HD, "fromSeed");
		const deriveSpy = spyOn(HD.prototype, "derive");
		const pkSpy = spyOn(PrivateKey, "fromRandom");
		try {
			const created = createMasterBackup("agent");
			expect(mnemonicSpy).not.toHaveBeenCalled();
			expect(seedSpy).not.toHaveBeenCalled();
			expect(deriveSpy).not.toHaveBeenCalled();
			expect(pkSpy).toHaveBeenCalled();
			expect("mnemonic" in created).toBe(false);
			expect(isType42Backup(created.backup)).toBe(true);
			if (!isType42Backup(created.backup)) {
				throw new Error("expected Type42 backup");
			}
			expect(created.backup.rootPk).toMatch(/^[5KL]/);
			expect("xprv" in created.backup).toBe(false);
		} finally {
			mnemonicSpy.mockRestore();
			seedSpy.mockRestore();
			deriveSpy.mockRestore();
			pkSpy.mockRestore();
		}
	});

	test("create path source has no HD hop or mnemonic flags", async () => {
		const identity = await Bun.file(
			new URL("../src/identity.ts", import.meta.url),
		).text();
		const commands = await Bun.file(
			new URL("../src/commands.ts", import.meta.url),
		).text();
		const args = await Bun.file(
			new URL("../src/args.ts", import.meta.url),
		).text();
		expect(identity).not.toContain("Mnemonic.fromRandom");
		expect(identity).not.toContain("HD.fromSeed");
		expect(identity).not.toContain("fromSeed");
		expect(identity).not.toContain("m/0'/0");
		expect(identity).toContain("PrivateKey.fromRandom().toWif()");
		expect(commands).not.toContain("show-mnemonic");
		expect(commands).not.toContain("mnemonic-file");
		expect(args).not.toContain("show-mnemonic");
		expect(args).not.toContain("mnemonic-file");
	});

	test("pre-change Type42 fixture still decrypts the same bapId", async () => {
		const dir = import.meta.dir;
		const meta = JSON.parse(
			readFileSync(join(dir, "fixtures/type42-pre-change.json"), "utf8"),
		) as {
			password: string;
			label: string;
			bapId: string;
			pubkey: string;
			address: string;
		};
		const ciphertext = readFileSync(
			join(dir, "fixtures/type42-pre-change.bep"),
			"utf8",
		);
		const decrypted = await decryptMaster(ciphertext, meta.password);
		expect(isType42Backup(decrypted)).toBe(true);
		expect("xprv" in decrypted).toBe(false);
		expect("wif" in decrypted).toBe(false);
		const fields = publicFields(decrypted);
		expect(fields.bapId).toBe(meta.bapId);
		expect(fields.pubkey).toBe(meta.pubkey);
		expect(fields.address).toBe(meta.address);
		expect(fields.label).toBe(meta.label);
		expect(bapFromBackup(decrypted).listIds()).toEqual([meta.bapId]);
	});

	test("--force replaces an existing .bep and does not append", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		const first = await capture(
			[
				"identity",
				"create",
				"--label",
				"first",
				"--out",
				out,
				"--json",
				"--home",
				dir,
			],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		expect(first.code).toBe(0);
		const before = readFileSync(out);
		const second = await capture(
			[
				"identity",
				"create",
				"--label",
				"second",
				"--out",
				out,
				"--json",
				"--home",
				dir,
				"--force",
			],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		expect(second.code).toBe(0);
		const after = readFileSync(out);
		expect(after.equals(before)).toBe(false);
		expect(after.toString("utf8").startsWith(before.toString("utf8"))).toBe(
			false,
		);
		const decrypted = (await decryptBackup(
			after.toString("utf8"),
			PASSWORD,
		)) as {
			label: string;
		};
		expect(decrypted.label).toBe("second");
	});
});

describe("password and env", () => {
	test("AT-007 two password sources fail", async () => {
		const dir = tmp();
		const pwfile = join(dir, "pw");
		writeFileSync(pwfile, PASSWORD);
		const { code } = await capture(
			[
				"identity",
				"info",
				"--backup",
				join(dir, "missing.bep"),
				"--password-file",
				pwfile,
			],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
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

	test("whitespace-only SIGMA_BACKUP_PASSWORD fails closed", async () => {
		const dir = tmp();
		const { code, stderr } = await capture(
			[
				"identity",
				"create",
				"--label",
				"agent",
				"--home",
				dir,
				"--out",
				join(dir, "id.bep"),
			],
			{ SIGMA_BACKUP_PASSWORD: "        " },
		);
		expect(code).toBe(1);
		expect(stderr).toContain("whitespace-only");
		expect(existsSync(join(dir, "id.bep"))).toBe(false);
	});
});

describe("identity info and encrypt", () => {
	test("AT-009 info is public-only", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const { code, stdout } = await capture(
			["identity", "info", "--backup", out, "--json", "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const decrypted = await decryptBackup(readFileSync(out, "utf8"), PASSWORD);
		const jsonPath = join(dir, "plain.json");
		const bep2 = join(dir, "round.bep");
		writeFileSync(jsonPath, JSON.stringify(decrypted));
		const { code } = await capture(
			["backup", "encrypt", "--in", jsonPath, "--out", bep2, "--home", dir],
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const calls: Array<{ url: string; init?: RequestInit }> = [];
		const original = globalThis.fetch;
		globalThis.fetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: RequestInit,
		) => {
			const url = String(input);
			calls.push({ url, init });
			if (url.endsWith("/api/auth/sign-in/sigma")) {
				return new Response(
					JSON.stringify({
						token: "sess",
						user: { id: "user-1", pubkey: "02ab" },
					}),
					{
						status: 200,
						headers: {
							"set-cookie": "better-auth.session_token=abc; Path=/; HttpOnly",
						},
					},
				);
			}
			if (url.endsWith("/api/user/bap-ids")) {
				return new Response(JSON.stringify({ success: true }), { status: 200 });
			}
			return new Response("nope", { status: 404 });
		}) as unknown as typeof fetch;
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
				{ SIGMA_BACKUP_PASSWORD: PASSWORD, SIGMA_AUTH_URL: undefined },
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		expect(code).toBe(7);
		expect(stderr).toContain("plaintext");
	});

	test("backup push refuses WIF and raw text", async () => {
		const dir = tmp();
		const fetchMock = mock(() => {
			throw new Error("network should not be used");
		});
		const original = globalThis.fetch;
		globalThis.fetch = fetchMock as unknown as typeof fetch;
		try {
			const wifPath = join(dir, "key.wif");
			writeFileSync(
				wifPath,
				"L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6",
			);
			const wifResult = await capture([
				"backup",
				"push",
				"--backup",
				wifPath,
				"--home",
				dir,
			]);
			expect(wifResult.code).toBe(7);
			expect(wifResult.stderr.toLowerCase()).toContain("wif");
			expect(fetchMock).not.toHaveBeenCalled();

			const rawPath = join(dir, "raw.txt");
			writeFileSync(rawPath, "this is not bitcoin-backup ciphertext");
			const rawResult = await capture([
				"backup",
				"push",
				"--backup",
				rawPath,
				"--home",
				dir,
			]);
			expect(rawResult.code).toBe(7);
			expect(rawResult.stderr).toContain("ciphertext");
			expect(fetchMock).not.toHaveBeenCalled();
		} finally {
			globalThis.fetch = original;
		}
	});

	test("AT-013 backup push posts opaque ciphertext", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const ciphertext = readFileSync(out, "utf8").replace(/\n+$/, "");
		const calls: Array<{ url: string; init?: RequestInit }> = [];
		const original = globalThis.fetch;
		globalThis.fetch = (async (
			input: Parameters<typeof fetch>[0],
			init?: RequestInit,
		) => {
			const url = String(input);
			calls.push({ url, init });
			return new Response(
				JSON.stringify({
					bapId: "bap-1",
					message: "Backup stored successfully",
				}),
				{ status: 200 },
			);
		}) as unknown as typeof fetch;
		try {
			const { code, stdout } = await capture(
				["backup", "push", "--backup", out, "--json", "--home", dir],
				{ SIGMA_BACKUP_PASSWORD: PASSWORD },
			);
			expect(code).toBe(0);
			expect(calls).toHaveLength(1);
			expect(calls[0]?.url).toContain("/api/backup");
			expect(calls[0]?.init?.body).toBe(
				JSON.stringify({ encryptedBackup: ciphertext }),
			);
			expect(JSON.parse(stdout).data.bapId).toBe("bap-1");
		} finally {
			globalThis.fetch = original;
		}
	});

	test("password-stdin compose with --signin does not reread stdin", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		const jar = join(dir, "cookies.txt");
		let reads = 0;
		const spy = spyOn(Bun.stdin, "text").mockImplementation(async () => {
			reads += 1;
			if (reads > 1) {
				return "";
			}
			return `${PASSWORD}\n`;
		});
		const original = globalThis.fetch;
		globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
			const url = String(input);
			if (url.endsWith("/api/auth/sign-in/sigma")) {
				return new Response(
					JSON.stringify({
						token: "sess",
						user: { id: "user-1", pubkey: "02ab" },
					}),
					{
						status: 200,
						headers: {
							"set-cookie": "better-auth.session_token=abc; Path=/; HttpOnly",
						},
					},
				);
			}
			if (url.endsWith("/api/user/bap-ids")) {
				return new Response(JSON.stringify({ success: true }), { status: 200 });
			}
			return new Response("nope", { status: 404 });
		}) as unknown as typeof fetch;
		try {
			const { code } = await capture(
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
					"--password-stdin",
					"--signin",
					"--cookie-jar",
					jar,
					"--base-url",
					"https://auth.sigmaidentity.com",
				],
				{ SIGMA_BACKUP_PASSWORD: undefined },
			);
			expect(code).toBe(0);
			expect(reads).toBe(1);
		} finally {
			spy.mockRestore();
			globalThis.fetch = original;
		}
	});

	test("bap-ids failure signs out and deletes the cookie jar", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		const jar = join(dir, "cookies.txt");
		await capture(
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const calls: string[] = [];
		const original = globalThis.fetch;
		globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
			const url = String(input);
			calls.push(url);
			if (url.endsWith("/api/auth/sign-in/sigma")) {
				return new Response(
					JSON.stringify({ token: "sess", user: { id: "user-1" } }),
					{
						status: 200,
						headers: {
							"set-cookie": "better-auth.session_token=abc; Path=/; HttpOnly",
						},
					},
				);
			}
			if (url.endsWith("/api/user/bap-ids")) {
				return new Response(JSON.stringify({ error: "mapping failed" }), {
					status: 500,
				});
			}
			if (url.endsWith("/api/auth/sign-out")) {
				return new Response(JSON.stringify({ success: true }), { status: 200 });
			}
			return new Response("nope", { status: 404 });
		}) as unknown as typeof fetch;
		try {
			const { code } = await capture(
				[
					"auth",
					"sign-in",
					"--backup",
					out,
					"--home",
					dir,
					"--cookie-jar",
					jar,
					"--base-url",
					"https://auth.sigmaidentity.com",
				],
				{ SIGMA_BACKUP_PASSWORD: PASSWORD },
			);
			expect(code).toBe(6);
			expect(calls.some((url) => url.endsWith("/api/auth/sign-out"))).toBe(
				true,
			);
			expect(existsSync(jar)).toBe(false);
		} finally {
			globalThis.fetch = original;
		}
	});

	test("AT-023 Retry-After is included in the error", async () => {
		const dir = tmp();
		const out = join(dir, "id.bep");
		await capture(
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
			{ SIGMA_BACKUP_PASSWORD: PASSWORD },
		);
		const original = globalThis.fetch;
		globalThis.fetch = (async () => {
			return new Response(JSON.stringify({ error: "rate limited" }), {
				status: 429,
				headers: { "Retry-After": "10" },
			});
		}) as unknown as typeof fetch;
		try {
			const { code, stderr } = await capture([
				"backup",
				"push",
				"--backup",
				out,
				"--home",
				dir,
			]);
			expect(code).toBe(5);
			expect(stderr).toContain("Retry-After: 10");
		} finally {
			globalThis.fetch = original;
		}
	});
});

describe("diagnose", () => {
	test("help lists diagnose commands", async () => {
		const { code, stdout } = await capture(["--help"]);
		expect(code).toBe(0);
		expect(stdout).toContain("diagnose bap");
		expect(stdout).toContain("diagnose identities");
		expect(stdout).toContain("diagnose last-oauth");
		expect(stdout).toContain("diagnose client");
	});

	test("diagnose bap treats profile 404 as found:false", async () => {
		const original = globalThis.fetch;
		const calls: string[] = [];
		globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
			calls.push(String(input));
			return new Response(JSON.stringify({ error: "Profile not found" }), {
				status: 404,
			});
		}) as unknown as typeof fetch;
		try {
			const { code, stdout } = await capture([
				"diagnose",
				"bap",
				"--bap-id",
				"3QpdyNb9HScYmWEyfqtRQbKzwyf",
				"--json",
			]);
			expect(code).toBe(0);
			const parsed = JSON.parse(stdout) as {
				ok: boolean;
				data: { found: boolean; bapId: string; hint: string };
			};
			expect(parsed.ok).toBe(true);
			expect(parsed.data.found).toBe(false);
			expect(parsed.data.bapId).toBe("3QpdyNb9HScYmWEyfqtRQbKzwyf");
			expect(parsed.data.hint).toContain("no published");
			expect(calls[0]).toContain(
				"/api/bap/profile?bapId=3QpdyNb9HScYmWEyfqtRQbKzwyf",
			);
		} finally {
			globalThis.fetch = original;
		}
	});

	test("diagnose bap --pubkey reports leftover HD identity", async () => {
		const original = globalThis.fetch;
		globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
			const url = String(input);
			if (url.includes("/api/bap/profile")) {
				return new Response(JSON.stringify({ error: "Profile not found" }), {
					status: 404,
				});
			}
			if (url.includes("/api/user/bap-ids")) {
				return new Response(
					JSON.stringify({
						bapIds: [
							{
								id: "33mGVYzkGE9XMbu346XkUaMHyzwV",
								identity_key: "33mGVYzkGE9XMbu346XkUaMHyzwV",
								name: "Minerva",
							},
						],
					}),
					{ status: 200 },
				);
			}
			return new Response("unexpected", { status: 500 });
		}) as unknown as typeof fetch;
		try {
			const { code, stdout } = await capture([
				"diagnose",
				"bap",
				"--bap-id",
				"3QpdyNb9HScYmWEyfqtRQbKzwyf",
				"--pubkey",
				"03aaaa",
				"--json",
			]);
			expect(code).toBe(0);
			const parsed = JSON.parse(stdout) as {
				data: { found: boolean; registeredToPubkey: boolean; hint: string };
			};
			expect(parsed.data.found).toBe(false);
			expect(parsed.data.registeredToPubkey).toBe(false);
			expect(parsed.data.hint).toContain("leftover HD");
		} finally {
			globalThis.fetch = original;
		}
	});

	test("diagnose last-oauth requires both flags", async () => {
		const { code, stderr } = await capture([
			"diagnose",
			"last-oauth",
			"--pubkey",
			"03aaaa",
		]);
		expect(code).toBe(1);
		expect(stderr).toContain("--pubkey and --client-id are required");
	});
});

describe("doctor JSON", () => {
	test("failure prints ok:false with data.checks", async () => {
		const dir = tmp();
		const original = globalThis.fetch;
		globalThis.fetch = (async () => {
			throw new Error("offline");
		}) as unknown as typeof fetch;
		try {
			const { code, stdout } = await capture([
				"doctor",
				"--json",
				"--home",
				dir,
				"--base-url",
				"https://example.invalid",
			]);
			expect(code).toBe(1);
			const parsed = JSON.parse(stdout) as {
				ok: boolean;
				data?: { checks?: unknown[] };
				error?: unknown;
			};
			expect(parsed.ok).toBe(false);
			expect(parsed.data?.checks).toBeArray();
			expect((parsed.data?.checks?.length ?? 0) > 0).toBe(true);
			expect(parsed.error).toBeUndefined();
		} finally {
			globalThis.fetch = original;
		}
	});
});

afterEach(() => {
	delete process.env.SIGMA_BACKUP_PASSWORD;
});
