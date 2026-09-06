import { afterEach, expect, spyOn, test } from "bun:test";
import { createPublicKey, verify } from "node:crypto";
import { mkdtempSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentCommand, agentUrl, validateAgentProvider } from "../src/agent.ts";
import { agentStore } from "../src/agent-store.ts";
import { parseArgs } from "../src/args.ts";
import { loadConfig } from "../src/config.ts";

const origin = "http://localhost:19119";
const issuer = `${origin}/api/auth`;
const config = {
	version: "1",
	provider_name: "Mock",
	description: "Mock provider",
	issuer,
	algorithms: ["EdDSA"],
	modes: ["delegated" as const],
	approval_methods: ["device_authorization"],
	endpoints: {
		register: "/agent/register",
		status: "/agent/status",
		revoke: "/agent/revoke",
		capabilities: "/capability/list",
		execute: "/capability/execute",
	},
	capabilities: [{ name: "profile.read", description: "Read profile" }],
};
const restores: (() => void)[] = [];
afterEach(() => {
	for (const restore of restores.splice(0)) restore();
});

function fixture() {
	const home = mkdtempSync(join(tmpdir(), "sigma-agent-test-"));
	let now = 2_000_000_000_000;
	const clock = spyOn(Date, "now").mockImplementation(() => now);
	restores.push(() => clock.mockRestore());
	const requests: { url: string; init?: RequestInit }[] = [];
	let status = "pending";
	let throttle = false;
	let offline = false;
	let revokeOk = true;
	let discovery = config;
	let publicKey: Record<string, unknown> | undefined;
	const fetchMock = spyOn(globalThis, "fetch").mockImplementation((async (
		input: string | URL | Request,
		init?: RequestInit,
	) => {
		const url = String(input);
		requests.push({ url, init });
		expect(init?.redirect).toBe("error");
		expect(init?.credentials).toBe("omit");
		expect(new Headers(init?.headers).has("cookie")).toBe(false);
		if (url.endsWith("agent-configuration")) return Response.json(discovery);
		if (url.endsWith("/agent/register")) {
			const body = JSON.parse(String(init?.body));
			expect(body.mode).toBe("delegated");
			expect(body.capabilities).toEqual(["profile.read"]);
			const token = new Headers(init?.headers).get("authorization")!.slice(7);
			const claims = JSON.parse(
				Buffer.from(token.split(".")[1]!, "base64url").toString(),
			);
			publicKey = claims.agent_public_key;
			return Response.json({
				agent_id: "agent/one",
				host_id: "host",
				mode: "delegated",
				status: "pending",
				agent_capability_grants: [
					{ capability: "profile.read", status: "pending" },
				],
				approval: {
					method: "device_authorization",
					verification_uri: `${origin}/agent/approve?claim_token=secret-claim`,
					verification_uri_complete: `${origin}/agent/approve?bearer=secret-complete`,
					user_code: "PUBLIC-CODE",
					expires_in: 600,
					interval: 5,
				},
			});
		}
		if (url.includes("/agent/status?")) {
			if (offline) throw new Error("mock network failure");
			if (throttle)
				return Response.json(
					{ error: "slow_down" },
					{ status: 429, headers: { "retry-after": "30" } },
				);
			return Response.json({
				agent_id: "agent/one",
				status,
				mode: "delegated",
				agent_capability_grants: [
					{
						capability: "profile.read",
						status: status === "active" ? "active" : "pending",
					},
				],
			});
		}
		if (url.endsWith("/capability/execute")) {
			const token = new Headers(init?.headers).get("authorization")!.slice(7);
			const parts = token.split(".");
			const claims = JSON.parse(Buffer.from(parts[1]!, "base64url").toString());
			expect(claims.aud).toBe(`${issuer}/capability/execute`);
			expect(claims.capabilities).toEqual(["profile.read"]);
			expect(
				verify(
					null,
					Buffer.from(`${parts[0]}.${parts[1]}`),
					createPublicKey({ key: publicKey!, format: "jwk" }),
					Buffer.from(parts[2]!, "base64url"),
				),
			).toBe(true);
			return Response.json({
				data: {
					name: "Example",
					authorization: `Bearer ${token}`,
					token,
					privateKey: { d: "private-secret" },
				},
			});
		}
		if (url.endsWith("/agent/revoke"))
			return Response.json({}, { status: revokeOk ? 200 : 500 });
		if (url.endsWith("/capability/list"))
			return Response.json({
				capabilities: config.capabilities,
				has_more: false,
			});
		throw new Error("Unexpected mock URL");
	}) as typeof fetch);
	restores.push(() => fetchMock.mockRestore());
	async function run(...argv: string[]) {
		const output: string[] = [];
		const spy = spyOn(process.stdout, "write").mockImplementation((chunk) => {
			output.push(String(chunk));
			return true;
		});
		try {
			const args = parseArgs([
				"agent",
				...argv,
				"--json",
				"--home",
				home,
				"--base-url",
				origin,
			]);
			await agentCommand(args, loadConfig(args));
			return JSON.parse(output.join("")).data;
		} finally {
			spy.mockRestore();
		}
	}
	return {
		home,
		requests,
		run,
		advance: (ms = 5001) => {
			now += ms;
		},
		status: (value: string) => {
			status = value;
		},
		offline: (value: boolean) => {
			offline = value;
		},
		throttle: (value: boolean) => {
			throttle = value;
		},
		revoke: (value: boolean) => {
			revokeOk = value;
		},
		discovery: (value: typeof config) => {
			discovery = value;
		},
	};
}

test("pending connect persists privately, restart resumes once, execute is scoped and signed, revoke confirmed", async () => {
	const f = fixture();
	const pending = await f.run(
		"connect",
		"--name",
		"Test",
		"--capability",
		"profile.read",
	);
	expect(pending.status).toBe("pending");
	expect(pending.userCode).toBe("PUBLIC-CODE");
	expect(pending.verificationUri).toBe(`${origin}/agent/approve`);
	expect(JSON.stringify(pending)).not.toContain("secret");
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		0,
	);
	expect(statSync(join(f.home, "agent-auth")).mode & 0o777).toBe(0o700);
	for (const file of readdirSync(join(f.home, "agent-auth"))) {
		expect(file).toMatch(/^[a-f0-9]{64}\.json$/);
		expect(statSync(join(f.home, "agent-auth", file)).mode & 0o777).toBe(0o600);
	}
	await f.run("status", "--agent-id", pending.agentId);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		0,
	);
	f.status("active");
	f.advance();
	expect((await f.run("status", "--agent-id", pending.agentId)).status).toBe(
		"active",
	);
	expect(
		f.requests.filter((r) => r.url.endsWith("/agent/register")).length,
	).toBe(1);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		1,
	);
	const args = join(f.home, "args.json");
	writeFileSync(args, "{}");
	const result = await f.run(
		"execute",
		"--agent-id",
		pending.agentId,
		"--capability",
		"profile.read",
		"--args-file",
		args,
	);
	expect(result).toEqual({ data: { name: "Example" } });
	await expect(
		f.run(
			"execute",
			"--agent-id",
			pending.agentId,
			"--capability",
			"write",
			"--args-file",
			args,
		),
	).rejects.toThrow("not an active requested grant");
	f.revoke(false);
	await expect(
		f.run("disconnect", "--agent-id", pending.agentId),
	).rejects.toThrow("retained");
	expect(
		await agentStore(f.home).storage.getAgentConnection(pending.agentId),
	).not.toBeNull();
	f.revoke(true);
	expect(
		(await f.run("disconnect", "--agent-id", pending.agentId)).status,
	).toBe("revoked");
	expect(
		await agentStore(f.home).storage.getAgentConnection(pending.agentId),
	).toBeNull();
});

for (const status of ["denied", "rejected", "revoked", "expired"]) {
	test(`resumed status records terminal ${status}`, async () => {
		const f = fixture();
		const connection = await f.run(
			"connect",
			"--name",
			"Test",
			"--capability",
			"profile.read",
		);
		f.status(status);
		f.advance();
		expect(
			(await f.run("status", "--agent-id", connection.agentId)).status,
		).toBe(status);
		f.advance();
		await f.run("status", "--agent-id", connection.agentId);
		expect(
			f.requests.filter((r) => r.url.includes("/agent/status")).length,
		).toBe(1);
	});
}

test("429 Retry-After survives restart and server expiration is authoritative", async () => {
	const f = fixture();
	const connection = await f.run(
		"connect",
		"--name",
		"Test",
		"--capability",
		"profile.read",
	);
	f.throttle(true);
	f.advance();
	const pending = await f.run("status", "--agent-id", connection.agentId);
	expect(pending.nextPollAt - Date.now()).toBeGreaterThanOrEqual(30000);
	f.advance();
	await f.run("status", "--agent-id", connection.agentId);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		1,
	);
	f.advance(600000);
	f.throttle(false);
	f.status("expired");
	expect((await f.run("status", "--agent-id", connection.agentId)).status).toBe(
		"expired",
	);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		2,
	);
});

test("late resume observes approval completed before the local deadline", async () => {
	const f = fixture();
	const connection = await f.run(
		"connect",
		"--name",
		"Test",
		"--capability",
		"profile.read",
	);
	f.status("active");
	f.advance(600001);
	expect((await f.run("status", "--agent-id", connection.agentId)).status).toBe(
		"active",
	);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		1,
	);
	expect(
		f.requests.filter((r) => r.url.endsWith("/agent/register")).length,
	).toBe(1);
});

test("provider origin and credential boundaries reject unsafe discovery before registration", async () => {
	const f = fixture();
	f.discovery({
		...config,
		endpoints: {
			...config.endpoints,
			register: "https://evil.example/register",
		},
	});
	await expect(
		f.run("connect", "--name", "Test", "--capability", "profile.read"),
	).rejects.toThrow();
	expect(f.requests.some((r) => r.url.includes("/agent/register"))).toBe(false);
	expect(() => agentUrl("http://example.com")).toThrow();
	expect(() => agentUrl("https://user:password@example.com")).toThrow();
	expect(() =>
		validateAgentProvider(
			{ ...config, default_location: "https://evil.example/execute" },
			origin,
		),
	).toThrow();
	expect(() => validateAgentProvider(config, origin)).not.toThrow();
});

test("late resume preserves pending and retry timing after network failure", async () => {
	const f = fixture();
	const connection = await f.run(
		"connect",
		"--name",
		"Test",
		"--capability",
		"profile.read",
	);
	f.status("active");
	f.advance(600001);
	f.offline(true);
	await expect(
		f.run("status", "--agent-id", connection.agentId),
	).rejects.toThrow("Agent request failed");
	const pending = await f.run("status", "--agent-id", connection.agentId);
	expect(pending.status).toBe("pending");
	expect(pending.nextPollAt).toBeGreaterThan(Date.now());
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		1,
	);
	f.offline(false);
	f.advance();
	expect((await f.run("status", "--agent-id", connection.agentId)).status).toBe(
		"active",
	);
	expect(f.requests.filter((r) => r.url.includes("/agent/status")).length).toBe(
		2,
	);
});
