import {
	AgentAuthClient,
	type ApprovalInfo,
	type ProviderConfig,
} from "@auth/agent";
import { agentStore } from "./agent-store.ts";
import { flag, flagList, type ParsedArgs } from "./args.ts";
import type { RuntimeConfig } from "./config.ts";
import { CliError, usage } from "./error.ts";
import { readText } from "./fsutil.ts";
import { printHuman, printJson } from "./output.ts";

type State = {
	agentId: string;
	provider: string;
	requestedCapabilities: string[];
	status: string;
	verificationUri?: string;
	userCode?: string;
	expiresAt?: number;
	nextPollAt: number;
	intervalMs: number;
};
const pending = Symbol("approval saved");
const terminal = new Set(["denied", "rejected", "revoked", "expired"]);
function fail(message: string): never {
	throw new CliError(1, "agent", message);
}

export function agentUrl(value: string, origin?: string): URL {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return fail("Invalid agent provider URL");
	}
	const localhost = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
	if (
		(url.protocol !== "https:" && !(url.protocol === "http:" && localhost)) ||
		url.username ||
		url.password ||
		url.hash ||
		(origin && url.origin !== origin)
	) {
		fail(
			"Agent URLs must use HTTPS (HTTP localhost is allowed), have no credentials, and share the provider origin",
		);
	}
	return url;
}

export function validateAgentProvider(
	config: ProviderConfig,
	origin: string,
): void {
	agentUrl(config.issuer, origin);
	if (!config.endpoints || typeof config.endpoints !== "object")
		fail("Invalid agent discovery endpoints");
	for (const endpoint of Object.values(config.endpoints)) {
		if (typeof endpoint !== "string") fail("Invalid agent discovery endpoint");
		agentUrl(
			new URL(endpoint, `${config.issuer.replace(/\/+$/, "")}/`).href,
			origin,
		);
	}
	for (const location of [
		config.default_location,
		config.jwks_uri,
		...(config.capabilities ?? []).map((cap) => cap.location),
	]) {
		if (location) agentUrl(location, origin);
	}
}

function publicApproval(info: ApprovalInfo, origin: string) {
	const uri = info.verification_uri
		? agentUrl(info.verification_uri, origin)
		: undefined;
	// Complete URIs and query strings can contain bearer claim artifacts.
	if (uri) uri.search = "";
	return { verificationUri: uri?.href, userCode: info.user_code };
}

function redact(value: unknown, secrets: string[]): unknown {
	if (typeof value === "string") {
		let text = value.replace(
			/Bearer\s+\S+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi,
			"[redacted]",
		);
		for (const secret of secrets)
			if (secret) text = text.replaceAll(secret, "[redacted]");
		return text;
	}
	if (Array.isArray(value)) return value.map((item) => redact(item, secrets));
	if (value && typeof value === "object") {
		return Object.fromEntries(
			Object.entries(value)
				.filter(
					([key]) =>
						!/^(d|privateKey|private_key|agentKeypair|keypair|authorization|headers|cookie|cookies|.*token.*|.*secret.*|.*password.*|verification_uri_complete)$/i.test(
							key,
						),
				)
				.map(([key, item]) => [key, redact(item, secrets)]),
		);
	}
	return value;
}

export async function agentCommand(
	args: ParsedArgs,
	cfg: RuntimeConfig,
): Promise<number> {
	const command = args.positional[1];
	if (
		!["capabilities", "connect", "status", "execute", "disconnect"].includes(
			command ?? "",
		)
	)
		usage(
			"Expected agent capabilities, connect, status, execute, or disconnect",
		);
	const required = (name: string) =>
		flag(args, name)?.trim() || usage(`--${name} is required`);
	const requested = [...new Set(flagList(args, "capability"))];
	const name = command === "connect" ? required("name") : undefined;
	if (
		command === "connect" &&
		(!requested.length || requested.some((cap) => !cap.trim()))
	)
		usage("At least one --capability is required");
	const agentId = ["status", "execute", "disconnect"].includes(command ?? "")
		? required("agent-id")
		: undefined;
	const capability = command === "execute" ? required("capability") : undefined;
	if (command === "execute" && requested.length !== 1)
		usage("Execute accepts exactly one --capability");
	let argumentsValue: Record<string, unknown> | undefined;
	if (command === "execute") {
		try {
			argumentsValue = JSON.parse(readText(required("args-file")));
		} catch {
			usage("--args-file must contain a JSON object");
		}
		if (
			!argumentsValue ||
			Array.isArray(argumentsValue) ||
			typeof argumentsValue !== "object"
		)
			usage("--args-file must contain a JSON object");
	}
	const origin = agentUrl(cfg.baseUrl).origin;
	const { kv, storage } = agentStore(cfg.home);
	let state: State | undefined;
	let revokeConfirmed = false;
	const stateKey = (id: string) => `cli:state:${id}`;
	const save = async () => {
		if (state) await kv.set(stateKey(state.agentId), JSON.stringify(state));
	};
	if (agentId) {
		const raw = await kv.get(stateKey(agentId));
		if (!raw) fail("No saved agent connection; connect first");
		state = JSON.parse(raw) as State;
		agentUrl(state.provider, origin);
	}
	const originalDelete = storage.deleteAgentConnection.bind(storage);
	storage.deleteAgentConnection = async (id) => {
		// SDK 0.6.2 ignores revoke HTTP/network failures. Keep credentials for retry.
		if (command === "disconnect" && !revokeConfirmed)
			fail(
				"Revocation was not confirmed; local credentials retained. Retry disconnect",
			);
		await originalDelete(id);
	};
	const transport = (async (
		input: string | URL | Request,
		init?: RequestInit,
	) => {
		const url = agentUrl(
			typeof input === "string"
				? input
				: input instanceof URL
					? input.href
					: input.url,
			origin,
		);
		const response = await fetch(input, {
			...init,
			redirect: "error",
			credentials: "omit",
			signal: AbortSignal.timeout(cfg.timeoutMs),
		});
		if (response.url) agentUrl(response.url, origin);
		if (command === "disconnect") revokeConfirmed = response.ok;
		if (state && command === "status") {
			const retry = response.headers.get("retry-after");
			const seconds = retry === null ? Number.NaN : Number(retry);
			const until = Number.isFinite(seconds)
				? Date.now() + Math.max(0, seconds) * 1000
				: Date.parse(retry ?? "");
			if (response.status === 429)
				state.intervalMs = Math.max(state.intervalMs * 2, 5000);
			state.nextPollAt = Math.max(
				state.nextPollAt,
				Date.now() + state.intervalMs,
				Number.isFinite(until) ? until : 0,
			);
			await save();
			if (response.status === 429)
				throw new CliError(
					5,
					"rate_limit",
					"Agent status is throttled; retry after nextPollAt",
					429,
				);
		}
		if (response.ok && url.pathname.endsWith("agent-configuration"))
			validateAgentProvider(
				(await response.clone().json()) as ProviderConfig,
				origin,
			);
		return response;
	}) as typeof fetch;
	// URL-only mode disables the SDK default public directory. Discovery stays on this provider.
	const client = new AgentAuthClient({
		storage,
		urls: [cfg.baseUrl],
		fetch: transport,
		onApprovalRequired: async (info) => {
			if (!state) fail("Registration state was not saved");
			Object.assign(state, publicApproval(info, origin), {
				status: "pending",
				expiresAt: Date.now() + Math.max(0, info.expires_in) * 1000,
				intervalMs: Math.max(1, info.interval || 5) * 1000,
				nextPollAt: Date.now() + Math.max(1, info.interval || 5) * 1000,
			});
			await save();
			throw pending;
		},
	});
	// Hook SDK persistence, which occurs before onApprovalRequired (no polling or duplicate registration).
	const originalSet = storage.setAgentConnection.bind(storage);
	storage.setAgentConnection = async (id, connection) => {
		await originalSet(id, connection);
		if (command === "connect") {
			state = {
				agentId: id,
				provider: connection.issuer,
				requestedCapabilities: requested,
				status: "pending",
				nextPollAt: Date.now() + 5000,
				intervalMs: 5000,
			};
			await save();
		}
	};
	const output = async (data: unknown) => {
		const host = await storage.getHostIdentity();
		const connection = state
			? await storage.getAgentConnection(state.agentId)
			: null;
		const secrets = [
			host?.keypair.privateKey.d,
			connection?.agentKeypair.privateKey.d,
		].filter((value): value is string => typeof value === "string");
		const safe = redact(data, secrets);
		if (cfg.json) printJson(true, safe);
		else printHuman(cfg, JSON.stringify(safe, null, 2));
		return 0;
	};
	try {
		const provider = agentId
			? await storage.getProviderConfig(state!.provider)
			: await client.discoverProvider(cfg.baseUrl);
		if (!provider)
			fail(
				"Saved provider configuration is missing; connection cannot be used",
			);
		validateAgentProvider(provider, origin);
		if (command === "capabilities")
			return output(
				await client.listCapabilities({ provider: provider.issuer }),
			);
		if (command === "connect") {
			if (!provider.modes.includes("delegated"))
				fail("Provider does not support delegated approval");
			try {
				const result = await client.connectAgent({
					provider: provider.issuer,
					name,
					capabilities: requested,
					mode: "delegated",
				});
				state!.status = result.status;
				await save();
			} catch (error) {
				if (error !== pending) throw error;
			}
			return output(state);
		}
		if (command === "status") {
			// Approval may have completed before expiresAt while this CLI was stopped.
			// Only the provider can declare the registration expired.
			if (!terminal.has(state!.status) && Date.now() >= state!.nextPollAt) {
				state!.nextPollAt = Date.now() + state!.intervalMs;
				await save();
				try {
					const result = await client.agentStatus(agentId!);
					state!.status = result.status;
				} catch (error) {
					if (!(error instanceof CliError && error.status === 429)) throw error;
				}
			}
			await save();
			const connection = await storage.getAgentConnection(agentId!);
			return output({
				...state,
				grants: connection?.capabilityGrants.map(
					({ capability, status, constraints }) => ({
						capability,
						status,
						constraints,
					}),
				),
				action: terminal.has(state!.status)
					? "Connect again to request new approval"
					: state!.status === "pending"
						? "Complete approval in your browser, then run status after nextPollAt"
						: undefined,
			});
		}
		if (command === "disconnect") {
			await client.disconnectAgent(agentId!);
			state!.status = "revoked";
			await save();
			return output({ agentId, status: "revoked" });
		}
		if (state!.status !== "active")
			fail("Agent is not active; run status after approval");
		const connection = await storage.getAgentConnection(agentId!);
		if (
			!state!.requestedCapabilities.includes(capability!) ||
			!connection?.capabilityGrants.some(
				(grant) => grant.capability === capability && grant.status === "active",
			)
		)
			fail("Capability is not an active requested grant");
		return output(
			await client.executeCapability({
				agentId: agentId!,
				capability: capability!,
				arguments: argumentsValue,
			}),
		);
	} catch (error) {
		if (error instanceof CliError) throw error;
		// SDK errors may contain untrusted server response text, URLs, and headers.
		throw new CliError(
			1,
			"agent",
			"Agent request failed; credentials were retained. Check provider availability and run status before retrying",
		);
	} finally {
		client.destroy();
	}
}
