export class CliError extends Error {
	readonly exitCode: number;
	readonly code: string;
	readonly status?: number;

	constructor(
		exitCode: number,
		code: string,
		message: string,
		status?: number
	) {
		super(message);
		this.name = "CliError";
		this.exitCode = exitCode;
		this.code = code;
		this.status = status;
	}
}

export function usage(message: string): never {
	throw new CliError(1, "usage", message);
}

export function cryptoFail(message: string): never {
	throw new CliError(7, "crypto", message);
}

export function ioFail(message: string): never {
	throw new CliError(7, "io", message);
}

export function envFail(message: string): never {
	throw new CliError(1, "env", message);
}

export function exitForHttp(status: number): number {
	if (status === 401 || status === 403) {
		return 2;
	}
	if (status === 404) {
		return 3;
	}
	if (status === 409) {
		return 4;
	}
	if (status === 429) {
		return 5;
	}
	if (status >= 500) {
		return 6;
	}
	return 1;
}

export function codeForHttp(status: number): string {
	if (status === 401 || status === 403) {
		return "auth";
	}
	if (status === 404) {
		return "not_found";
	}
	if (status === 409) {
		return "conflict";
	}
	if (status === 429) {
		return "rate_limit";
	}
	if (status >= 500) {
		return "server";
	}
	return "usage";
}
