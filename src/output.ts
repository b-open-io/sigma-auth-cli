import { CliError } from "./error.ts";

export type OutputMode = {
	json: boolean;
	quiet: boolean;
};

export function printJson(ok: boolean, data: unknown, error?: unknown): void {
	if (ok) {
		process.stdout.write(`${JSON.stringify({ ok: true, data })}\n`);
		return;
	}
	process.stdout.write(`${JSON.stringify({ ok: false, error })}\n`);
}

export function printHuman(mode: OutputMode, text: string): void {
	if (mode.quiet || mode.json) {
		return;
	}
	process.stdout.write(`${text}\n`);
}

export function printWarn(mode: OutputMode, text: string): void {
	if (mode.json) {
		return;
	}
	process.stderr.write(`${text}\n`);
}

export function reportError(mode: OutputMode, err: unknown): number {
	if (err instanceof CliError) {
		if (mode.json) {
			printJson(false, undefined, {
				code: err.code,
				message: err.message,
				status: err.status,
			});
		} else if (!mode.quiet) {
			process.stderr.write(`${err.message}\n`);
		}
		return err.exitCode;
	}
	const message = err instanceof Error ? err.message : String(err);
	if (mode.json) {
		printJson(false, undefined, { code: "io", message });
	} else {
		process.stderr.write(`${message}\n`);
	}
	return 1;
}
