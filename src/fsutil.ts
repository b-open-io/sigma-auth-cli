import {
	chmodSync,
	existsSync,
	mkdirSync,
	readFileSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { dirname } from "node:path";
import { ioFail, usage } from "./error.ts";

export function ensureDir(path: string, mode = 0o700): void {
	mkdirSync(path, { recursive: true, mode });
	chmodSync(path, mode);
}

export function writeSecretFile(
	path: string,
	contents: string,
	force: boolean
): void {
	if (existsSync(path) && !force) {
		usage(`refusing to overwrite ${path} (pass --force)`);
	}
	ensureDir(dirname(path));
	writeFileSync(path, contents, { encoding: "utf8", mode: 0o600 });
	chmodSync(path, 0o600);
}

export function readText(path: string): string {
	try {
		return readFileSync(path, "utf8");
	} catch {
		ioFail(`cannot read ${path}`);
	}
}

export function fileMode(path: string): number {
	try {
		return statSync(path).mode & 0o777;
	} catch {
		return 0;
	}
}

export function pathExists(path: string): boolean {
	return existsSync(path);
}
