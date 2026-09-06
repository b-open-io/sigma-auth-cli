import { createHash, randomUUID } from "node:crypto";
import {
	chmodSync,
	closeSync,
	fsyncSync,
	openSync,
	readFileSync,
	renameSync,
	rmSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { KVStorage } from "@auth/agent";
import { ensureDir } from "./fsutil.ts";

export function agentStore(home: string) {
	const directory = join(home, "agent-auth");
	ensureDir(directory);
	const path = (key: string) =>
		join(directory, `${createHash("sha256").update(key).digest("hex")}.json`);
	const kv = {
		async get(key: string): Promise<string | null> {
			try {
				return readFileSync(path(key), "utf8");
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
				throw error;
			}
		},
		async set(key: string, value: string) {
			const target = path(key);
			const temporary = `${target}.${randomUUID()}.tmp`;
			const fd = openSync(temporary, "wx", 0o600);
			try {
				writeFileSync(fd, value);
				fsyncSync(fd);
			} finally {
				closeSync(fd);
			}
			try {
				renameSync(temporary, target);
				chmodSync(target, 0o600);
			} finally {
				rmSync(temporary, { force: true });
			}
		},
		async del(key: string) {
			try {
				unlinkSync(path(key));
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
		},
	};
	return { kv, storage: new KVStorage(kv) };
}
