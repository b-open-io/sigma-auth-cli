import { PrivateKey, Utils } from "@bsv/sdk";
import {
	type BapMasterBackup,
	decryptBackup,
	encryptBackup,
	isLegacyBackup,
	isType42Backup,
} from "bitcoin-backup";
import { BAP } from "bsv-bap";
import { cryptoFail } from "./error.ts";

/** bitcoin-backup encryptData: salt(16) || iv(12) || AES-GCM ciphertext (16-byte tag). */
const SALT_LENGTH_BYTES = 16;
const IV_LENGTH_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const MIN_ENVELOPE_BYTES = SALT_LENGTH_BYTES + IV_LENGTH_BYTES + AES_GCM_TAG_BYTES;

export type PublicIdentity = {
	bapId: string;
	pubkey: string;
	address: string;
	label?: string;
	createdAt?: string;
	ids: string[];
};

export function createMasterBackup(label: string): {
	backup: BapMasterBackup;
	bapId: string;
	pubkey: string;
	address: string;
} {
	const rootPk = PrivateKey.fromRandom().toWif();
	const bap = new BAP({ rootPk });
	const first = bap.newId();
	const backup: BapMasterBackup = {
		rootPk,
		ids: bap.exportIds(),
		createdAt: new Date().toISOString(),
		label,
	};
	const member = first.getAccountKey();
	return {
		backup,
		bapId: first.bapId,
		pubkey: member.toPublicKey().toString(),
		address: member.toAddress().toString(),
	};
}

export function bapFromBackup(backup: BapMasterBackup): InstanceType<typeof BAP> {
	let bap: InstanceType<typeof BAP>;
	if (isLegacyBackup(backup)) {
		bap = new BAP(backup.xprv);
	} else if (isType42Backup(backup)) {
		bap = new BAP({ rootPk: backup.rootPk });
	} else {
		cryptoFail("backup is not a Type42 or legacy master backup");
	}
	if (backup.ids && backup.ids.length > 0) {
		bap.importIds(backup.ids);
	}
	return bap;
}

export function publicFields(
	backup: BapMasterBackup,
	bapId?: string
): PublicIdentity {
	const bap = bapFromBackup(backup);
	const ids = bap.listIds();
	if (ids.length === 0) {
		cryptoFail("backup has no identities; run identity create");
	}
	const selected = bapId ?? ids[0];
	if (!selected || !ids.includes(selected)) {
		cryptoFail(`BAP id not found in backup${bapId ? `: ${bapId}` : ""}`);
	}
	const member = bap.getId(selected);
	if (!member) {
		cryptoFail(`BAP id not found: ${selected}`);
	}
	const key = member.getAccountKey();
	return {
		bapId: selected,
		pubkey: key.toPublicKey().toString(),
		address: key.toAddress().toString(),
		label: "label" in backup ? backup.label : undefined,
		createdAt: "createdAt" in backup ? backup.createdAt : undefined,
		ids,
	};
}

export function memberWif(backup: BapMasterBackup, bapId?: string): {
	wif: string;
	bapId: string;
	pubkey: string;
	address: string;
} {
	const fields = publicFields(backup, bapId);
	const bap = bapFromBackup(backup);
	const member = bap.getId(fields.bapId);
	if (!member) {
		cryptoFail(`BAP id not found: ${fields.bapId}`);
	}
	return {
		wif: member.getAccountKey().toWif(),
		bapId: fields.bapId,
		pubkey: fields.pubkey,
		address: fields.address,
	};
}

export function rootPubkey(backup: BapMasterBackup): string | null {
	if (isType42Backup(backup)) {
		return PrivateKey.fromWif(backup.rootPk).toPublicKey().toString();
	}
	return null;
}

export async function encryptMaster(
	backup: BapMasterBackup,
	password: string
): Promise<string> {
	return encryptBackup(backup, password);
}

export async function decryptMaster(ciphertext: string, password: string): Promise<BapMasterBackup> {
	try {
		const decrypted = await decryptBackup(ciphertext, password);
		if (isType42Backup(decrypted) || isLegacyBackup(decrypted)) {
			return decrypted;
		}
		cryptoFail("decrypted backup is not a master backup");
	} catch (error) {
		const message = error instanceof Error ? error.message : "decrypt failed";
		cryptoFail(message);
	}
}

export function looksLikePlaintextBackup(text: string): boolean {
	try {
		const parsed = JSON.parse(text) as Record<string, unknown>;
		return (
			typeof parsed.rootPk === "string" ||
			typeof parsed.xprv === "string" ||
			typeof parsed.wif === "string" ||
			typeof parsed.mnemonic === "string"
		);
	} catch {
		return false;
	}
}

function looksLikeWif(text: string): boolean {
	return /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(text);
}

function looksLikeExtendedKey(text: string): boolean {
	return /^(xprv|tprv|yprv|zprv|Yprv|Zprv)/.test(text);
}

function looksLikeMnemonic(text: string): boolean {
	const words: string[] = [];
	let current = "";
	for (const ch of text) {
		if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
			if (current.length > 0) {
				words.push(current);
				current = "";
			}
		} else {
			current += ch;
		}
	}
	if (current.length > 0) {
		words.push(current);
	}
	const wordCount = words.length;
	if (
		wordCount !== 12 &&
		wordCount !== 15 &&
		wordCount !== 18 &&
		wordCount !== 21 &&
		wordCount !== 24
	) {
		return false;
	}
	return words.every((word) => /^[a-z]+$/i.test(word));
}

function looksLikeJsonObject(text: string): boolean {
	try {
		const parsed = JSON.parse(text) as unknown;
		return parsed !== null && typeof parsed === "object";
	} catch {
		return false;
	}
}

export function isBitcoinBackupCiphertext(text: string): boolean {
	if (text.length === 0) {
		return false;
	}
	if (
		looksLikePlaintextBackup(text) ||
		looksLikeJsonObject(text) ||
		looksLikeWif(text) ||
		looksLikeExtendedKey(text) ||
		looksLikeMnemonic(text)
	) {
		return false;
	}
	try {
		const bytes = Utils.toArray(text, "base64");
		if (bytes.length < MIN_ENVELOPE_BYTES) {
			return false;
		}
		return Utils.toBase64(bytes) === text;
	} catch {
		return false;
	}
}

export function assertBitcoinBackupCiphertext(text: string): void {
	if (
		looksLikePlaintextBackup(text) ||
		looksLikeWif(text) ||
		looksLikeExtendedKey(text) ||
		looksLikeMnemonic(text)
	) {
		cryptoFail(
			"refusing to upload plaintext backup (rootPk/xprv/wif/mnemonic present)"
		);
	}
	if (!isBitcoinBackupCiphertext(text)) {
		cryptoFail("refusing to upload: not opaque bitcoin-backup ciphertext");
	}
}
