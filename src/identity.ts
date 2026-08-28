import { HD, Mnemonic, PrivateKey } from "@bsv/sdk";
import {
	type BapMasterBackup,
	decryptBackup,
	encryptBackup,
	isLegacyBackup,
	isType42Backup,
} from "bitcoin-backup";
import { BAP } from "bsv-bap";
import { cryptoFail } from "./error.ts";

export type PublicIdentity = {
	bapId: string;
	pubkey: string;
	address: string;
	label?: string;
	createdAt?: string;
	ids: string[];
};

export function createMasterBackup(label: string): {
	mnemonic: string;
	backup: BapMasterBackup;
	bapId: string;
	pubkey: string;
	address: string;
} {
	const mnemonic = Mnemonic.fromRandom();
	const hdKey = HD.fromSeed(mnemonic.toSeed());
	const rootKey = hdKey.derive("m/0'/0");
	const rootPk = rootKey.privKey?.toWif();
	if (!rootPk) {
		cryptoFail("Failed to derive wallet root private key");
	}
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
		mnemonic: mnemonic.toString(),
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
