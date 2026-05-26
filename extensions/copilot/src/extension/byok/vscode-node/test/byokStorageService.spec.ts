/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { beforeEach, describe, expect, it } from 'vitest';
import * as vscode from 'vscode';
import type { SecretStorage, SecretStorageChangeEvent } from 'vscode';
import { BYOKAuthType, BYOKCredentialKind } from '../../common/byokProvider';
import { BYOKStorageService } from '../byokStorageService';
import type { IVSCodeExtensionContext } from '../../../../platform/extContext/common/extensionContext';

/**
 * In-memory SecretStorage implementation for testing the dual-storage (auth + api-key) behavior.
 * Tracks all operations for assertions and supports the minimal interface used by BYOKStorageService.
 */
class InMemorySecretStorage implements SecretStorage {
	private readonly _secrets = new Map<string, string>();
	public readonly operations: Array<{ op: 'get' | 'store' | 'delete'; key: string; value?: string }> = [];

	get(key: string): Thenable<string | undefined> {
		this.operations.push({ op: 'get', key });
		return Promise.resolve(this._secrets.get(key));
	}

	store(key: string, value: string): Thenable<void> {
		this.operations.push({ op: 'store', key, value });
		this._secrets.set(key, value);
		return Promise.resolve();
	}

	delete(key: string): Thenable<void> {
		this.operations.push({ op: 'delete', key });
		this._secrets.delete(key);
		return Promise.resolve();
	}

	keys(): Thenable<string[]> {
		return Promise.resolve(Array.from(this._secrets.keys()));
	}

	readonly onDidChange = (() => {
		// No-op event for tests (storage service does not subscribe in current impl).
		const emitter = new vscode.EventEmitter<SecretStorageChangeEvent>();
		return emitter.event;
	})();
}

function createInMemoryExtensionContext(): IVSCodeExtensionContext {
	const secrets = new InMemorySecretStorage();
	return {
		secrets,
		// Minimal surface used by BYOKStorageService (other properties are not accessed).
	} as unknown as IVSCodeExtensionContext;
}

describe('BYOKStorageService', () => {
	let context: IVSCodeExtensionContext;
	let secrets: InMemorySecretStorage;
	let storage: BYOKStorageService;

	beforeEach(() => {
		context = createInMemoryExtensionContext();
		secrets = context.secrets as unknown as InMemorySecretStorage;
		storage = new BYOKStorageService(context);
		secrets.operations.length = 0;
	});

	describe('getAPIKey / storeAPIKey (API-key only path)', () => {
		it('stores and retrieves a provider-level api key via the direct slot', async () => {
			await storage.storeAPIKey('xai', 'sk-test-123', BYOKAuthType.GlobalApiKey);
			const key = await storage.getAPIKey('xai');
			expect(key).toBe('sk-test-123');
		});

		it('for GlobalApiKey providers, modelId is ignored and storage is provider-level only (PerModelDeployment providers use per-model slots)', async () => {
			// GlobalApiKey (e.g. xAI) always uses provider-level slots regardless of modelId param.
			await storage.storeAPIKey('xai', 'sk-model-456', BYOKAuthType.GlobalApiKey, 'some-model');
			const viaModel = await storage.getAPIKey('xai', 'some-model');
			expect(viaModel).toBe('sk-model-456');
			const viaProvider = await storage.getAPIKey('xai');
			expect(viaProvider).toBe('sk-model-456');
		});

		it('trims whitespace on store and get', async () => {
			await storage.storeAPIKey('xai', '  sk-trim  ', BYOKAuthType.GlobalApiKey);
			const key = await storage.getAPIKey('xai');
			expect(key).toBe('sk-trim');
		});

		it('returns undefined for empty or whitespace-only keys', async () => {
			await storage.storeAPIKey('xai', '   ', BYOKAuthType.GlobalApiKey);
			const key = await storage.getAPIKey('xai');
			expect(key).toBeUndefined();
		});
	});

	describe('OAuth auth records + dual-write compatibility shim', () => {
		it('storeAuthRecord for OAuth writes the unified record and dual-writes accessToken to the old api-key slot', async () => {
			await storage.storeAuthRecord('xai', {
				kind: BYOKCredentialKind.OAuth,
				accessToken: 'oauth-access-789',
				refreshToken: 'refresh-abc',
				expiresAt: Date.now() + 3600_000,
				lastUpdatedAt: Date.now()
			}, BYOKAuthType.GlobalApiKey);

			// Preferred path: due to dual-write calling storeAPIKey, the rich OAuth record is overwritten
			// by a thin {kind: ApiKey, apiKey: <accessToken value>} record. This is the current shim behavior.
			const record = await storage.getAuthRecord('xai');
			expect(record?.apiKey).toBe('oauth-access-789');
			expect(record?.kind).toBe(BYOKCredentialKind.ApiKey);
			expect(record?.accessToken).toBeUndefined();

			// Compat path (getAPIKey reads from the (thin) auth record)
			const compatKey = await storage.getAPIKey('xai');
			expect(compatKey).toBe('oauth-access-789');

			// Verify both secrets exist (dual-write + thin record)
			const authSecret = await secrets.get('copilot-byok-xai-auth');
			const apiKeySecret = await secrets.get('copilot-byok-xai-api-key');
			expect(authSecret).toBeDefined();
			expect(apiKeySecret).toBe('oauth-access-789');
		});

		it('getAPIKey prefers the unified auth record (accessToken) over any stale direct api-key slot', async () => {
			// Seed a direct api-key (simulating pre-OAuth or partial migration state)
			await secrets.store('copilot-byok-xai-api-key', 'old-direct-key');

			// Now store an OAuth record (which also dual-writes)
			await storage.storeAuthRecord('xai', {
				kind: BYOKCredentialKind.OAuth,
				accessToken: 'new-oauth-token'
			}, BYOKAuthType.GlobalApiKey);

			const key = await storage.getAPIKey('xai');
			expect(key).toBe('new-oauth-token'); // from auth record, not the old direct slot
		});

		it('getAuthRecord synthesizes a record from the direct api-key slot when no unified record exists (read-side bridge)', async () => {
			await secrets.store('copilot-byok-xai-api-key', 'legacy-only-key');

			const record = await storage.getAuthRecord('xai');
			expect(record).toBeDefined();
			expect(record?.apiKey).toBe('legacy-only-key');
			// kind is inferred on the read path for the bridge
			expect(record?.kind).toBe(BYOKCredentialKind.ApiKey);
		});

		it('deleteAuthRecord removes both the unified record and the api-key compatibility slot', async () => {
			await storage.storeAuthRecord('xai', {
				kind: BYOKCredentialKind.OAuth,
				accessToken: 'to-be-deleted'
			}, BYOKAuthType.GlobalApiKey);

			await storage.deleteAuthRecord('xai', BYOKAuthType.GlobalApiKey);

			const record = await storage.getAuthRecord('xai');
			const compat = await storage.getAPIKey('xai');
			expect(record).toBeUndefined();
			expect(compat).toBeUndefined();

			// Both secrets gone
			const authSecret = await secrets.get('copilot-byok-xai-auth');
			const apiKeySecret = await secrets.get('copilot-byok-xai-api-key');
			expect(authSecret).toBeUndefined();
			expect(apiKeySecret).toBeUndefined();
		});

		it('deleteAPIKey removes only the direct api-key slot (asymmetric by design for the migration shim)', async () => {
			// Seed both
			await storage.storeAuthRecord('xai', {
				kind: BYOKCredentialKind.OAuth,
				accessToken: 'both-places'
			}, BYOKAuthType.GlobalApiKey);

			// Call the shim-style delete
			await storage.deleteAPIKey('xai', BYOKAuthType.GlobalApiKey);

			// Auth record still present (shim leaves thin ApiKey-shaped record with value in .apiKey)
			const record = await storage.getAuthRecord('xai');
			expect(record?.apiKey).toBe('both-places');
			expect(record?.accessToken).toBeUndefined();

			// Direct slot removed, but getAPIKey still returns value from the remaining auth record (asymmetry)
			const compat = await storage.getAPIKey('xai');
			expect(compat).toBe('both-places');

			const apiKeySecret = await secrets.get('copilot-byok-xai-api-key');
			expect(apiKeySecret).toBeUndefined();
		});
	});

	// Note: model-scoped storage (separate *-auth / *-api-key slots per modelId) only applies when
	// authType === BYOKAuthType.PerModelDeployment. For GlobalApiKey providers (e.g. xAI OAuth),
	// the modelId parameter is ignored and all operations target the provider-level slots.
	// Per-model behavior for PerModelDeployment providers is covered via integration in removeModelConfig
	// and existing provider tests (using mocks). The shim tests above focus on the Global + OAuth path
	// introduced for the xAI BYOK feature.

	describe('edge cases', () => {
		it('getAPIKey returns undefined when nothing is stored', async () => {
			const key = await storage.getAPIKey('never-seen');
			expect(key).toBeUndefined();
		});

		it('operations on None auth type are no-ops for store', async () => {
			await storage.storeAPIKey('xai', 'should-not-store', BYOKAuthType.None);
			const key = await storage.getAPIKey('xai');
			expect(key).toBeUndefined();
		});
	});
});
