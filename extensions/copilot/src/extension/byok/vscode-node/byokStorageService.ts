/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { IVSCodeExtensionContext } from '../../../platform/extContext/common/extensionContext';
import { BYOKAuthType, BYOKCredentialKind, BYOKModelCapabilities } from '../../byok/common/byokProvider';

export interface StoredModelConfig {
	deploymentUrl?: string;
	isRegistered?: boolean; // Will be undefined for now but eventually storage will update to be true / false.
	isCustomModel?: boolean; // Will be undefined for now but eventually storage will update to be true / false.
	modelCapabilities?: BYOKModelCapabilities;
}

/**
 * Unified auth record for a BYOK provider or model.
 * Supports both API key authentication and OAuth / token-based authentication as first-class methods.
 *
 * With the Option 3 design, the `kind` discriminator makes the user's authentication choice
 * explicit and mutually visible ("API key" vs "OAuth sign-in") rather than implicit by which
 * optional field is populated. This enables clear UI labeling, separate sign-in flows,
 * and clean sign-out semantics per credential type.
 */
export interface BYOKAuthRecord {
	/**
	 * Explicit discriminator for the authentication method.
	 * - 'api-key': Traditional manual API key entry.
	 * - 'oauth': OAuth access token obtained via provider sign-in flow (e.g. xAI device code).
	 *
	 * When present, this is the source of truth for UI and preference logic.
	 * When absent (legacy/migrated records), callers may infer from presence of accessToken vs apiKey.
	 */
	kind?: BYOKCredentialKind;

	/** API key for providers that use API key authentication (first-class supported method). */
	apiKey?: string;

	/** OAuth / token-based credentials. */
	accessToken?: string;
	refreshToken?: string;
	/** Expiration timestamp in epoch milliseconds (UTC). */
	expiresAt?: number;
	tokenType?: string;
	scope?: string;

	/** Optional user profile information from the identity provider. */
	userInfo?: {
		id?: string;
		email?: string;
		name?: string;
	};

	/** Last time this record was updated (epoch ms). Used for refresh heuristics and migration. */
	lastUpdatedAt?: number;
}

export interface IBYOKStorageService {
	/**
	 * Get API key for a provider or model
	 */
	getAPIKey(providerName: string, modelId?: string): Promise<string | undefined>;

	/**
	 * Store API key for a provider or model based on auth type
	 */
	storeAPIKey(providerName: string, apiKey: string, authType: BYOKAuthType, modelId?: string): Promise<void>;

	/**
	 * Delete API key for a provider or model based on auth type
	 */
	deleteAPIKey(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void>;

	/**
	 * Get all stored model configurations for a provider
	 */
	getStoredModelConfigs(providerName: string): Promise<Record<string, StoredModelConfig>>;

	/**
	 * Save model configuration to storage
	 */
	saveModelConfig(
		modelId: string,
		providerName: string,
		config: {
			apiKey: string;
			deploymentUrl?: string;
			modelCapabilities?: BYOKModelCapabilities;
		},
		authType: BYOKAuthType
	): Promise<void>;
	/**
	 * Handles the cases
	 * 1. Non custom model, and isDeletingCustomModel = false -> Delete from storage as we have the known model list
	 * 2. Custom model, and isDeletingCustomModel = true -> Delete from storage as we have the known model list
	 * 3. Custom model, and isDeletingCustomModel = false -> Do not delete from storage as we do not have the known model list. Instead mark unregistered
	 */
	removeModelConfig(modelId: string, providerName: string, isDeletingCustomModel: boolean): Promise<void>;

	/**
	 * Get the unified auth record (API key or OAuth tokens) for a provider or specific model.
	 * Falls back to constructing a record from the old *-api-key secret slots if no *-auth record exists (read-only migration bridge for the previous storage format).
	 */
	getAuthRecord(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined>;

	/**
	 * Store a unified auth record for a provider or model. The record may contain either an apiKey or OAuth fields.
	 * The authType determines whether storage is global (provider-level) or per-model.
	 */
	storeAuthRecord(providerName: string, record: BYOKAuthRecord, authType: BYOKAuthType, modelId?: string): Promise<void>;

	/**
	 * Delete the auth record (and any associated old-format api-key secret) for a provider or model.
	 */
	deleteAuthRecord(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void>;
}

export class BYOKStorageService implements IBYOKStorageService {
	private readonly _extensionContext: IVSCodeExtensionContext;

	constructor(extensionContext: IVSCodeExtensionContext) {
		this._extensionContext = extensionContext;
	}

	public async getAPIKey(providerName: string, modelId?: string): Promise<string | undefined> {
		// Prefer the new unified auth record (supports both apiKey and OAuth accessToken).
		const record = await this.getAuthRecord(providerName, modelId);
		if (record) {
			// For OAuth records, the accessToken is used exactly in place of an API key for Bearer auth (xAI PoC).
			if (record.accessToken && record.accessToken.trim()) {
				return record.accessToken.trim();
			}
			if (record.apiKey && record.apiKey.trim()) {
				return record.apiKey.trim();
			}
		}

		// Fallback to old-format direct api-key secret slots for records that have not yet been migrated to the new *-auth JSON format.
		// If model-specific key is requested, try to get it first
		if (modelId) {
			const modelKey = await this._extensionContext.secrets.get(`copilot-byok-${providerName}-${modelId}-api-key`);
			// Only return the key if it's non-empty after trimming, and return the trimmed version
			if (modelKey && modelKey.trim()) {
				return modelKey.trim();
			}
		}

		// Fall back to provider key if no model-specific key or it was requested directly
		const providerKey = await this._extensionContext.secrets.get(`copilot-byok-${providerName}-api-key`);
		// Only return the key if it's non-empty after trimming, and return the trimmed version
		return providerKey?.trim() || undefined;
	}

	public async storeAPIKey(providerName: string, apiKey: string, authType: BYOKAuthType, modelId?: string): Promise<void> {
		// Store API keys based on the provider's auth type
		if (authType === BYOKAuthType.None) {
			// Don't store keys for None auth type providers
			return;
		}

		// Ignore empty or whitespace-only API keys.
		// This prevents invalid keys from being stored
		if (!apiKey?.trim()) {
			return;
		}

		if (authType === BYOKAuthType.GlobalApiKey) {
			// For GlobalApiKey providers, only store at provider level
			await this._extensionContext.secrets.store(`copilot-byok-${providerName}-api-key`, apiKey);
		} else if (authType === BYOKAuthType.PerModelDeployment && modelId) {
			// For PerModelDeployment providers, store per model
			await this._extensionContext.secrets.store(`copilot-byok-${providerName}-${modelId}-api-key`, apiKey);
		}

		// Option 3: Also write (or update) a thin *-auth JSON record with explicit kind=ApiKey.
		// This ensures that the manual "enter API key" flow (via handleAPIKeyUpdate) produces
		// a first-class kinded record, making the credential type visible to UI and providers.
		// We write directly to secrets (bypassing storeAuthRecord) to avoid recursion with
		// the dual-write logic inside storeAuthRecord.
		const authKey = (authType === BYOKAuthType.PerModelDeployment && modelId)
			? `copilot-byok-${providerName}-${modelId}-auth`
			: `copilot-byok-${providerName}-auth`;

		const thinAuthRecord: BYOKAuthRecord = {
			kind: BYOKCredentialKind.ApiKey,
			apiKey: apiKey.trim(),
			lastUpdatedAt: Date.now()
		};
		await this._extensionContext.secrets.store(authKey, JSON.stringify(thinAuthRecord));
	}

	public async deleteAPIKey(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void> {
		// Delete API keys based on the provider's auth type
		if (authType === BYOKAuthType.None) {
			// Nothing to delete for None auth type providers
			return;
		} else if (authType === BYOKAuthType.GlobalApiKey) {
			// For GlobalApiKey providers, delete at provider level
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-api-key`);
		} else if (authType === BYOKAuthType.PerModelDeployment && modelId) {
			// For PerModelDeployment providers, delete per model
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-${modelId}-api-key`);
		}
	}

	public async getStoredModelConfigs(providerName: string): Promise<Record<string, StoredModelConfig>> {
		return this._extensionContext.globalState.get<Record<string, StoredModelConfig>>(
			`copilot-byok-${providerName}-models-config`,
			{}
		);
	}

	public async saveModelConfig(
		modelId: string,
		providerName: string,
		config: {
			apiKey: string;
			isCustomModel: boolean;
			deploymentUrl?: string;
			modelCapabilities?: BYOKModelCapabilities;
		},
		authType: BYOKAuthType
	): Promise<void> {
		// Save model configuration data
		const configToSave: StoredModelConfig = {
			isCustomModel: config.isCustomModel,
			deploymentUrl: config.deploymentUrl,
			isRegistered: true,
			modelCapabilities: config.modelCapabilities
		};
		const existingConfigs = await this.getStoredModelConfigs(providerName);
		existingConfigs[modelId] = configToSave;
		await this._extensionContext.globalState.update(`copilot-byok-${providerName}-models-config`, existingConfigs);

		await this.storeAPIKey(providerName, config.apiKey, authType, modelId);
	}

	public async removeModelConfig(modelId: string, providerName: string, isDeletingCustomModel: boolean): Promise<void> {
		const existingConfigs = await this.getStoredModelConfigs(providerName);
		const existingConfig = existingConfigs[modelId];
		const isCustomModel = existingConfig?.isCustomModel || false;
		if (existingConfig && (isDeletingCustomModel || !isCustomModel)) {
			delete existingConfigs[modelId];
			await this._extensionContext.globalState.update(
				`copilot-byok-${providerName}-models-config`,
				existingConfigs
			);
			// Remove both the old-format api-key secret and the new auth record from secrets
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-${modelId}-api-key`);
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-${modelId}-auth`);
		} else {
			existingConfig.isRegistered = false;
			await this._extensionContext.globalState.update(
				`copilot-byok-${providerName}-models-config`,
				existingConfigs
			);
		}
	}

	public async getAuthRecord(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined> {
		const authKey = modelId
			? `copilot-byok-${providerName}-${modelId}-auth`
			: `copilot-byok-${providerName}-auth`;

		const raw = await this._extensionContext.secrets.get(authKey);
		if (raw) {
			try {
				const parsed = JSON.parse(raw) as BYOKAuthRecord;
				if (parsed && (parsed.apiKey || parsed.accessToken)) {
					return parsed;
				}
			} catch {
				// Corrupt record; fall through to old-format migration path.
			}
		}

		// Read-only migration bridge: if an old-format api-key secret exists (from a previous release), synthesize a record from it.
		// We do not delete the old secret here (safety for rollback across releases).
		// Directly read the old secret keys to avoid recursion with the updated getAPIKey.
		const oldFormatApiKey = modelId
			? await this._extensionContext.secrets.get(`copilot-byok-${providerName}-${modelId}-api-key`)
			: await this._extensionContext.secrets.get(`copilot-byok-${providerName}-api-key`);
		if (oldFormatApiKey && oldFormatApiKey.trim()) {
			return {
				kind: BYOKCredentialKind.ApiKey,
				apiKey: oldFormatApiKey.trim(),
				lastUpdatedAt: Date.now()
			};
		}

		return undefined;
	}

	public async storeAuthRecord(providerName: string, record: BYOKAuthRecord, authType: BYOKAuthType, modelId?: string): Promise<void> {
		if (authType === BYOKAuthType.None) {
			return;
		}

		// Ignore completely empty records.
		if (!record || (!record.apiKey?.trim() && !record.accessToken?.trim())) {
			return;
		}

		const authKey = (authType === BYOKAuthType.PerModelDeployment && modelId)
			? `copilot-byok-${providerName}-${modelId}-auth`
			: `copilot-byok-${providerName}-auth`;

		// Determine the explicit kind for Option 3 clear-choice model.
		// If the caller provided a kind, respect it (source of truth).
		// Otherwise infer from which credential field is populated.
		let kind = record.kind;
		if (!kind) {
			if (record.accessToken && !record.apiKey?.trim()) {
				kind = BYOKCredentialKind.OAuth;
			} else if (record.apiKey?.trim()) {
				kind = BYOKCredentialKind.ApiKey;
			}
		}

		const toStore: BYOKAuthRecord = {
			...record,
			kind,
			lastUpdatedAt: Date.now()
		};
		await this._extensionContext.secrets.store(authKey, JSON.stringify(toStore));

		// Also keep the old-format api-key secret in sync for any code paths that still read it directly
		// during the transition period. This makes rollback safer.
		if (record.apiKey) {
			await this.storeAPIKey(providerName, record.apiKey, authType, modelId);
		} else if (record.accessToken) {
			// For pure OAuth records, we still write the accessToken into the old-format api-key slot
			// so that getAPIKey continues to return a usable credential without requiring every caller
			// to be updated in the same change. This is the key bridge for the xAI PoC.
			await this.storeAPIKey(providerName, record.accessToken, authType, modelId);
		}
	}

	public async deleteAuthRecord(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void> {
		if (authType === BYOKAuthType.None) {
			return;
		}

		if (authType === BYOKAuthType.GlobalApiKey) {
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-auth`);
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-api-key`);
		} else if (authType === BYOKAuthType.PerModelDeployment && modelId) {
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-${modelId}-auth`);
			await this._extensionContext.secrets.delete(`copilot-byok-${providerName}-${modelId}-api-key`);
		}
	}
}
