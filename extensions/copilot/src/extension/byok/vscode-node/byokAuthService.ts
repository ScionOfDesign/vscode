/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Event, EventEmitter } from 'vscode';
import { IBYOKStorageService, BYOKAuthRecord } from './byokStorageService';
import { BYOKAuthType } from '../../byok/common/byokProvider';

/**
 * Result of an authentication operation (sign-in / refresh).
 */
export interface BYOKAuthResult {
	/** The provider or model this auth record applies to. */
	providerName: string;
	modelId?: string;

	/** The record that was stored (may contain accessToken or apiKey). */
	record: BYOKAuthRecord;

	/** Whether this was a fresh sign-in vs a refresh. */
	isNewSignIn: boolean;
}

/**
 * Minimal interface that per-provider OAuth managers (e.g. XaiAuthManager) implement
 * for delegation from BYOKAuthService. This avoids the service depending on concrete
 * manager classes while still allowing provider-specific device code / refresh logic.
 */
export interface IOAuthManager {
	signIn(): Promise<BYOKAuthRecord | undefined>;
	refreshIfNeeded(record: BYOKAuthRecord): Promise<BYOKAuthRecord | undefined>;
}

/**
 * Service responsible for the full lifecycle of BYOK authentication credentials,
 * supporting both API key authentication and OAuth-based access tokens as first-class methods.
 *
 * For the xAI PoC (and future OAuth providers), this service (or a provider-specific
 * manager it delegates to) will:
 *  - Perform the OAuth device authorization grant flow (or other OIDC flow)
 *  - Proactively refresh expiring tokens before use
 *  - Expose a stable "get credential" API so that AbstractOpenAICompatibleLMProvider
 *    and OpenAIEndpoint can obtain a Bearer token exactly as they currently obtain an API key.
 *
 * The default implementation provides a thin pass-through / migration layer over
 * IBYOKStorageService. Concrete per-provider managers (e.g. XaiOAuthManager) will
 * be composed in later steps.
 */
export interface IBYOKAuthService {
	/**
	 * Event fired when auth state changes for a provider (sign-in, sign-out, token refresh).
	 * Consumers (e.g. model picker, providers) can use this to refresh UI or reconfigure clients.
	 */
	readonly onDidChange: Event<{ providerName: string; modelId?: string }>;

	/**
	 * Returns a credential suitable for use as a Bearer token (API key or OAuth access token).
	 * For OAuth records this returns the (possibly refreshed) accessToken.
	 * For API key records this returns the apiKey.
	 *
	 * This is the primary integration point for existing BYOK provider code.
	 */
	getValidCredential(providerName: string, modelId?: string): Promise<string | undefined>;

	/**
	 * Returns the full auth record (useful for UI that wants to show user info, expiry, etc.).
	 */
	getAuthRecord(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined>;

	/**
	 * Initiates an OAuth sign-in flow for the given provider.
	 * For the xAI PoC this will eventually perform the device code flow against xAI's IdP.
	 * The implementation may prompt the user, open a browser, poll, etc.
	 *
	 * Returns the resulting auth record on success, or undefined if the user cancelled.
	 */
	signInWithOAuth(providerName: string, modelId?: string, options?: { promptForReconfigure?: boolean }): Promise<BYOKAuthResult | undefined>;

	/**
	 * Refreshes the access token for the provider/model if it is expired or nearing expiry.
	 * No-op for pure API key records.
	 * Returns the (possibly updated) record, or undefined if refresh failed / not applicable.
	 */
	refreshIfNeeded(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined>;

	/**
	 * Completely removes stored credentials (both OAuth record and old-format api-key secret) for the provider/model.
	 * Fires onDidChange.
	 */
	signOut(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void>;

	/**
	 * Stores a credential record (either from a successful OAuth flow or from an API key entry prompt).
	 * This is the write path that higher-level flows (prompts, managers) should use.
	 */
	storeAuthRecord(providerName: string, record: BYOKAuthRecord, authType: BYOKAuthType, modelId?: string): Promise<void>;

	/**
	 * Registers a provider-specific OAuth manager (e.g. for xAI device code flow).
	 * Once registered, signInWithOAuth and refreshIfNeeded for that provider will delegate
	 * to the manager instead of using the base no-op / heuristic implementations.
	 */
	registerOAuthManager(providerName: string, manager: IOAuthManager): void;
}

/**
 * Default implementation of IBYOKAuthService.
 * Initially a thin wrapper over storage that unifies apiKey + accessToken access.
 * Per-provider OAuth managers will be plugged in here in subsequent steps.
 */
export class BYOKAuthService implements IBYOKAuthService {
	private readonly _onDidChange = new EventEmitter<{ providerName: string; modelId?: string }>();
	public readonly onDidChange = this._onDidChange.event;

	private readonly _oauthManagers = new Map<string, IOAuthManager>();

	constructor(
		private readonly _storageService: IBYOKStorageService
	) { }

	public async getValidCredential(providerName: string, modelId?: string): Promise<string | undefined> {
		// Delegate to storage which already bridges old-format and new OAuth records and returns
		// the best available credential (accessToken preferred over apiKey).
		return this._storageService.getAPIKey(providerName, modelId);
	}

	public async getAuthRecord(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined> {
		return this._storageService.getAuthRecord(providerName, modelId);
	}

	public async signInWithOAuth(providerName: string, modelId?: string, options?: { promptForReconfigure?: boolean }): Promise<BYOKAuthResult | undefined> {
		const manager = this._oauthManagers.get(providerName);
		if (manager) {
			void options; // reserved for future "reconfigure" UX
			const record = await manager.signIn();
			if (record) {
				return {
					providerName,
					modelId,
					record,
					isNewSignIn: true
				};
			}
			return undefined;
		}

		// No manager registered for this provider — base implementation has no interactive flow.
		void options;
		void providerName;
		void modelId;
		return undefined;
	}

	public async refreshIfNeeded(providerName: string, modelId?: string): Promise<BYOKAuthRecord | undefined> {
		const manager = this._oauthManagers.get(providerName);
		if (manager) {
			const record = await this._storageService.getAuthRecord(providerName, modelId);
			if (!record) {
				return undefined;
			}
			return manager.refreshIfNeeded(record);
		}

		// No manager registered — fall back to the simple expiry heuristic (no proactive refresh).
		const record = await this._storageService.getAuthRecord(providerName, modelId);
		if (!record || !record.accessToken) {
			return record; // Nothing to refresh (API key record or empty)
		}

		const now = Date.now();
		const skewMs = 60_000; // 1 minute
		if (record.expiresAt && record.expiresAt <= (now + skewMs)) {
			// Token is expired or very close; without a registered manager we cannot refresh it.
			// The caller (provider) will surface a sign-in prompt on the next failed request.
			return record;
		}

		return record;
	}

	public async signOut(providerName: string, authType: BYOKAuthType, modelId?: string): Promise<void> {
		await this._storageService.deleteAuthRecord(providerName, authType, modelId);
		this._onDidChange.fire({ providerName, modelId });
	}

	public async storeAuthRecord(providerName: string, record: BYOKAuthRecord, authType: BYOKAuthType, modelId?: string): Promise<void> {
		await this._storageService.storeAuthRecord(providerName, record, authType, modelId);
		this._onDidChange.fire({ providerName, modelId });
	}

	public registerOAuthManager(providerName: string, manager: IOAuthManager): void {
		this._oauthManagers.set(providerName, manager);
	}
}
