/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { IConfigurationService } from '../../../platform/configuration/common/configurationService';
import { ILogService } from '../../../platform/log/common/logService';
import { IFetcherService } from '../../../platform/networking/common/fetcherService';
import { IExperimentationService } from '../../../platform/telemetry/common/nullExperimentationService';
import { IInstantiationService } from '../../../util/vs/platform/instantiation/common/instantiation';
import { Emitter, Event } from '../../../util/vs/base/common/event';
import { BYOKCredentialKind, BYOKKnownModels, BYOKModelCapabilities } from '../common/byokProvider';
import { AbstractOpenAICompatibleLMProvider, LanguageModelChatConfiguration, OpenAICompatibleLanguageModelChatInformation } from './abstractLanguageModelChatProvider';
import { IBYOKAuthService } from './byokAuthService';
import { IBYOKStorageService } from './byokStorageService';
import { OpenAIEndpoint } from '../node/openAIEndpoint';

// https://docs.x.ai/docs/api-reference#list-language-models
interface XAIModelData {
	id: string;
	fingerprint: string;
	created: number;
	object: string;
	owned_by: string;
	input_modalities: string[];
	output_modalities: string[];
	prompt_text_token_price: number;
	cached_prompt_text_token_price: number;
	prompt_image_token_price: number;
	completion_text_token_price: number;
	search_price?: number;
	version: string;
	aliases: string[];
}

export class XAIBYOKLMProvider extends AbstractOpenAICompatibleLMProvider {

	public static readonly providerName = 'xAI';
	public static readonly providerId = this.providerName.toLowerCase();

	/**
	 * Canonical key used for BYOK auth records, OAuth manager registration (in byokContribution),
	 * and storage (inside XaiAuthManager). Must match the literal 'xai' used in
	 * registerOAuthManager('xai', ...) and storeAuthRecord('xai', ...).
	 * The LM-facing providerName/providerId remain 'xAI'/'xai' for the primary entry.
	 */
	public static readonly authProviderName = 'xai';

	/**
	 * The key used for BYOK auth records and for the XaiAuthManager registration.
	 * (Previously used by a removed 'xai-oauth' subclass for a dedicated OAuth dropdown entry;
	 * the field is retained for future OAuth-variant providers that may need a distinct LM
	 * vendor while sharing the same underlying auth records and device-flow manager.)
	 */
	protected readonly _authProviderName: string;

	/**
	 * Event fired when the set of models available from this xAI provider changes.
	 * Wired to the unified BYOK auth service's onDidChange (for the auth provider key)
	 * so that successful OAuth sign-in (or sign-out) causes the core to re-query
	 * provideLanguageModelChatInformation and surface the provider with models.
	 */
	private readonly _onDidChangeLanguageModelChatInformation = new Emitter<void>();
	readonly onDidChangeLanguageModelChatInformation: Event<void> = this._onDidChangeLanguageModelChatInformation.event;

	constructor(
		knownModels: BYOKKnownModels,
		byokStorageService: IBYOKStorageService,
		byokAuthService: IBYOKAuthService,
		authProviderName: string = XAIBYOKLMProvider.authProviderName,
		@IFetcherService fetcherService: IFetcherService,
		@ILogService logService: ILogService,
		@IInstantiationService instantiationService: IInstantiationService,
		@IConfigurationService configurationService: IConfigurationService,
		@IExperimentationService expService: IExperimentationService
	) {
		super(
			XAIBYOKLMProvider.providerId,
			XAIBYOKLMProvider.providerName,
			knownModels,
			byokStorageService,
			byokAuthService,
			fetcherService,
			logService,
			instantiationService,
			configurationService,
			expService
		);

		this._authProviderName = authProviderName;

		// React to xAI credential changes (OAuth sign-in via XaiAuthManager, proactive refresh,
		// or sign-out) by firing the provider change event. This is the contract the core
		// LanguageModelsService uses to know it should re-resolve models for this vendor.
		//
		// The explicit "Sign in to xAI" command (signInXai in byokContribution.ts) is the
		// only place that performs the migrate for the kind-aware "xAI (OAuth)" group name.
		// The listener and initial-load here must **only fire the event** and never call
		// configure/migrate. This prevents duplicate name errors, re-adding on rename/delete,
		// and repeated add attempts. We listen on the *auth* provider name ('xai') so the
		// provider reacts to credential changes even though the LM vendor id is also 'xai'.
		this._byokAuthService.onDidChange(e => {
			if (e.providerName === this._authProviderName) {
				this._logService.info(`XAIBYOKLMProvider: auth changed for ${this._authProviderName}${e.modelId ? ` (model ${e.modelId})` : ''}, firing onDidChangeLanguageModelChatInformation`);
				this._onDidChangeLanguageModelChatInformation.fire();
				// No configure/migrate here. The command handler owns the one-time migrate.
			}
		});

		// If we already have a credential at load time (persisted OAuth or API key), fire once
		// so the core picks up any models for already-persisted groups. Do NOT call configure
		// or migrate — that would re-add the group after the user deleted it in the Language Models UI.
		void this.getCredentialWithRefresh().then(cred => {
			if (cred) {
				this._onDidChangeLanguageModelChatInformation.fire();
			}
		});
	}

	protected getModelsBaseUrl(): string | undefined {
		return 'https://api.x.ai/v1';
	}

	protected override getModelsDiscoveryUrl(modelsBaseUrl: string): string {
		return `${modelsBaseUrl}/language-models`;
	}

	protected override resolveModelCapabilities(modelData: unknown): BYOKModelCapabilities | undefined {
		const xaiModelData = modelData as XAIModelData;
		// Add new model with reasonable defaults
		let maxInputTokens;
		let maxOutputTokens;

		// Coding models and Grok 4+ models have larger context windows
		const parsedVersion = this.parseXAIModelVersion(xaiModelData.id) ?? 0;
		if (xaiModelData.id.startsWith('grok-code') || parsedVersion >= 4) {
			maxInputTokens = 120000;
			maxOutputTokens = 120000;
		} else {
			maxInputTokens = 80000;
			maxOutputTokens = 30000;
		}

		return {
			name: this.humanizeXAIModelId(xaiModelData.id),
			toolCalling: true,
			vision: xaiModelData.input_modalities.includes('image'),
			maxInputTokens,
			maxOutputTokens,
		};
	}

	/**
	 * xAI-specific override: use the refresh-aware credential path so that OAuth
	 * access tokens are proactively refreshed (via the registered XaiAuthManager)
	 * before model discovery and before chat responses.
	 *
	 * This override performs refresh but does not trigger group migration; the explicit
	 * sign-in command in byokContribution is responsible for initial group setup.
	 */
	protected override async configureDefaultGroupWithApiKeyOnly(): Promise<string | undefined> {
		const cred = await this.getCredentialWithRefresh();
		if (cred) {
			const record = await this._byokAuthService.getAuthRecord(this._authProviderName);
			this._logService.info(`XAIBYOKLMProvider: configureDefaultGroupWithApiKeyOnly (refresh only) for ${this._authProviderName} (kind=${record?.kind ?? 'unknown'})`);
		} else {
			this._logService.info('XAIBYOKLMProvider: configureDefaultGroupWithApiKeyOnly called but no credential present');
		}
		return cred;
	}

	/**
	 * xAI-specific override for the chat response path: force a proactive refresh
	 * (if an OAuth record with refresh token exists) immediately before constructing
	 * the OpenAIEndpoint.
	 */
	protected override async createOpenAIEndPoint(model: OpenAICompatibleLanguageModelChatInformation<LanguageModelChatConfiguration>): Promise<OpenAIEndpoint> {
		// Ensure we have the freshest possible xAI credential (OAuth or API key) before chat.
		const freshCredential = await this.getCredentialWithRefresh();
		// Temporarily attach the fresh credential so the base implementation picks it up.
		const modelWithFreshKey = {
			...model,
			configuration: {
				...model.configuration,
				apiKey: freshCredential
			}
		} as OpenAICompatibleLanguageModelChatInformation<LanguageModelChatConfiguration>;
		return super.createOpenAIEndPoint(modelWithFreshKey);
	}

	/**
	 * xAI-specific override: ensure proactive OAuth refresh happens immediately before
	 * the actual /language-models (or /models) network call for discovery.
	 *
	 * Errors during discovery are caught and logged instead of thrown (non-fatal for
	 * the OAuth path) so the provider group can still be persisted.
	 */
	protected override async getAllModels(silent: boolean, apiKey: string | undefined, configuration: LanguageModelChatConfiguration | undefined): Promise<OpenAICompatibleLanguageModelChatInformation<LanguageModelChatConfiguration>[]> {
		// Force refresh (no-op for API-key-only records) so the apiKey we pass to super is fresh.
		const fresh = await this.getCredentialWithRefresh();
		try {
			return await super.getAllModels(silent, fresh ?? apiKey, configuration);
		} catch (err) {
			this._logService.warn(`XAIBYOKLMProvider: non-fatal error during model discovery for xAI (OAuth path or transient); returning empty list so group can still be persisted. Error: ${String(err)}`);
			return [];
		}
	}

	private parseXAIModelVersion(modelId: string): number | undefined {
		const match = modelId.match(/^grok-(\d+)/);
		return match ? parseInt(match[1], 10) : undefined;
	}

	private humanizeXAIModelId(modelId: string): string {
		const parts = modelId.split('-').filter(p => p.length > 0);
		return parts.map(p => {
			if (/^\d+$/.test(p)) {
				return p; // keep pure numbers as-is
			}
			return p.charAt(0).toUpperCase() + p.slice(1);
		}).join(' ');
	}

	/**
	 * Returns a credential for xAI (access token or API key), first performing proactive
	 * OAuth refresh via the registered XaiAuthManager when the stored record indicates
	 * an OAuth credential (kind === OAuth or presence of a refresh token).
	 *
	 * Callers (overrides of provideLanguageModelChatInformation, createOpenAIEndPoint, etc.)
	 * should use this instead of the base _getCredential when they need a fresh xAI credential.
	 *
	 * Uses the instance _authProviderName (the canonical 'xai' auth key) for all
	 * BYOK auth service calls.
	 */
	protected async getCredentialWithRefresh(): Promise<string | undefined> {
		const record = await this._byokAuthService.getAuthRecord(this._authProviderName);
		if (record && (record.kind === BYOKCredentialKind.OAuth || record.refreshToken)) {
			await this._byokAuthService.refreshIfNeeded(this._authProviderName);
		}
		return this._byokAuthService.getValidCredential(this._authProviderName);
	}
}

