/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { commands, LanguageModelChatInformation, LanguageModelChatProvider, l10n, lm, window } from 'vscode';
import { IAuthenticationService } from '../../../platform/authentication/common/authentication';
import { IVSCodeExtensionContext } from '../../../platform/extContext/common/extensionContext';
import { ILogService } from '../../../platform/log/common/logService';
import { IFetcherService } from '../../../platform/networking/common/fetcherService';
import { Disposable, DisposableStore } from '../../../util/vs/base/common/lifecycle';
import { IInstantiationService } from '../../../util/vs/platform/instantiation/common/instantiation';
import { BYOKAuthType, BYOKKnownModels, isClientBYOKAllowed } from '../../byok/common/byokProvider';
import { IExtensionContribution } from '../../common/contributions';
import { AbstractLanguageModelChatProvider } from './abstractLanguageModelChatProvider';
import { AnthropicLMProvider } from './anthropicProvider';
import { AzureBYOKModelProvider } from './azureProvider';
import { BYOKAuthService, IBYOKAuthService } from './byokAuthService';
import { BYOKStorageService, IBYOKStorageService } from './byokStorageService';
import { XaiAuthManager } from './xaiAuthManager';
import { getXaiAuthUriHandler } from './xaiAuthUriHandler';
import { CustomEndpointBYOKModelProvider } from './customEndpointProvider';
import { CustomOAIBYOKModelProvider } from './customOAIProvider';
import { GeminiNativeBYOKLMProvider } from './geminiNativeProvider';
import { OllamaLMProvider } from './ollamaProvider';
import { OAIBYOKLMProvider } from './openAIProvider';
import { OpenRouterLMProvider } from './openRouterProvider';
import { XAIBYOKLMProvider } from './xAIProvider';

export class BYOKContrib extends Disposable implements IExtensionContribution {
	public readonly id: string = 'byok-contribution';
	private readonly _byokStorageService: IBYOKStorageService;
	private readonly _byokAuthService: IBYOKAuthService;

	/** Exposes the unified auth service (supports both API keys and OAuth tokens) for commands and other consumers. */
	public get byokAuthService(): IBYOKAuthService { return this._byokAuthService; }

	private readonly _providers: Map<string, LanguageModelChatProvider<LanguageModelChatInformation>> = new Map();
	private readonly _providerRegistrations = this._register(new DisposableStore());
	private _providersRegistered = false;
	private _knownModelsRefreshed = false;
	private _knownModelsRefreshTargets: ReadonlyArray<readonly [string, AbstractLanguageModelChatProvider]> = [];

	constructor(
		@IFetcherService private readonly _fetcherService: IFetcherService,
		@ILogService private readonly _logService: ILogService,
		@IVSCodeExtensionContext extensionContext: IVSCodeExtensionContext,
		@IAuthenticationService private readonly _authService: IAuthenticationService,
		@IInstantiationService private readonly _instantiationService: IInstantiationService,
	) {
		super();
		this._byokStorageService = new BYOKStorageService(extensionContext);
		this._byokAuthService = new BYOKAuthService(this._byokStorageService);

		// xAI OAuth (PKCE + OIDC). Handler singleton shared for dispatch + flow wait.
		const xaiHandler = getXaiAuthUriHandler(this._logService);
		const xaiManager = new XaiAuthManager(this._byokAuthService, this._fetcherService, this._logService, xaiHandler);
		this._byokAuthService.registerOAuthManager('xai', xaiManager);

		this._applyPolicy();
		this._register(this._authService.onDidAuthenticationChange(() => this._applyPolicy()));
		this._register(this._byokAuthService.onDidChange(e => {
			this._logService.info(`BYOK: auth changed for provider ${e.providerName}${e.modelId ? ` (model ${e.modelId})` : ''}`);
		}));

		// Register differentiated xAI OAuth commands. These are enabled via when-clauses in package.json.
		// The handlers delegate to the unified auth service, which routes to XaiAuthManager for the PKCE flow.
		this._register(commands.registerCommand('github.copilot.chat.signInXai', async () => {
			try {
				await this._byokAuthService.signInWithOAuth(XAIBYOKLMProvider.authProviderName);

				// After successful OAuth sign-in, ensure the xAI provider is registered (in case
				// the command was invoked before _applyPolicy built providers), then directly
				// trigger migrate for the "xAI (OAuth)" group. This decouples persistence from
				// the provider's onDidChange listener timing.
				this._applyPolicy();
				const cred = await this._byokAuthService.getValidCredential(XAIBYOKLMProvider.authProviderName);
				if (cred) {
					this._logService.info('BYOK: xAI OAuth sign-in succeeded; triggering migrate for "xAI (OAuth)" group');
					try {
						await commands.executeCommand('lm.migrateLanguageModelsProviderGroup', {
							vendor: XAIBYOKLMProvider.providerId,
							name: 'xAI (OAuth)',
							apiKey: cred
						});
						this._logService.info('BYOK: lm.migrateLanguageModelsProviderGroup completed for xAI (OAuth)');
					} catch (migrateErr) {
						const msg = migrateErr instanceof Error ? migrateErr.message : String(migrateErr);
						if (msg.includes('already exists in provider group')) {
							this._logService.info(`BYOK: migrate for xAI (OAuth) skipped (group already present): ${msg}`);
						} else {
							this._logService.error('BYOK: migrate for xAI (OAuth) failed', msg);
							void window.showWarningMessage(l10n.t('xAI OAuth sign-in succeeded, but adding the model provider group failed.'));
						}
					}
				} else {
					this._logService.warn('BYOK: xAI OAuth sign-in reported success but no credential available for migrate');
				}
			} catch (err) {
				this._logService.error('BYOK: xAI sign-in command failed', err instanceof Error ? err.message : String(err));
			}
		}));

		this._register(commands.registerCommand('github.copilot.chat.signOutXai', async () => {
			try {
				// Modal confirm for destructive sign-out of stored OAuth tokens.
				const confirm = await window.showWarningMessage(
					l10n.t('Sign out of xAI? This will remove your OAuth access tokens for this provider.'),
					{ modal: true },
					l10n.t('Sign Out'),
					l10n.t('Cancel')
				);
				if (confirm === l10n.t('Sign Out')) {
					await this._byokAuthService.signOut(XAIBYOKLMProvider.authProviderName, BYOKAuthType.GlobalApiKey);
				}
			} catch (err) {
				this._logService.error('BYOK: xAI sign-out command failed', err instanceof Error ? err.message : String(err));
			}
		}));
	}

	private _buildProviders(): void {
		const instantiationService = this._instantiationService;

		// All BYOK providers receive the unified auth service (supports both API key and OAuth credentials).
		// The auth service is always provided; it delegates to storage for API-key-only flows.
		const anthropic = instantiationService.createInstance(AnthropicLMProvider, undefined, this._byokStorageService, this._byokAuthService);
		const gemini = instantiationService.createInstance(GeminiNativeBYOKLMProvider, undefined, this._byokStorageService, this._byokAuthService);
		const xai = instantiationService.createInstance(XAIBYOKLMProvider, {}, this._byokStorageService, this._byokAuthService, XAIBYOKLMProvider.authProviderName);
		const openai = instantiationService.createInstance(OAIBYOKLMProvider, {}, this._byokStorageService, this._byokAuthService);

		this._providers.set(OllamaLMProvider.providerId, instantiationService.createInstance(OllamaLMProvider, this._byokStorageService, this._byokAuthService));
		this._providers.set(AnthropicLMProvider.providerId, anthropic);
		this._providers.set(GeminiNativeBYOKLMProvider.providerId, gemini);
		this._providers.set(XAIBYOKLMProvider.providerId, xai);
		this._providers.set(OAIBYOKLMProvider.providerId, openai);
		this._providers.set(OpenRouterLMProvider.providerId, instantiationService.createInstance(OpenRouterLMProvider, this._byokStorageService, this._byokAuthService));
		this._providers.set(AzureBYOKModelProvider.providerId, instantiationService.createInstance(AzureBYOKModelProvider, this._byokStorageService, this._byokAuthService));
		this._providers.set(CustomOAIBYOKModelProvider.providerId, instantiationService.createInstance(CustomOAIBYOKModelProvider, this._byokStorageService, this._byokAuthService));
		this._providers.set(CustomEndpointBYOKModelProvider.providerId, instantiationService.createInstance(CustomEndpointBYOKModelProvider, this._byokStorageService, this._byokAuthService));

		this._knownModelsRefreshTargets = [
			[AnthropicLMProvider.providerName, anthropic],
			[GeminiNativeBYOKLMProvider.providerName, gemini],
			[XAIBYOKLMProvider.providerName, xai],
			[OAIBYOKLMProvider.providerName, openai],
		];
	}

	private _applyPolicy(): void {
		const allowed = isClientBYOKAllowed(!!this._authService.anyGitHubSession, this._authService.copilotToken);
		if (allowed && !this._providersRegistered) {
			if (this._providers.size === 0) {
				this._buildProviders();
			}
			for (const [providerId, provider] of this._providers) {
				this._providerRegistrations.add(lm.registerLanguageModelChatProvider(providerId, provider));
			}
			this._providersRegistered = true;
			this._logService.info(`BYOK: registered ${this._providers.size} provider(s): ${Array.from(this._providers.keys()).join(', ')}`);
			if (!this._knownModelsRefreshed) {
				this._knownModelsRefreshed = true;
				void this._refreshKnownModels().catch(err => {
					this._knownModelsRefreshed = false;
					this._logService.warn(`BYOK: failed to refresh known models, will retry on next allowed transition: ${err instanceof Error ? err.message : String(err)}`);
				});
			}
		} else if (!allowed && this._providersRegistered) {
			this._providerRegistrations.clear();
			this._providersRegistered = false;
			this._logService.info('BYOK: unregistered providers due to enterprise policy.');
		}
	}

	private async _refreshKnownModels(): Promise<void> {
		const knownModels = await this._fetchKnownModelList(this._fetcherService);
		if (this._store.isDisposed) {
			return;
		}
		for (const [providerName, provider] of this._knownModelsRefreshTargets) {
			provider.updateKnownModels(knownModels[providerName]);
		}
	}

	private async _fetchKnownModelList(fetcherService: IFetcherService): Promise<Record<string, BYOKKnownModels>> {
		this._logService.info('BYOK: fetching known models list');
		const data = await (await fetcherService.fetch('https://main.vscode-cdn.net/extensions/copilotChat.json', { method: 'GET', callSite: 'byok-known-models' })).json();
		// Use this for testing with changes from a local file. Don't check in
		// const data = JSON.parse((await this._fileSystemService.readFile(URI.file('/Users/roblou/code/vscode-engineering/chat/copilotChat.json'))).toString());
		if (data.version !== 1) {
			this._logService.warn('BYOK: Copilot Chat known models list is not in the expected format. Defaulting to empty list.');
			return {};
		}
		this._logService.info('BYOK: Copilot Chat known models list fetched successfully.');
		return data.modelInfo;
	}
}
