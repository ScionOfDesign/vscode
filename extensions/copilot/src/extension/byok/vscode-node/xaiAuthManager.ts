/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { IFetcherService } from '../../../platform/networking/common/fetcherService';
import { ILogService } from '../../../platform/log/common/logService';
import { BYOKAuthRecord } from './byokStorageService';
import { IBYOKAuthService, OAuthManagerBase } from './byokAuthService';
import { BYOKAuthType, BYOKCredentialKind } from '../common/byokProvider';
import { XaiAuthUriHandler } from './xaiAuthUriHandler';
import {
	AuthorizationCodePkceClient,
	base64UrlEncode,
	generateCodeChallenge,
	generateCodeVerifier,
	OAuthProviderConfig
} from '../common/oauth';

/**
 * xAI OIDC issuer. Mandatory discovery is performed against
 * `${XAI_OIDC_ISSUER}/.well-known/openid-configuration` (hard fail, no fallback).
 */
export const XAI_OIDC_ISSUER = 'https://auth.x.ai';

/**
 * Fallback token endpoint used for refresh (and as safety default).
 * The primary sign-in flow obtains the real endpoint from OIDC discovery.
 */
export const XAI_TOKEN_ENDPOINT = 'https://auth.x.ai/oauth2/token';

/**
 * Public client_id for the xAI OAuth flow (shared with Grok CLI, OpenCode, Hermes, etc.).
 *
 * This value is NOT secret. It is the same identifier used by other first-party
 * xAI clients today. xAI has not yet provided a dedicated client registration
 * for VS Code + GitHub Copilot with custom redirect URIs, branding, and policy.
 *
 * When a dedicated client becomes available:
 *  - We can switch the redirect target to a pure `vscode://github.copilot/xai-auth` URI
 *    (currently we still use loopback for the shared client allowlist).
 *  - We may be able to request a more appropriate scope set.
 *
 * Do not change this value without coordinating with xAI.
 */
export const XAI_CLIENT_ID = 'b1a00492-073a-47ea-816f-4c329264a828';

/**
 * Scopes requested during authorization.
 * These are carried over from the original CLI-derived token and are known to work.
 * A future dedicated client registration may allow a cleaner/minimal set.
 */
export const XAI_SCOPES = ['openid', 'profile', 'email', 'offline_access', 'grok-cli:access', 'api:access'];

/** Refresh the token if it expires within this window (5 minutes). */
export const TOKEN_REFRESH_THRESHOLD_MS = 5 * 60 * 1000;

/**
 * xAI-specific OAuth provider configuration for the reusable PKCE + OIDC client.
 */
const xaiOAuthConfig: OAuthProviderConfig = {
	issuer: XAI_OIDC_ISSUER,
	clientId: XAI_CLIENT_ID,
	scopes: XAI_SCOPES
};

/**
 * Thin OIDC/PKCE client for xAI, built on the reusable AuthorizationCodePkceClient
 * extracted to ../common/oauth.ts. Future BYOK OAuth providers should use the
 * generic client (or extend it) instead of copying PKCE + discovery logic.
 */
export class XaiOidcClient extends AuthorizationCodePkceClient {
	constructor(fetcher: IFetcherService, logService: ILogService) {
		super(fetcher, logService, xaiOAuthConfig);
	}
}

/**
 * High-level manager for xAI OAuth (BYOK) using PKCE + OIDC discovery.
 * The XaiAuthUriHandler (singleton) must be supplied for both URI dispatch registration
 * and waiting for the authorization redirect.
 */
export class XaiAuthManager extends OAuthManagerBase {
	private readonly _oidcClient: XaiOidcClient;

	constructor(
		private readonly _authService: IBYOKAuthService,
		private readonly _fetcherService: IFetcherService,
		private readonly _logService: ILogService,
		private readonly _uriHandler: XaiAuthUriHandler,
	) {
		super();
		this._oidcClient = new XaiOidcClient(this._fetcherService, this._logService);
	}

	/**
	 * Runs the full PKCE Authorization Code + OIDC discovery sign-in for xAI.
	 * On success, stores the tokens via the BYOK auth service.
	 */
	async signIn(): Promise<BYOKAuthRecord | undefined> {
		try {
			// 1. Discovery (hard fail)
			const discovered = await this._oidcClient.discoverAuthorizationServer();

			// 2. PKCE
			const codeVerifier = await generateCodeVerifier();
			const codeChallenge = await generateCodeChallenge(codeVerifier);

			// 3. State for CSRF protection (must match what the handler validates)
			const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

			// 4. Build the callback URI that the IdP will redirect to after consent.
			// We use the vscode:// form; asExternalUri will rewrite it appropriately
			// for the current environment (local / remote / web).
			const callbackUri = vscode.Uri.parse(
				`${vscode.env.uriScheme}://github.copilot/xai-auth?state=${encodeURIComponent(state)}`
			);

			const redirectUri = (await vscode.env.asExternalUri(callbackUri)).toString(true);

			// 5. Build the authorization request URL
			const authUrl = new URL(discovered.authorizationEndpoint);
			authUrl.searchParams.set('response_type', 'code');
			authUrl.searchParams.set('client_id', XAI_CLIENT_ID);
			authUrl.searchParams.set('redirect_uri', redirectUri);
			authUrl.searchParams.set('scope', XAI_SCOPES.join(' '));
			authUrl.searchParams.set('state', state);
			authUrl.searchParams.set('code_challenge', codeChallenge);
			authUrl.searchParams.set('code_challenge_method', 'S256');

			// 6. Open the (possibly rewritten) URL in the browser
			await vscode.env.openExternal(vscode.Uri.parse(authUrl.toString()));

			// 7. Wait for the authorization code to arrive via our handler
			const code = await vscode.window.withProgress<string | undefined>(
				{
					location: vscode.ProgressLocation.Notification,
					title: vscode.l10n.t('Signing in to xAI...'),
					cancellable: true
				},
				async (progress, token) => {
					progress.report({ message: vscode.l10n.t('Waiting for authorization in the browser...') });

					try {
						return await this._uriHandler.waitForAuthorizationCode(state, token);
					} catch (err) {
						if (token.isCancellationRequested) {
							return undefined;
						}
						this._logService.error('XaiAuthManager: failed waiting for authorization code', String(err));
						await vscode.window.showErrorMessage(
							vscode.l10n.t('Failed to sign in to xAI: {0}', String(err))
						);
						return undefined;
					}
				}
			);

			if (!code) {
				return undefined;
			}

			// 8. Exchange the code for tokens (PKCE)
			const tokenResp = await this._oidcClient.exchangeAuthorizationCode(
				code,
				codeVerifier,
				redirectUri,
				discovered.tokenEndpoint
			);

			const expiresAt = Date.now() + (tokenResp.expires_in * 1000);

			const authRecord: BYOKAuthRecord = {
				kind: BYOKCredentialKind.OAuth,
				accessToken: tokenResp.access_token,
				refreshToken: tokenResp.refresh_token,
				expiresAt,
				tokenType: tokenResp.token_type,
				scope: tokenResp.scope,
				lastUpdatedAt: Date.now()
			};

			await this._authService.storeAuthRecord('xai', authRecord, BYOKAuthType.GlobalApiKey);
			this._logService.info('XaiAuthManager: OAuth tokens stored for xAI via PKCE flow');

			await vscode.window.showInformationMessage(
				vscode.l10n.t('Successfully signed in to xAI with OAuth.')
			);

			return authRecord;

		} catch (err) {
			this._logService.error('XaiAuthManager: signIn failed', String(err));
			await vscode.window.showErrorMessage(
				vscode.l10n.t('Failed to start xAI sign-in: {0}', String(err))
			);
			return undefined;
		}
	}

	/**
	 * Refreshes the access token if the current one is expired or about to expire.
	 * Uses the 5-minute threshold.
	 */
	async refreshIfNeeded(record: BYOKAuthRecord): Promise<BYOKAuthRecord | undefined> {
		if (!record.refreshToken) {
			return record; // No refresh token available; nothing we can do proactively
		}

		const now = Date.now();
		const threshold = now + TOKEN_REFRESH_THRESHOLD_MS;

		if (record.expiresAt && record.expiresAt > threshold) {
			return record; // Still valid for the next 5 minutes
		}

		try {
			// Re-discover to obtain current token endpoint (cheap GET; avoids staleness if xAI rotates endpoints).
			const discovered = await this._oidcClient.discoverAuthorizationServer();
			const newTokens = await this._oidcClient.refreshAccessToken(record.refreshToken, discovered.tokenEndpoint);

			const newRecord: BYOKAuthRecord = {
				...record,
				kind: BYOKCredentialKind.OAuth,
				accessToken: newTokens.access_token,
				refreshToken: newTokens.refresh_token ?? record.refreshToken,
				expiresAt: Date.now() + (newTokens.expires_in * 1000),
				lastUpdatedAt: Date.now()
			};

			// Store via the auth service so it fires onDidChange for any listeners.
			await this._authService.storeAuthRecord('xai', newRecord, BYOKAuthType.GlobalApiKey);

			this._logService.info('XaiAuthManager: refreshed xAI OAuth token proactively');

			return newRecord;
		} catch (err) {
			this._logService.error('XaiAuthManager: proactive refresh failed', String(err));
			// Leave the old record in place; the next actual API call will surface the error
			// and the provider can offer re-auth at that point.
			return record;
		}
	}

	/**
	 * Signs the user out of xAI for BYOK (clears tokens from storage).
	 */
	async signOut(): Promise<void> {
		try {
			// Use the auth service's signOut so it also fires onDidChange for listeners
			await this._authService.signOut('xai', BYOKAuthType.GlobalApiKey);

			this._logService.info('XaiAuthManager: signed out of xAI (BYOK OAuth cleared)');

			await vscode.window.showInformationMessage(
				vscode.l10n.t('Signed out of xAI.')
			);
		} catch (err) {
			this._logService.error('XaiAuthManager: signOut failed', String(err));
		}
	}
}
