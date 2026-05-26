/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { IFetcherService } from '../../../platform/networking/common/fetcherService';
import { ILogService } from '../../../platform/log/common/logService';
import { BYOKAuthRecord } from './byokStorageService';
import { IBYOKAuthService } from './byokAuthService';
import { BYOKAuthType, BYOKCredentialKind } from '../common/byokProvider';
import { XaiAuthUriHandler } from './xaiAuthUriHandler';

/**
 * xAI OIDC issuer. We perform mandatory discovery against
 * `${XAI_OIDC_ISSUER}/.well-known/openid-configuration` using the core
 * `fetchAuthorizationServerMetadata` utility (hard fail — no hardcoded fallback).
 *
 * See: src/vs/base/common/oauth.ts
 */
export const XAI_OIDC_ISSUER = 'https://auth.x.ai';

/**
 * Token endpoint. In the final implementation this will be obtained from
 * OIDC discovery (/.well-known/openid-configuration), but we pin a known-good
 * value for the initial PKCE implementation.
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

/** Successful token response (both initial and refresh). */
export interface XaiTokenResponse {
	readonly access_token: string;
	readonly token_type: string;
	readonly expires_in: number;
	readonly refresh_token?: string;
	readonly scope?: string;
}

/** Error response from token endpoint. */
export interface XaiTokenErrorResponse {
	readonly error: string;
	readonly error_description?: string;
}

/**
 * Cryptographic helpers for PKCE (RFC 7636) S256.
 */
async function generateCodeVerifier(): Promise<string> {
	const array = new Uint8Array(32);
	crypto.getRandomValues(array);
	return base64UrlEncode(array);
}

function base64UrlEncode(buffer: Uint8Array): string {
	return btoa(String.fromCharCode(...buffer))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

async function generateCodeChallenge(verifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(verifier);
	const digest = await crypto.subtle.digest('SHA-256', data);
	return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Pure HTTP + PKCE client for xAI's OAuth2 Authorization Code flow.
 * Performs OIDC discovery and drives the PKCE dance.
 * Does not perform UI or storage operations.
 */
export class XaiOidcClient {
	constructor(
		private readonly _fetcher: IFetcherService,
		private readonly _logService: ILogService,
	) { }

	/**
	 * Performs OIDC discovery against the well-known endpoint.
	 * Hard fail if discovery does not succeed (no hardcoded fallback).
	 */
	async discoverAuthorizationServer(): Promise<{ authorizationEndpoint: string; tokenEndpoint: string }> {
		const wellKnown = `${XAI_OIDC_ISSUER}/.well-known/openid-configuration`;
		this._logService.debug(`XaiOidcClient: performing OIDC discovery from ${wellKnown}`);

		const response = await this._fetcher.fetch(wellKnown, {
			method: 'GET',
			headers: { 'Accept': 'application/json' },
			callSite: 'xai-byok-oidc-discovery'
		});

		if (!response.ok) {
			const text = await response.text();
			throw new Error(`OIDC discovery failed (${response.status}): ${text}`);
		}

		const metadata = await response.json() as {
			authorization_endpoint?: string;
			token_endpoint?: string;
		};

		if (!metadata.authorization_endpoint || !metadata.token_endpoint) {
			throw new Error('Invalid OIDC discovery document from xAI (missing endpoints)');
		}

		this._logService.info('XaiOidcClient: OIDC discovery succeeded');
		return {
			authorizationEndpoint: metadata.authorization_endpoint,
			tokenEndpoint: metadata.token_endpoint
		};
	}

	/**
	 * Exchanges an authorization code + PKCE verifier for tokens.
	 */
	async exchangeAuthorizationCode(
		code: string,
		codeVerifier: string,
		redirectUri: string,
		tokenEndpoint: string
	): Promise<XaiTokenResponse> {
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			client_id: XAI_CLIENT_ID,
			code_verifier: codeVerifier
		}).toString();

		this._logService.debug('XaiOidcClient: exchanging authorization code for tokens');

		const response = await this._fetcher.fetch(tokenEndpoint, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json'
			},
			body,
			callSite: 'xai-byok-pkce-exchange'
		});

		if (!response.ok) {
			const text = await response.text();
			this._logService.error(`XaiOidcClient: code exchange failed ${response.status}: ${text}`);
			throw new Error(`Authorization code exchange failed: ${response.status}. Server: ${text}`);
		}

		const tokenData = await response.json() as XaiTokenResponse;
		if (!tokenData.access_token || typeof tokenData.expires_in !== 'number') {
			throw new Error('Invalid token response from xAI');
		}

		this._logService.info('XaiOidcClient: PKCE authorization code exchange succeeded');
		return tokenData;
	}

	/**
	 * Exchanges a refresh_token for a new access_token.
	 */
	async refreshAccessToken(refreshToken: string): Promise<XaiTokenResponse> {
		const body = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: XAI_CLIENT_ID
		}).toString();

		this._logService.debug('XaiOidcClient: refreshing access token');

		const response = await this._fetcher.fetch(XAI_TOKEN_ENDPOINT, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json'
			},
			body,
			callSite: 'xai-byok-refresh'
		});

		if (!response.ok) {
			const text = await response.text();
			this._logService.error(`XaiOidcClient: refresh failed ${response.status}: ${text}`);
			throw new Error(`Token refresh failed: ${response.status}. Server: ${text}`);
		}

		const tokenData = await response.json() as XaiTokenResponse;
		if (!tokenData.access_token || typeof tokenData.expires_in !== 'number') {
			throw new Error('Invalid refresh response from xAI');
		}

		this._logService.info('XaiOidcClient: token refresh succeeded');
		return tokenData;
	}
}

/**
 * High-level manager for xAI OAuth lifecycle (BYOK).
 *
 * Implements the full VS Code OAuth pattern (Option C):
 * - Mandatory OIDC discovery via /.well-known/openid-configuration (hard fail).
 * - PKCE Authorization Code flow (S256).
 * - Uses XaiAuthUriHandler + vscode.env.asExternalUri for the redirect callback.
 *   This gives correct behavior on local, remote/SSH, and web.
 *
 * The handler must be provided at construction time (obtained via the singleton
 * getXaiAuthUriHandler so that the same instance is used for both dispatch and waiting).
 */
export class XaiAuthManager {
	private readonly _oidcClient: XaiOidcClient;

	constructor(
		private readonly _authService: IBYOKAuthService,
		private readonly _fetcherService: IFetcherService,
		private readonly _logService: ILogService,
		private readonly _uriHandler: XaiAuthUriHandler,
	) {
		this._oidcClient = new XaiOidcClient(this._fetcherService, this._logService);
	}

	/**
	 * Performs the PKCE + OIDC discovery sign-in flow for xAI.
	 *
	 * High-level steps:
	 * 1. OIDC discovery to learn the real authorization_endpoint.
	 * 2. Generate PKCE code_verifier + code_challenge (S256).
	 * 3. Create state + nonce.
	 * 4. Build authorize URL and run it through asExternalUri (critical for remote/SSH).
	 * 5. Open the resulting URL.
	 * 6. Wait for the code via the XaiAuthUriHandler (which receives the vscode:// redirect).
	 * 7. Exchange the code for tokens using the code_verifier.
	 * 8. Persist via the auth service.
	 */
	async signIn(): Promise<BYOKAuthRecord | undefined> {
		const cancellation = new vscode.CancellationTokenSource();

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
		} finally {
			cancellation.dispose();
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
			const newTokens = await this._oidcClient.refreshAccessToken(record.refreshToken);

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
