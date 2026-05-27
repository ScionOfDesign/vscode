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
import { XaiLoopbackServer } from './xaiLoopbackServer';
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
 * We use a local loopback redirect (http://127.0.0.1:<random>/callback) for the
 * authorization code. This works with the shared client_id today without any
 * vscode:// or code-oss:// redirect URIs having to be registered by xAI.
 *
 * TEMPORARY WORKAROUND: Loopback is used only because xAI currently restricts
 * the shared public client to http(s) redirects (no custom schemes such as
 * vscode://, code-oss://, etc. are registered). Once xAI adds support for
 * proper registered redirect URIs (https or the github.copilot/xai-auth path),
 * we will switch to the XaiAuthUriHandler + asExternalUri flow.
 *
 * The loopback server includes CORS preflight + header support so that xAI's
 * accounts.x.ai consent page (which uses fetch() to the redirect_uri) does not
 * trigger a browser CORS block. This mitigates the "Could not establish connection"
 * manual-paste symptom for the current shared client_id.
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
 *
 * TEMPORARY: We currently use a local loopback HTTP server
 * (http://127.0.0.1:port/callback) because xAI only allows http(s) redirects
 * for the shared public client_id (custom schemes like vscode:// etc. are
 * not yet registered). The XaiAuthUriHandler + asExternalUri path is the
 * intended long-term "proper" flow and the handler remains registered.
 *
 * See the commented FUTURE block in signIn() for the URL to swap in.
 */
export class XaiAuthManager extends OAuthManagerBase {
	private readonly _oidcClient: XaiOidcClient;

	constructor(
		private readonly _authService: IBYOKAuthService,
		private readonly _fetcherService: IFetcherService,
		private readonly _logService: ILogService,
		private readonly _uriHandler: XaiAuthUriHandler, // kept only for call-site compatibility; not used in current loopback flow
	) {
		super();
		void this._uriHandler; // intentionally unused for now (loopback redirect does not require the custom URI handler)
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

			// 3. State + nonce for CSRF / OIDC protection.
			// TEMPORARY WORKAROUND: loopback redirect while xAI only permits http(s)
			// redirects for this shared public client_id. Custom scheme redirects
			// (vscode://github.copilot/xai-auth etc.) are not yet supported by xAI.
			// The XaiLoopbackServer now handles CORS so fetch()-based consent pages succeed.
			const state = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
			const nonce = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));

			// 4. Start a minimal local HTTP server on a random port. This is the redirect target
			// the browser will be sent to after the user consents on xAI.
			const server = new XaiLoopbackServer(msg => this._logService.info(`XaiLoopback: ${msg}`));
			server.setExpectedState(state);
			const port = await server.start();

			// FUTURE (swap this in once xAI registers proper http(s) or scheme redirects):
			// const redirectUri = (await vscode.env.asExternalUri(
			// 	vscode.Uri.parse(`${vscode.env.uriScheme}://github.copilot/xai-auth`)
			// )).toString(true).replace(/\/$/, '');
			const redirectUri = `http://127.0.0.1:${port}/callback`;

			this._logService.info(`XaiAuthManager: using redirect_uri for xAI: ${redirectUri}`);

			// 5. Build the authorization request URL (using the discovered endpoint)
			const authUrl = new URL(discovered.authorizationEndpoint);
			authUrl.searchParams.set('response_type', 'code');
			authUrl.searchParams.set('client_id', XAI_CLIENT_ID);
			authUrl.searchParams.set('redirect_uri', redirectUri);
			authUrl.searchParams.set('scope', XAI_SCOPES.join(' '));
			authUrl.searchParams.set('state', state);
			authUrl.searchParams.set('nonce', nonce);
			authUrl.searchParams.set('code_challenge', codeChallenge);
			authUrl.searchParams.set('code_challenge_method', 'S256');

			const finalAuthUrl = authUrl.toString();
			this._logService.info(`XaiAuthManager: opening browser for xAI consent: ${finalAuthUrl}`);

			// 6. Open the browser. xAI will redirect the browser to the loopback URL with the code.
			await vscode.env.openExternal(vscode.Uri.parse(finalAuthUrl));

			// 7. Wait for the local server to receive the callback (or cancellation/timeout)
			const code = await vscode.window.withProgress<string | undefined>(
				{
					location: vscode.ProgressLocation.Notification,
					title: vscode.l10n.t('Signing in to xAI...'),
					cancellable: true
				},
				async (progress, token) => {
					progress.report({ message: vscode.l10n.t('Waiting for authorization in the browser...') });

					const timeoutPromise = new Promise<never>((_, reject) =>
						setTimeout(() => reject(new Error('Timed out waiting for xAI authorization')), 5 * 60 * 1000));

					const cancelPromise = new Promise<never>((_, reject) => {
						if (token.isCancellationRequested) {
							reject(new Error('Cancelled'));
						} else {
							token.onCancellationRequested(() => {
								void server.stop();
								reject(new Error('Cancelled by user'));
							});
						}
					});

					try {
						const result = await Promise.race([
							server.waitForOAuthResponse(),
							timeoutPromise,
							cancelPromise
						]);
						return result.code;
					} catch (err) {
						if (token.isCancellationRequested) {
							return undefined;
						}

						this._logService.error('XaiAuthManager: failed waiting for authorization code', String(err));

						// Recovery path for the (now mitigated) symptom the user saw:
						// xAI showed "Could not establish connection. We couldn't reach your app."
						// and offered a manual code to paste. This was caused by the consent page using
						// fetch() to the loopback; the server now returns proper CORS headers for xAI origins.
						// The fallback remains useful until xAI updates their allowlist for the shared client.
						const manualCode = await vscode.window.showInputBox({
							prompt: vscode.l10n.t('xAI could not reach the local redirect. Paste the authorization code shown on the xAI page (or leave empty to cancel)'),
							placeHolder: 'Paste the long code from the "Could not establish connection" page',
							ignoreFocusOut: true
						});
						if (manualCode && manualCode.trim()) {
							this._logService.info('XaiAuthManager: using manually pasted authorization code as fallback');
							return manualCode.trim();
						}

						await vscode.window.showErrorMessage(
							vscode.l10n.t('Failed to sign in to xAI: {0}', String(err))
						);
						return undefined;
					} finally {
						await server.stop().catch(() => { /* best effort */ });
					}
				}
			);

			if (!code) {
				return undefined;
			}

			// 8. Exchange the code for tokens (PKCE)
			// Must pass the exact same redirect_uri that was used in the authorize request.
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
