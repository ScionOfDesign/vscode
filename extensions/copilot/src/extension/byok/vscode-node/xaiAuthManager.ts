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

/**
 * xAI OIDC / OAuth2 constants for the device authorization grant flow (RFC 8628).
 * These endpoints are discovered from the issuer's .well-known/openid-configuration,
 * but we hardcode the known values for reliability in the PoC.
 */
export const XAI_OIDC_ISSUER = 'https://auth.x.ai';
export const XAI_DEVICE_AUTH_ENDPOINT = 'https://auth.x.ai/oauth2/device/code';
export const XAI_TOKEN_ENDPOINT = 'https://auth.x.ai/oauth2/token';

/**
 * Client ID for the xAI OAuth device flow (PoC / testing).
 *
 * Value extracted from a real xAI auth.json (issued to the Grok CLI client).
 * For the official first-party VS Code + GitHub Copilot integration, xAI must
 * register a dedicated client_id with appropriate branding, policy, and
 * redirect/audience configuration. Do not ship with a CLI-derived client_id.
 */
export const XAI_CLIENT_ID = 'b1a00492-073a-47ea-816f-4c329264a828';

/**
 * Scopes requested in the device authorization grant.
 * These match the scopes present in the real token from the provided auth.json.
 * The 'grok-cli:access' scope is an artifact of the source client; a dedicated
 * VS Code client registration would likely use a cleaner scope set.
 */
export const XAI_SCOPES = ['openid', 'profile', 'email', 'offline_access', 'grok-cli:access', 'api:access'];

/** Refresh the token if it expires within this window (5 minutes). */
export const TOKEN_REFRESH_THRESHOLD_MS = 5 * 60 * 1000;

/** Response from the device authorization endpoint. */
export interface XaiDeviceCodeResponse {
	readonly device_code: string;
	readonly user_code: string;
	readonly verification_uri: string;
	readonly verification_uri_complete?: string;
	readonly expires_in: number;
	/** Minimum polling interval in seconds. Defaults to 5 per RFC 8628 if omitted. */
	readonly interval?: number;
}

/** Successful token response (both initial and refresh). */
export interface XaiTokenResponse {
	readonly access_token: string;
	readonly token_type: string;
	readonly expires_in: number;
	readonly refresh_token?: string;
	readonly scope?: string;
}

/** Error response from token endpoint during polling. */
export interface XaiTokenErrorResponse {
	readonly error: string;
	readonly error_description?: string;
}

/**
 * Pure HTTP client for xAI's OAuth2 device code flow.
 * Does not perform any UI or storage operations.
 */
export class XaiOidcClient {
	constructor(
		private readonly _fetcher: IFetcherService,
		private readonly _logService: ILogService,
	) { }

	/**
	 * Initiates a device code authorization request.
	 */
	async requestDeviceCode(): Promise<XaiDeviceCodeResponse> {
		const body = new URLSearchParams({
			client_id: XAI_CLIENT_ID,
			scope: XAI_SCOPES.join(' ')
		}).toString();

		this._logService.debug(`XaiOidcClient: requesting device code from ${XAI_DEVICE_AUTH_ENDPOINT}`);

		const response = await this._fetcher.fetch(XAI_DEVICE_AUTH_ENDPOINT, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json'
			},
			body,
			callSite: 'xai-byok-device-code'
		});

		if (!response.ok) {
			const text = await response.text();
			this._logService.error(`XaiOidcClient: device code request failed ${response.status}: ${text}`);
			throw new Error(`Device code request failed: ${response.status} ${response.statusText}. Server: ${text}`);
		}

		const data = await response.json() as XaiDeviceCodeResponse;
		if (!data.device_code || !data.user_code || !data.verification_uri || typeof data.expires_in !== 'number') {
			this._logService.error('XaiOidcClient: invalid device code response', JSON.stringify(data));
			throw new Error('Invalid device code response from xAI');
		}

		this._logService.info(`XaiOidcClient: received device code, user_code=${data.user_code}`);
		return data;
	}

	/**
	 * Polls the token endpoint until the user completes authorization or timeout.
	 * Handles slow_down and authorization_pending per RFC 8628.
	 * The optional progress reporter is used to give the user visible heartbeat feedback
	 * in the notification while they complete the flow in the browser.
	 */
	async pollForToken(deviceCode: string, intervalSeconds: number, expiresInSeconds: number, cancellationToken?: vscode.CancellationToken, progress?: vscode.Progress<{ message?: string }>): Promise<XaiTokenResponse> {
		const pollIntervalMs = (intervalSeconds || 5) * 1000;
		const expiresAt = Date.now() + (expiresInSeconds * 1000);

		this._logService.info(`XaiOidcClient: starting token poll, interval=${pollIntervalMs}ms, expiresIn=${expiresInSeconds}s`);
		progress?.report({ message: vscode.l10n.t('Waiting for authorization in the browser...') });

		while (Date.now() < expiresAt) {
			if (cancellationToken?.isCancellationRequested) {
				throw new Error('Cancelled');
			}

			await new Promise(resolve => setTimeout(resolve, pollIntervalMs));

			if (cancellationToken?.isCancellationRequested) {
				throw new Error('Cancelled');
			}

			const body = new URLSearchParams({
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code: deviceCode,
				client_id: XAI_CLIENT_ID
			}).toString();

			this._logService.info(`XaiOidcClient: polling token endpoint (device_code present, interval=${pollIntervalMs}ms)`);

			const response = await this._fetcher.fetch(XAI_TOKEN_ENDPOINT, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/x-www-form-urlencoded',
					'Accept': 'application/json'
				},
				body,
				callSite: 'xai-byok-token-poll'
			});

			if (response.ok) {
				const tokenData = await response.json() as XaiTokenResponse;
				if (!tokenData.access_token || typeof tokenData.expires_in !== 'number') {
					throw new Error('Invalid token response from xAI');
				}
				this._logService.info(`XaiOidcClient: device code flow completed successfully (expires_in=${tokenData.expires_in}s, has_refresh=${!!tokenData.refresh_token})`);
				return tokenData;
			}

			// Error handling per RFC 8628 §3.5
			let errorData: XaiTokenErrorResponse | undefined;
			try {
				errorData = await response.json() as XaiTokenErrorResponse;
			} catch {
				// Non-JSON error body
			}

			const errorCode = errorData?.error || 'unknown_error';
			const errorDesc = errorData?.error_description ? ` (${errorData.error_description})` : '';

			if (errorCode === 'authorization_pending') {
				// User has not yet completed the flow — continue polling.
				// This is the expected state until the user authorizes in the browser.
				this._logService.info(`XaiOidcClient: authorization_pending from xAI${errorDesc}`);
				progress?.report({ message: vscode.l10n.t('Waiting for authorization in the browser...') });
				continue;
			} else if (errorCode === 'slow_down') {
				// Server requests we slow down — wait an extra interval
				this._logService.info(`XaiOidcClient: slow_down from xAI${errorDesc}`);
				await new Promise(resolve => setTimeout(resolve, pollIntervalMs));
				continue;
			} else if (errorCode === 'expired_token') {
				throw new Error(vscode.l10n.t('The device code has expired. Please try signing in again.'));
			} else if (errorCode === 'access_denied') {
				throw new Error(vscode.l10n.t('Sign-in was cancelled or denied.'));
			} else {
				const desc = errorData?.error_description ? `: ${errorData.error_description}` : '';
				throw new Error(`Token request failed: ${errorCode}${desc}`);
			}
		}

		throw new Error(vscode.l10n.t('Device code flow timed out. Please try signing in again.'));
	}

	/**
	 * Exchanges a refresh_token for a new access_token (and possibly new refresh_token).
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
 * High-level manager for xAI OAuth lifecycle.
 * Owns the device code sign-in UX (notification + clipboard, no modals),
 * token refresh, and persistence via the BYOK storage/auth services.
 */
export class XaiAuthManager {
	private readonly _oidcClient: XaiOidcClient;

	constructor(
		private readonly _authService: IBYOKAuthService,
		private readonly _fetcherService: IFetcherService,
		private readonly _logService: ILogService,
	) {
		this._oidcClient = new XaiOidcClient(this._fetcherService, this._logService);
	}

	/**
	 * Performs the full device code sign-in flow for xAI.
	 * Shows a non-modal notification with the user code and opens the verification URI.
	 * On success, stores the resulting tokens via the auth service.
	 */
	async signIn(): Promise<BYOKAuthRecord | undefined> {
		try {
			const deviceResp = await this._oidcClient.requestDeviceCode();

			await vscode.env.clipboard.writeText(deviceResp.user_code);

			// Prefer the complete URI (pre-fills the code on xAI's page) when available
			const uriToOpen = deviceResp.verification_uri_complete || deviceResp.verification_uri;
			await vscode.env.openExternal(vscode.Uri.parse(uriToOpen));

			const record = await vscode.window.withProgress<BYOKAuthRecord | undefined>(
				{
					location: vscode.ProgressLocation.Notification,
					title: vscode.l10n.t('Signing in to xAI...'),
					cancellable: true
				},
				async (progress, token) => {
					progress.report({
						message: vscode.l10n.t('Open {0} and paste code {1} (this can take a minute after you authorize)', deviceResp.verification_uri, deviceResp.user_code)
					});

					try {
						const tokenResp = await this._oidcClient.pollForToken(
							deviceResp.device_code,
							deviceResp.interval ?? 5,
							deviceResp.expires_in,
							token,
							progress
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

						// Store via the auth service (the intended public write path). It delegates to storage
						// and fires onDidChange so listeners (model picker, providers) can react.
						await this._authService.storeAuthRecord('xai', authRecord, BYOKAuthType.GlobalApiKey);
						this._logService.info('XaiAuthManager: OAuth tokens stored for xAI; onDidChange fired (provider listeners and direct migrate handler should react)');

						// IMPORTANT: Do NOT report a final "Signed in successfully" message on the progress
						// notification here, and do NOT show the info message while the progress task is
						// still active. Returning promptly allows the withProgress Notification to dismiss
						// cleanly (no lingering loading bar). The success confirmation is shown *after*
						// the withProgress promise resolves (see caller below). This eliminates the
						// duplicate messages the user observed.
						return authRecord;
					} catch (err) {
						if (token.isCancellationRequested) {
							return undefined;
						}
						this._logService.error('XaiAuthManager: signIn failed during polling', String(err));
						progress.report({ message: vscode.l10n.t('Sign-in failed.') });
						await vscode.window.showErrorMessage(
							vscode.l10n.t('Failed to sign in to xAI: {0}', String(err))
						);
						return undefined;
					}
				}
			);

			// Show the success confirmation *after* the withProgress resolves. This lets the
			// "Signing in to xAI..." notification dismiss cleanly (no lingering loading bar or
			// stale "Signed in successfully" message attached to the progress UI). The separate
			// info message is the single, expected success toast the user sees.
			if (record) {
				await vscode.window.showInformationMessage(
					vscode.l10n.t('Successfully signed in to xAI with OAuth.')
				);
			}
			return record;
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
