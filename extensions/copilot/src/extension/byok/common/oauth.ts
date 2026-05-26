/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { IFetcherService } from '../../../platform/networking/common/fetcherService';
import { ILogService } from '../../../platform/log/common/logService';

// HTTP method, header, and callSite constants for the OAuth/OIDC client.
const OIDC_WELL_KNOWN_PATH = '/.well-known/openid-configuration';
const CONTENT_TYPE_FORM_URLENCODED = 'application/x-www-form-urlencoded';
const ACCEPT_JSON = 'application/json';
const CALL_SITE_OIDC_DISCOVERY = 'byok-oidc-discovery';
const CALL_SITE_PKCE_EXCHANGE = 'byok-pkce-exchange';
const CALL_SITE_REFRESH = 'byok-refresh';
const METHOD_GET = 'GET';
const METHOD_POST = 'POST';

/**
 * Successful token response (both initial authorization code exchange and refresh).
 */
export interface TokenResponse {
	readonly access_token: string;
	readonly token_type: string;
	readonly expires_in: number;
	readonly refresh_token?: string;
	readonly scope?: string;
}

/**
 * Configuration for a single OAuth/OIDC provider using the Authorization Code + PKCE flow.
 */
export interface OAuthProviderConfig {
	/** OIDC issuer, e.g. 'https://auth.x.ai'. Discovery is performed at `${issuer}/.well-known/openid-configuration`. */
	readonly issuer: string;

	/** Public client_id (not a secret). */
	readonly clientId: string;

	/** Scopes to request. */
	readonly scopes: readonly string[];
}

/**
 * Cryptographic helpers for PKCE (RFC 7636) with S256 code challenge method.
 * These are pure and have no service dependencies so they can be used by any OAuth flow.
 */
export async function generateCodeVerifier(): Promise<string> {
	const array = new Uint8Array(32);
	crypto.getRandomValues(array);
	return base64UrlEncode(array);
}

export function base64UrlEncode(buffer: Uint8Array): string {
	return btoa(String.fromCharCode(...buffer))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
}

export async function generateCodeChallenge(verifier: string): Promise<string> {
	const encoder = new TextEncoder();
	const data = encoder.encode(verifier);
	const digest = await crypto.subtle.digest('SHA-256', data);
	return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Reusable thin client for the OAuth2 Authorization Code flow with PKCE (RFC 7636)
 * combined with OIDC discovery.
 *
 * This class performs only the network calls (discovery + token exchange + refresh).
 * It does not handle UI, browser launching, redirect URI handling, or storage.
 *
 * Future BYOK OAuth providers can instantiate this with their own {@link OAuthProviderConfig}
 * instead of copying the PKCE and discovery logic.
 */
export class AuthorizationCodePkceClient {
	constructor(
		private readonly _fetcher: IFetcherService,
		private readonly _logService: ILogService,
		private readonly _provider: OAuthProviderConfig
	) { }

	/**
	 * Performs OIDC discovery against the well-known endpoint (hard fail, no fallback).
	 * Returns the authorization and token endpoints from the metadata.
	 */
	async discoverAuthorizationServer(): Promise<{ authorizationEndpoint: string; tokenEndpoint: string }> {
		const wellKnown = `${this._provider.issuer}${OIDC_WELL_KNOWN_PATH}`;
		this._logService.debug(`AuthorizationCodePkceClient: performing OIDC discovery from ${wellKnown}`);

		const response = await this._fetcher.fetch(wellKnown, {
			method: METHOD_GET,
			headers: { 'Accept': ACCEPT_JSON },
			callSite: CALL_SITE_OIDC_DISCOVERY
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
			throw new Error('Invalid OIDC discovery document (missing endpoints)');
		}

		this._logService.info('AuthorizationCodePkceClient: OIDC discovery succeeded');
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
	): Promise<TokenResponse> {
		const body = new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			redirect_uri: redirectUri,
			client_id: this._provider.clientId,
			code_verifier: codeVerifier
		}).toString();

		this._logService.debug('AuthorizationCodePkceClient: exchanging authorization code for tokens');

		const response = await this._fetcher.fetch(tokenEndpoint, {
			method: METHOD_POST,
			headers: {
				'Content-Type': CONTENT_TYPE_FORM_URLENCODED,
				'Accept': ACCEPT_JSON
			},
			body,
			callSite: CALL_SITE_PKCE_EXCHANGE
		});

		if (!response.ok) {
			const text = await response.text();
			this._logService.error(`AuthorizationCodePkceClient: code exchange failed ${response.status}: ${text}`);
			throw new Error(`Authorization code exchange failed: ${response.status}. Server: ${text}`);
		}

		const tokenData = await response.json() as TokenResponse;
		if (!tokenData.access_token || typeof tokenData.expires_in !== 'number') {
			throw new Error('Invalid token response');
		}

		this._logService.info('AuthorizationCodePkceClient: PKCE authorization code exchange succeeded');
		return tokenData;
	}

	/**
	 * Exchanges a refresh_token for a new access_token.
	 * @param tokenEndpoint Optional explicit endpoint; falls back to the one from the last discovery
	 * or a provider-specific default if the caller maintains one.
	 */
	async refreshAccessToken(refreshToken: string, tokenEndpoint: string): Promise<TokenResponse> {
		const body = new URLSearchParams({
			grant_type: 'refresh_token',
			refresh_token: refreshToken,
			client_id: this._provider.clientId
		}).toString();

		this._logService.debug('AuthorizationCodePkceClient: refreshing access token');

		const response = await this._fetcher.fetch(tokenEndpoint, {
			method: METHOD_POST,
			headers: {
				'Content-Type': CONTENT_TYPE_FORM_URLENCODED,
				'Accept': ACCEPT_JSON
			},
			body,
			callSite: CALL_SITE_REFRESH
		});

		if (!response.ok) {
			const text = await response.text();
			this._logService.error(`AuthorizationCodePkceClient: refresh failed ${response.status}: ${text}`);
			throw new Error(`Token refresh failed: ${response.status}. Server: ${text}`);
		}

		const tokenData = await response.json() as TokenResponse;
		if (!tokenData.access_token || typeof tokenData.expires_in !== 'number') {
			throw new Error('Invalid refresh response');
		}

		this._logService.info('AuthorizationCodePkceClient: token refresh succeeded');
		return tokenData;
	}
}
