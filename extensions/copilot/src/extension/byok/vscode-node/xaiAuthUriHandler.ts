/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { ILogService } from '../../../platform/log/common/logService';
import { CustomUriHandler } from '../../chatSessions/vscode/chatSessionsUriHandler';

/** 5 minute timeout for OAuth authorization code exchange (matches other flows and the refresh threshold). */
const FIVE_MINUTES_MS = 5 * 60 * 1000;

/**
 * Internal adapter + promise helper for waiting on a single VS Code event (e.g. URI callback).
 * Based on the established pattern in github-authentication and chat sessions.
 */
type PromiseAdapter<T, U> = (value: T, resolve: (value: U | PromiseLike<U>) => void, reject: (reason: unknown) => void) => unknown;

function promiseFromEvent<T, U>(
	event: vscode.Event<T>,
	adapter: PromiseAdapter<T, U>
): { promise: Promise<U>; cancel: vscode.EventEmitter<void> } {
	let subscription: vscode.Disposable;
	const cancel = new vscode.EventEmitter<void>();
	return {
		promise: new Promise<U>((resolve, reject) => {
			cancel.event(_ => reject('Cancelled'));
			subscription = event((value: T) => {
				try {
					Promise.resolve(adapter(value, resolve, reject)).catch(reject);
				} catch (error) {
					reject(error);
				}
			});
		}).then(
			(result: U) => {
				subscription.dispose();
				return result;
			},
			error => {
				subscription.dispose();
				throw error;
			}
		),
		cancel
	};
}

/**
 * XaiAuthUriHandler
 *
 * Implements the VS Code "full pattern" for OAuth callback handling inside the
 * GitHub Copilot extension:
 *
 * - Registered (via delegation) through the existing top-level UriHandler
 *   (CopilotDebugCommandContribution) so we do not violate the single-handler rule.
 * - Uses vscode.env.asExternalUri to produce a callback URI that works for
 *   local, remote, and web scenarios.
 * - Provides a `waitForAuthorizationCode` method that the XaiAuthManager will
 *   use during the PKCE Authorization Code flow.
 * - Validates the `state` parameter to prevent CSRF / mix-up attacks.
 * - Supports cancellation and has a hard 5-minute timeout (matching github-auth).
 *
 * The redirect path used is `github.copilot/xai-auth`.
 * Example callback after asExternalUri:
 *   vscode://github.copilot/xai-auth?code=...&state=...
 *
 * This handler is intentionally decoupled from the actual token exchange logic.
 * It only bridges the browser redirect back into the extension.
 */
export class XaiAuthUriHandler extends vscode.EventEmitter<vscode.Uri> implements CustomUriHandler {
	private readonly _pendingStates = new Set<string>();
	private readonly _codeExchangePromises = new Map<string, { promise: Promise<string>; cancel: vscode.EventEmitter<void> }>();

	constructor(private readonly _logService: ILogService) {
		super();
	}

	/**
	 * Returns true if this handler should process the given URI.
	 * Used by the top-level dispatcher (CopilotDebugCommandContribution).
	 */
	public canHandleUri(uri: vscode.Uri): boolean {
		// Normalize trailing slash for robustness (some redirect URIs may include it).
		const normalizedPath = uri.path.endsWith('/') ? uri.path.slice(0, -1) : uri.path;
		return normalizedPath === '/xai-auth';
	}

	/**
	 * Entry point from the top-level UriHandler.
	 * Fires the event so any waitForAuthorizationCode listeners can react.
	 */
	public handleUri(uri: vscode.Uri): vscode.ProviderResult<void> {
		this.fire(uri);
	}

	/**
	 * Waits for the OAuth authorization code (with state validation to mitigate CSRF).
	 * Resolves with the code on valid redirect, or rejects on timeout/cancel/error.
	 * 5-minute timeout matches other OAuth flows in the codebase.
	 */
	public async waitForAuthorizationCode(state: string, token: vscode.CancellationToken): Promise<string> {
		this._pendingStates.add(state);

		let codeExchangePromise = this._codeExchangePromises.get(state);
		if (!codeExchangePromise) {
			codeExchangePromise = promiseFromEvent(this.event, this.handleAuthorizationEvent(state));
			this._codeExchangePromises.set(state, codeExchangePromise);
		}

		try {
			return await Promise.race([
				codeExchangePromise.promise,
				new Promise<string>((_, reject) =>
					setTimeout(() => reject(new Error('Authorization timed out')), FIVE_MINUTES_MS)
				),
				promiseFromEvent<void, string>(
					token.onCancellationRequested,
					(_, __, reject) => reject(new Error('User cancelled'))
				).promise
			]);
		} finally {
			this._pendingStates.delete(state);
			codeExchangePromise?.cancel.fire();
			this._codeExchangePromises.delete(state);
		}
	}

	private handleAuthorizationEvent: (state: string) => PromiseAdapter<vscode.Uri, string> =
		(expectedState) => (uri, resolve, reject) => {
			const query = new URLSearchParams(uri.query);
			const code = query.get('code');
			const returnedState = query.get('state');

			if (!code) {
				reject(new Error('No authorization code in redirect'));
				return;
			}
			if (!returnedState) {
				reject(new Error('No state parameter in redirect'));
				return;
			}

			if (!this._pendingStates.has(returnedState)) {
				// Another sign-in flow is in progress with a different state.
				// This is normal if the user triggers multiple flows quickly.
				this._logService?.info?.('XAI Auth: State mismatch or not the expected pending state. Ignoring this redirect.');
				return;
			}

			this._pendingStates.delete(returnedState);
			resolve(code);
		};
}

/**
 * Singleton for the xAI URI handler.
 * Required because the handler must be registered for URI dispatch (in CopilotDebugCommandContribution)
 * and also passed to XaiAuthManager (in BYOKContrib). Created lazily on first use.
 */
let _xaiAuthUriHandler: XaiAuthUriHandler | undefined;

export function getXaiAuthUriHandler(logService: ILogService): XaiAuthUriHandler {
	if (!_xaiAuthUriHandler) {
		_xaiAuthUriHandler = new XaiAuthUriHandler(logService);
	}
	return _xaiAuthUriHandler;
}

/**
 * For testing / reset only.
 */
export function _resetXaiAuthUriHandlerForTests(): void {
	_xaiAuthUriHandler = undefined;
}
