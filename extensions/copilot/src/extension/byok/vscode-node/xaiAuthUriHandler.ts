/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { ILogService } from '../../../platform/log/common/logService';
/**
 * Custom URI handler interface used inside the Copilot extension for sub-dispatching.
 * Matches the pattern established by ChatSessionsUriHandler.
 */
export type CustomUriHandler = vscode.UriHandler & { canHandleUri(uri: vscode.Uri): boolean };

/**
 * Minimal PromiseAdapter + promiseFromEvent implementation.
 * Vendored here to keep xAI auth self-contained and avoid depending on
 * github-authentication's internal utilities.
 */
export type PromiseAdapter<T, U> = (value: T, resolve: (value: U | PromiseLike<U>) => void, reject: (reason: any) => void) => any;

const passthrough = (value: any, resolve: (value?: any) => void) => resolve(value);

export function promiseFromEvent<T, U>(
	event: vscode.Event<T>,
	adapter: PromiseAdapter<T, U> = passthrough
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
	private readonly _pendingStates = new Map<string, string[]>();
	private readonly _codeExchangePromises = new Map<string, { promise: Promise<string>; cancel: vscode.EventEmitter<void> }>();

	constructor(
		@ILogService private readonly _logService: ILogService
	) {
		super();
	}

	/**
	 * Returns true if this handler should process the given URI.
	 * Used by the top-level dispatcher (CopilotDebugCommandContribution).
	 */
	public canHandleUri(uri: vscode.Uri): boolean {
		return uri.path === '/xai-auth' || uri.path === '/xai-auth/';
	}

	/**
	 * Entry point from the top-level UriHandler.
	 * Fires the event so any waitForAuthorizationCode listeners can react.
	 */
	public handleUri(uri: vscode.Uri): vscode.ProviderResult<void> {
		this.fire(uri);
	}

	/**
	 * Waits for the OAuth authorization code to arrive via the vscode:// redirect.
	 *
	 * The caller (XaiAuthManager) is responsible for:
	 *  - Generating a cryptographically random `state`
	 *  - Building the authorize URL with that state (and PKCE params)
	 *  - Calling asExternalUri on a vscode://github.copilot/xai-auth?state=... URI
	 *  - Opening the resulting URL in the browser
	 *  - Passing the same state here
	 *
	 * This method will resolve with the `code` from the IdP when the redirect arrives
	 * and the state matches, or reject on timeout / cancellation / error.
	 */
	public async waitForAuthorizationCode(state: string, token: vscode.CancellationToken): Promise<string> {
		const existingStates = this._pendingStates.get(state) || [];
		this._pendingStates.set(state, [...existingStates, state]);

		let codeExchangePromise = this._codeExchangePromises.get(state);
		if (!codeExchangePromise) {
			codeExchangePromise = promiseFromEvent(this.event, this.handleAuthorizationEvent(state));
			this._codeExchangePromises.set(state, codeExchangePromise);
		}

		const FIVE_MINUTES = 300_000;

		try {
			return await Promise.race([
				codeExchangePromise.promise,
				new Promise<string>((_, reject) =>
					setTimeout(() => reject(new Error('Authorization timed out')), FIVE_MINUTES)
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

			const acceptedStates = this._pendingStates.get(expectedState) || [];
			if (!acceptedStates.includes(returnedState)) {
				// Another sign-in flow is in progress with a different state.
				// This is normal if the user triggers multiple flows quickly.
				this._logService?.info?.('XAI Auth: State mismatch or not the expected pending state. Ignoring this redirect.');
				return;
			}

			resolve(code);
		};
}

/**
 * Module-level singleton accessor.
 * Allows both BYOKContrib (to pass to XaiAuthManager) and the debug contribution
 * (for URI dispatch registration) to obtain the same instance without complex DI wiring
 * in the first implementation pass.
 *
 * The instance is lazily created when first requested.
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
