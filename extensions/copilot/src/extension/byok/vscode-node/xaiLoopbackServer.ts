/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as http from 'http';
import { URL } from 'url';

/**
 * Minimal local loopback HTTP server for the xAI PKCE Authorization Code flow.
 *
 * This allows the shared public xAI client_id to work without requiring
 * custom vscode:// or code-oss:// redirect URIs to be pre-registered by xAI.
 *
 * The redirect_uri used is of the form:
 *   http://127.0.0.1:<random-port>/callback
 *
 * The server validates the `state` parameter (CSRF protection) and resolves
 * with the authorization code. It serves a minimal success/error page so the
 * user sees feedback in the browser tab instead of a blank page or network error.
 */
interface IOAuthResult {
	readonly code: string;
	readonly state: string;
}

export class XaiLoopbackServer {
	private readonly _server: http.Server;
	private readonly _resultPromise: Promise<IOAuthResult>;
	private _deferred!: { resolve: (result: IOAuthResult) => void; reject: (reason: any) => void };
	private _expectedState: string | undefined;
	private _hasSettled = false;
	private readonly _log: (message: string) => void;

	public port: number | undefined;

	constructor(log?: (message: string) => void) {
		this._log = log ?? (() => { /* no-op */ });

		let deferred: { resolve: (r: IOAuthResult) => void; reject: (e: any) => void };
		this._resultPromise = new Promise<IOAuthResult>((resolve, reject) => {
			deferred = { resolve, reject };
		});
		// @ts-ignore - assigned in the Promise executor before use
		this._deferred = deferred;

		this._server = http.createServer((req, res) => {
			try {
				const reqUrl = new URL(req.url ?? '/', `http://${req.headers.host ?? '127.0.0.1'}`);
				this._log(`incoming request: ${reqUrl.pathname}${reqUrl.search}`);

				if (reqUrl.pathname !== '/callback') {
					res.writeHead(404, { 'Content-Type': 'text/plain' });
					res.end('Not found');
					return;
				}

				const code = reqUrl.searchParams.get('code') ?? undefined;
				const state = reqUrl.searchParams.get('state') ?? undefined;

				if (!code || !state) {
					this._sendErrorPage(res, 'Missing code or state parameter from xAI.');
					this._safeReject(new Error('Missing code or state in callback'));
					return;
				}

				if (this._expectedState && state !== this._expectedState) {
					this._sendErrorPage(res, 'State mismatch. The sign-in request may have been tampered with.');
					this._safeReject(new Error('State mismatch (CSRF protection)'));
					return;
				}

				// Success path - only settle once
				this._safeResolve({ code, state });
				this._sendSuccessPage(res);

			} catch (err) {
				try {
					this._sendErrorPage(res, 'Unexpected error handling the xAI callback.');
				} catch { /* ignore */ }
				this._safeReject(err);
			}
		});
	}

	/**
	 * Tell the server what state value we will send in the authorize request.
	 * The callback must echo exactly this value.
	 */
	public setExpectedState(state: string): void {
		this._expectedState = state;
	}

	/**
	 * Starts listening on a random free port on 127.0.0.1.
	 * @returns The chosen port number.
	 */
	public start(): Promise<number> {
		return new Promise<number>((resolve, reject) => {
			const timeout = setTimeout(() => {
				reject(new Error('Timed out waiting for the local loopback server to start'));
			}, 5000);

			this._server.once('listening', () => {
				clearTimeout(timeout);
				const address = this._server.address();
				if (address && typeof address === 'object' && 'port' in address) {
					this.port = address.port;
					this._log(`server listening on http://127.0.0.1:${this.port}/callback`);

					// Small delay after the listening event. On some Windows configurations
					// the TCP stack is not instantly ready to accept connections from the browser.
					setTimeout(() => resolve(this.port!), 120);
				} else {
					reject(new Error('Failed to determine loopback server port'));
				}
			});

			this._server.on('error', (err: any) => {
				// Log persistent errors (e.g. EADDRINUSE after start, or request handling issues)
				this._log(`server error: ${err?.message || err}`);
				// Only reject the start promise for the initial bind failure
				if (!this.port) {
					clearTimeout(timeout);
					reject(new Error(`Failed to start loopback server: ${err?.message || err}`));
				}
			});

			this._server.listen(0, '127.0.0.1');
		});
	}

	/**
	 * Stops the server (safe to call multiple times).
	 */
	public stop(): Promise<void> {
		return new Promise<void>((resolve) => {
			if (!this._server.listening) {
				resolve();
				return;
			}
			this._log('stopping loopback server');
			this._server.close(() => resolve());
		});
	}

	/**
	 * Returns a promise that resolves when the browser hits the callback with a valid code+state.
	 * The promise rejects on state mismatch, timeout, or server error.
	 */
	public waitForOAuthResponse(): Promise<IOAuthResult> {
		return this._resultPromise;
	}

	private _safeResolve(result: IOAuthResult) {
		if (!this._hasSettled) {
			this._hasSettled = true;
			this._deferred.resolve(result);
		}
	}

	private _safeReject(reason: any) {
		if (!this._hasSettled) {
			this._hasSettled = true;
			this._deferred.reject(reason);
		}
	}

	private _sendSuccessPage(res: http.ServerResponse): void {
		this._log('serving success page');
		const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>xAI Sign-In</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: center; padding: 40px; background: #0d1117; color: #c9d1d9;">
	<h2 style="color:#58a6ff;">✓ xAI sign-in complete</h2>
	<p>You can now close this browser tab and return to VS Code.</p>
	<p style="font-size: 0.9em; opacity: 0.7;">The authorization code has been securely delivered to the extension.</p>
</body>
</html>`;
		res.writeHead(200, {
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Length': Buffer.byteLength(html)
		});
		res.end(html);
	}

	private _sendErrorPage(res: http.ServerResponse, message: string): void {
		this._log(`serving error page: ${message}`);
		const html = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>xAI Sign-In Error</title></head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; text-align: center; padding: 40px; background: #0d1117; color: #c9d1d9;">
	<h2 style="color:#f85149;">xAI sign-in failed</h2>
	<p>${message}</p>
	<p style="font-size: 0.9em; opacity: 0.7;">You can close this tab and try the sign-in again from VS Code.</p>
</body>
</html>`;
		res.writeHead(400, {
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Length': Buffer.byteLength(html)
		});
		res.end(html);
	}
}
