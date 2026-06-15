/**
 * WP Search Shield — Frontend Token Manager
 *
 * Handles:
 * 1. Injecting the search token into all search forms
 * 2. Intercepting fetch/XMLHttpRequest for REST API search calls
 * 3. Rotating tokens after each search (requesting a fresh one)
 *
 * @package WP_Search_Shield
 * @since 1.0.0
 */
( function () {
	'use strict';

	if ( typeof WPSearchShield === 'undefined' ) {
		return;
	}

	const config = WPSearchShield;
	let currentToken = config.token;

	/**
	 * Inject a hidden input with the current token into all search forms.
	 */
	function injectTokenIntoForms() {
		const forms = document.querySelectorAll( 'form[role="search"], form.search-form, form#searchform' );

		forms.forEach( function ( form ) {
			// Remove any existing token field.
			const existing = form.querySelector( 'input[name="' + config.param_name + '"]' );
			if ( existing ) {
				existing.value = currentToken;
				return;
			}

			// Create and inject hidden input.
			const input = document.createElement( 'input' );
			input.type = 'hidden';
			input.name = config.param_name;
			input.value = currentToken;
			form.appendChild( input );
		} );
	}

	/**
	 * Request a fresh token from the server.
	 *
	 * Called after a successful search to rotate the token
	 * so the current one can't be reused.
	 */
	async function refreshToken() {
		try {
			const response = await fetch( config.rest_url, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'X-WP-Nonce': config.nonce,
				},
			} );

			if ( response.ok ) {
				const data = await response.json();
				if ( data.token ) {
					currentToken = data.token;
					injectTokenIntoForms();
				}
			}
		} catch ( e ) {
			// Silent fail — next page load will generate a new token.
		}
	}

	/**
	 * Intercept form submissions to ensure token is fresh
	 * and request a new one after submission.
	 */
	function interceptFormSubmissions() {
		document.addEventListener( 'submit', function ( event ) {
			const form = event.target;
			const isSearch = form.querySelector( 'input[type="search"], input[name="s"]' );

			if ( ! isSearch ) {
				return;
			}

			// Ensure the token input has the latest token.
			const tokenInput = form.querySelector( 'input[name="' + config.param_name + '"]' );
			if ( tokenInput ) {
				tokenInput.value = currentToken;
			}
		} );
	}

	/**
	 * Patch the global fetch to automatically inject the search token
	 * into REST API search requests.
	 */
	function interceptFetch() {
		const originalFetch = window.fetch;

		window.fetch = async function ( input, init ) {
			let url = typeof input === 'string' ? input : input instanceof Request ? input.url : '';

			// Check if this is a search request to the REST API.
			if ( url && ( url.includes( '/wp/v2/search' ) || ( url.includes( '/wp/v2/posts' ) && url.includes( 'search=' ) ) ) ) {
				const separator = url.includes( '?' ) ? '&' : '?';
				url = url + separator + config.param_name + '=' + encodeURIComponent( currentToken );

				// Call original fetch with modified URL.
				const response = await originalFetch.call( this, url, init );

				// Rotate token after successful search.
				if ( response.ok ) {
					refreshToken();
				}

				return response;
			}

			return originalFetch.call( this, input, init );
		};
	}

	/**
	 * Patch XMLHttpRequest to inject token into legacy AJAX search requests.
	 */
	function interceptXHR() {
		const originalOpen = XMLHttpRequest.prototype.open;

		XMLHttpRequest.prototype.open = function ( method, url, ...args ) {
			if ( url && typeof url === 'string' && ( url.includes( '/wp/v2/search' ) || ( url.includes( '/wp/v2/posts' ) && url.includes( 'search=' ) ) ) ) {
				const separator = url.includes( '?' ) ? '&' : '?';
				url = url + separator + config.param_name + '=' + encodeURIComponent( currentToken );

				// Rotate token when request completes.
				this.addEventListener( 'load', function () {
					if ( this.status >= 200 && this.status < 300 ) {
						refreshToken();
					}
				} );
			}

			return originalOpen.call( this, method, url, ...args );
		};
	}

	/**
	 * Expose the current token and refresh function for custom implementations.
	 *
	 * Developers can use:
	 *   WPSearchShield.getToken()  — get the current valid token
	 *   WPSearchShield.refresh()   — manually request a new token
	 */
	config.getToken = function () {
		return currentToken;
	};
	config.refresh = refreshToken;

	// Initialize on DOM ready.
	if ( document.readyState === 'loading' ) {
		document.addEventListener( 'DOMContentLoaded', function () {
			injectTokenIntoForms();
			interceptFormSubmissions();
			interceptFetch();
			interceptXHR();
		} );
	} else {
		injectTokenIntoForms();
		interceptFormSubmissions();
		interceptFetch();
		interceptXHR();
	}

} )();
