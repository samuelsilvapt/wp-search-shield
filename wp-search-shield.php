<?php
/**
 * Plugin Name: WP Search Shield
 * Plugin URI:  https://github.com/samuelsilva/wp-search-shield
 * Description: Protects the WordPress search endpoint from DDoS attacks using single-use tokens and IP-based rate limiting. Inspired by the talk "The Hidden DDoS Threat in WordPress" at WordCamp Europe 2026.
 * Version:     1.0.0
 * Author:      Samuel Silva
 * Author URI:  https://samuelsilva.pt
 * License:     GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-search-shield
 * Requires at least: 5.0
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPSS_VERSION', '1.0.0' );
define( 'WPSS_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPSS_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

/**
 * Main plugin class.
 *
 * Implements two layers of protection for the WordPress search endpoint:
 *
 * 1. Single-Use Tokens: Each page load generates a unique token that is valid
 *    for one search request only. After use, the token is invalidated and a
 *    new one is returned. Bots that extract the token from HTML can only use
 *    it once — they'd need to reload the full page for each search request,
 *    which defeats the purpose of a DDoS attack.
 *
 * 2. IP Rate Limiting: Tracks search requests per IP address using transients.
 *    Even if an attacker manages to rotate tokens, they're still limited to a
 *    configurable number of searches per time window.
 */
class WP_Search_Shield {

	/**
	 * Maximum search requests per IP per time window.
	 *
	 * @var int
	 */
	private int $rate_limit;

	/**
	 * Time window for rate limiting in seconds.
	 *
	 * @var int
	 */
	private int $rate_window;

	/**
	 * Token time-to-live in seconds.
	 *
	 * @var int
	 */
	private int $token_ttl;

	/**
	 * Whether to protect traditional (non-REST) search.
	 *
	 * @var bool
	 */
	private bool $protect_traditional;

	/**
	 * Whether to protect REST API search.
	 *
	 * @var bool
	 */
	private bool $protect_rest;

	/**
	 * Initialize the plugin.
	 */
	public function __construct() {
		$this->rate_limit          = apply_filters( 'wpss_rate_limit', 10 );
		$this->rate_window         = apply_filters( 'wpss_rate_window', 60 );
		$this->token_ttl           = apply_filters( 'wpss_token_ttl', 300 );
		$this->protect_traditional = apply_filters( 'wpss_protect_traditional_search', true );
		$this->protect_rest        = apply_filters( 'wpss_protect_rest_search', true );

		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'rest_api_init', array( $this, 'register_token_endpoint' ) );

		if ( $this->protect_traditional ) {
			add_action( 'pre_get_posts', array( $this, 'protect_traditional_search' ) );
		}

		if ( $this->protect_rest ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'protect_rest_search' ), 10, 3 );
		}
	}

	/**
	 * Enqueue frontend JavaScript and pass token + configuration.
	 */
	public function enqueue_assets(): void {
		if ( is_admin() ) {
			return;
		}

		$token = $this->generate_token();

		wp_enqueue_script(
			'wp-search-shield',
			WPSS_PLUGIN_URL . 'assets/js/search-shield.js',
			array(),
			WPSS_VERSION,
			true
		);

		wp_localize_script( 'wp-search-shield', 'WPSearchShield', array(
			'token'        => $token,
			'rest_url'     => rest_url( 'wpss/v1/token' ),
			'nonce'        => wp_create_nonce( 'wp_rest' ),
			'param_name'   => apply_filters( 'wpss_token_param_name', '_search_token' ),
		) );
	}

	/**
	 * Register the REST endpoint for token refresh.
	 */
	public function register_token_endpoint(): void {
		register_rest_route( 'wpss/v1', '/token', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'handle_token_refresh' ),
			'permission_callback' => '__return_true',
		) );
	}

	/**
	 * Handle token refresh requests.
	 *
	 * Called after a search is completed to provide a fresh token
	 * for the next search request.
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response
	 */
	public function handle_token_refresh( WP_REST_Request $request ): WP_REST_Response {
		$new_token = $this->generate_token();

		return new WP_REST_Response( array(
			'token' => $new_token,
		), 200 );
	}

	/**
	 * Protect traditional WordPress search (/?s=query).
	 *
	 * Hooks into pre_get_posts to validate the token and check rate limits
	 * before the search query is executed.
	 *
	 * @param WP_Query $query The query object.
	 */
	public function protect_traditional_search( WP_Query $query ): void {
		if ( is_admin() || ! $query->is_main_query() || ! $query->is_search() ) {
			return;
		}

		$param_name = apply_filters( 'wpss_token_param_name', '_search_token' );
		$token      = isset( $_REQUEST[ $param_name ] ) ? sanitize_text_field( wp_unslash( $_REQUEST[ $param_name ] ) ) : '';
		$ip         = $this->get_client_ip();

		// Check rate limit first (cheapest check).
		if ( $this->is_rate_limited( $ip ) ) {
			$this->block_query( $query, 'rate_limited' );
			return;
		}

		// Validate and consume the token.
		if ( ! $this->validate_and_consume_token( $token ) ) {
			$this->block_query( $query, 'invalid_token' );
			return;
		}

		// Track the request for rate limiting.
		$this->track_request( $ip );
	}

	/**
	 * Protect REST API search endpoint (/wp-json/wp/v2/search).
	 *
	 * @param mixed           $result  Response to replace the requested version with.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Request used to generate the response.
	 * @return mixed
	 */
	public function protect_rest_search( $result, WP_REST_Server $server, WP_REST_Request $request ) {
		$route = $request->get_route();

		// Only protect search-related endpoints.
		$search_routes = apply_filters( 'wpss_protected_rest_routes', array(
			'/wp/v2/search',
			'/wp/v2/posts',
		) );

		$is_search = false;
		foreach ( $search_routes as $search_route ) {
			if ( str_starts_with( $route, $search_route ) && $request->get_param( 'search' ) ) {
				$is_search = true;
				break;
			}
		}

		if ( ! $is_search ) {
			return $result;
		}

		$param_name = apply_filters( 'wpss_token_param_name', '_search_token' );
		$token      = $request->get_param( $param_name ) ?? $request->get_header( 'X-Search-Token' ) ?? '';
		$ip         = $this->get_client_ip();

		// Check rate limit.
		if ( $this->is_rate_limited( $ip ) ) {
			return new WP_Error(
				'wpss_rate_limited',
				__( 'Too many search requests. Please try again later.', 'wp-search-shield' ),
				array( 'status' => 429 )
			);
		}

		// Validate and consume token.
		if ( ! $this->validate_and_consume_token( $token ) ) {
			return new WP_Error(
				'wpss_invalid_token',
				__( 'Invalid or expired search token.', 'wp-search-shield' ),
				array( 'status' => 403 )
			);
		}

		// Track the request.
		$this->track_request( $ip );

		return $result;
	}

	/**
	 * Generate a single-use token and store it as a transient.
	 *
	 * @return string The generated token.
	 */
	private function generate_token(): string {
		$token = wp_generate_password( 40, false, false );
		$key   = $this->get_token_key( $token );

		set_transient( $key, array(
			'created' => time(),
			'ip'      => $this->get_client_ip(),
		), $this->token_ttl );

		return $token;
	}

	/**
	 * Validate a token and consume it (delete after use).
	 *
	 * @param string $token The token to validate.
	 * @return bool Whether the token was valid.
	 */
	private function validate_and_consume_token( string $token ): bool {
		if ( empty( $token ) ) {
			return false;
		}

		$key  = $this->get_token_key( $token );
		$data = get_transient( $key );

		if ( false === $data ) {
			return false;
		}

		// Token is valid — consume it immediately so it can't be reused.
		delete_transient( $key );

		return true;
	}

	/**
	 * Check if an IP address has exceeded the rate limit.
	 *
	 * @param string $ip The IP address.
	 * @return bool Whether the IP is rate limited.
	 */
	private function is_rate_limited( string $ip ): bool {
		$key  = $this->get_rate_key( $ip );
		$data = get_transient( $key );

		if ( false === $data ) {
			return false;
		}

		return $data['count'] >= $this->rate_limit;
	}

	/**
	 * Track a search request for rate limiting.
	 *
	 * @param string $ip The IP address.
	 */
	private function track_request( string $ip ): void {
		$key  = $this->get_rate_key( $ip );
		$data = get_transient( $key );

		if ( false === $data ) {
			$data = array(
				'count'    => 0,
				'window'   => time(),
			);
		}

		$data['count']++;

		set_transient( $key, $data, $this->rate_window );
	}

	/**
	 * Block a search query by returning no results.
	 *
	 * @param WP_Query $query  The query to block.
	 * @param string   $reason The reason for blocking.
	 */
	private function block_query( WP_Query $query, string $reason ): void {
		$query->set( 'post__in', array( 0 ) );
		$query->set( 's', '' );

		status_header( 'rate_limited' === $reason ? 429 : 403 );

		/**
		 * Fires when a search request is blocked.
		 *
		 * @param string   $reason The reason for blocking (rate_limited or invalid_token).
		 * @param string   $ip     The client IP address.
		 * @param WP_Query $query  The blocked query.
		 */
		do_action( 'wpss_search_blocked', $reason, $this->get_client_ip(), $query );
	}

	/**
	 * Get the transient key for a token.
	 *
	 * @param string $token The token.
	 * @return string The transient key.
	 */
	private function get_token_key( string $token ): string {
		return 'wpss_token_' . substr( hash( 'sha256', $token ), 0, 20 );
	}

	/**
	 * Get the transient key for rate limiting.
	 *
	 * @param string $ip The IP address.
	 * @return string The transient key.
	 */
	private function get_rate_key( string $ip ): string {
		return 'wpss_rate_' . substr( hash( 'sha256', $ip . AUTH_SALT ), 0, 16 );
	}

	/**
	 * Get the client IP address.
	 *
	 * Checks common proxy headers and falls back to REMOTE_ADDR.
	 *
	 * @return string The client IP address.
	 */
	private function get_client_ip(): string {
		$headers = array(
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_FORWARDED_FOR',
			'HTTP_X_REAL_IP',
			'REMOTE_ADDR',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$ip = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// X-Forwarded-For can contain multiple IPs — take the first.
				if ( str_contains( $ip, ',' ) ) {
					$ip = trim( explode( ',', $ip )[0] );
				}
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					return $ip;
				}
			}
		}

		return '0.0.0.0';
	}
}

// Initialize the plugin.
new WP_Search_Shield();
