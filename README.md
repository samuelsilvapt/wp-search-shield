# WP Search Shield 🛡️

**Protect your WordPress search endpoint from DDoS attacks using single-use tokens and IP-based rate limiting.**

Inspired by the talk *"The Hidden DDoS Threat in WordPress: Abusing the Search Endpoint"* at WordCamp Europe 2026 by [Samuel Silva](https://samuelsilva.pt).

## The Problem

Every WordPress site has a search endpoint (`/?s=`) that **bypasses CDN and cache entirely**. Each search query hits the database directly with a `LIKE '%query%'` full table scan. An attacker can flood this endpoint with random queries to overwhelm your database — no botnet required.

Your CDN protects static pages. Your object cache stores known queries. But **random search strings bypass everything**.

## The Solution

WP Search Shield adds two layers of protection:

### 1. 🎟️ Single-Use Tokens
- A unique token is generated on every page load
- Each token is valid for **one search request only**
- After use, the token is consumed and a fresh one is issued
- Attackers can't extract a token from HTML and reuse it — it's already dead after one use

### 2. 🚦 IP Rate Limiting
- Tracks search requests per IP using WordPress transients
- Configurable limit (default: 10 requests per 60 seconds)
- Returns `429 Too Many Requests` when exceeded
- Even with valid tokens, automated attacks are throttled

### Combined Effect

| Attack Vector | Without Plugin | With Plugin |
|---|---|---|
| Bot hits `/?s=random` directly | ✅ Hits database | ❌ 403 — No token |
| Bot extracts token, sends 1000 requests | ✅ All hit database | ❌ First works, rest get 403 — token consumed |
| Bot extracts token + refreshes each time | ✅ All hit database | ❌ Rate limited after 10 requests |
| Real user searches normally | ✅ Works | ✅ Works seamlessly |

## Installation

1. Download or clone this repository
2. Upload the `wp-search-shield` folder to `/wp-content/plugins/`
3. Activate the plugin in WordPress admin
4. That's it — protection is active immediately

```bash
cd wp-content/plugins/
git clone https://github.com/samuelsilva/wp-search-shield.git
```

## Configuration

The plugin works out of the box with sensible defaults. All settings are configurable via filters in your theme's `functions.php` or a custom plugin:

```php
// Maximum search requests per IP per time window (default: 10)
add_filter( 'wpss_rate_limit', function() { return 20; } );

// Time window in seconds (default: 60)
add_filter( 'wpss_rate_window', function() { return 120; } );

// Token time-to-live in seconds (default: 300)
add_filter( 'wpss_token_ttl', function() { return 180; } );

// Disable protection for traditional search (default: true)
add_filter( 'wpss_protect_traditional_search', '__return_false' );

// Disable protection for REST API search (default: true)
add_filter( 'wpss_protect_rest_search', '__return_false' );

// Custom token parameter name (default: _search_token)
add_filter( 'wpss_token_param_name', function() { return '_st'; } );

// Add custom REST routes to protect
add_filter( 'wpss_protected_rest_routes', function( $routes ) {
    $routes[] = '/wp/v2/custom-post-type';
    return $routes;
} );
```

## How It Works

### Token Lifecycle

```
Page Load → Generate Token → Store in Transient (5 min TTL)
                ↓
         Inject in HTML (hidden input in search forms)
         Pass to JS (for REST API / AJAX search)
                ↓
User Searches → Token sent with request
                ↓
Server validates → Token exists in transients?
                ↓
         YES → Delete token (consumed!) → Execute search → JS requests new token
         NO  → Block request (403)
```

### Rate Limiting

```
Search Request → Check IP hash in transients
                    ↓
              Count < Limit? → Allow + Increment counter
              Count >= Limit? → Block (429 Too Many Requests)
                    ↓
              Counter resets after time window expires
```

## Hooks & Actions

### `wpss_search_blocked` Action

Fires when a search request is blocked. Useful for logging or monitoring.

```php
add_action( 'wpss_search_blocked', function( $reason, $ip, $query ) {
    error_log( sprintf(
        '[WP Search Shield] Blocked search from %s — Reason: %s',
        $ip,
        $reason // 'rate_limited' or 'invalid_token'
    ) );
}, 10, 3 );
```

## For Custom Search Implementations

If your theme uses a custom AJAX/fetch search, the plugin automatically patches `fetch()` and `XMLHttpRequest` to inject tokens into REST API search calls.

For fully custom implementations, you can access the token via JavaScript:

```js
// Get the current valid token
const token = WPSearchShield.getToken();

// Manually refresh the token (call after a search)
await WPSearchShield.refresh();

// Use in a custom fetch call
fetch( '/wp-json/wp/v2/search?search=query&_search_token=' + token );
```

## Compatibility

- **WordPress**: 5.0+
- **PHP**: 7.4+
- **Caching Plugins**: Compatible with all major caching plugins (WP Super Cache, W3 Total Cache, LiteSpeed Cache). Token generation happens on dynamic page loads.
- **CDN**: Works with Cloudflare, Fastly, and any CDN. Tokens are unique per page load.
- **REST API**: Protects both traditional `/?s=` search and REST API `/wp-json/wp/v2/search` endpoints.

## FAQ

**Q: Does this break SEO?**
A: Search engine crawlers don't use the search endpoint for indexing. Your content is indexed through sitemaps and direct page crawling.

**Q: What if JavaScript is disabled?**
A: Traditional form-based search still works — the token is injected as a hidden form field on page load via PHP.

**Q: Will this slow down my site?**
A: No. The plugin uses WordPress transients (stored in your object cache if available) for both tokens and rate limiting. The overhead is negligible — a single transient read/write per search request.

**Q: Does this replace a WAF?**
A: No. This plugin specifically protects the search endpoint. A WAF provides broader protection. They complement each other.

## Credits

- **Author**: [Samuel Silva](https://samuelsilva.pt)
- **Talk**: [The Hidden DDoS Threat in WordPress](https://europe.wordcamp.org/2026/) — WordCamp Europe 2026
- **License**: GPL-2.0-or-later

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Changelog

### 1.0.0
- Initial release
- Single-use token system
- IP-based rate limiting
- REST API and traditional search protection
- Automatic fetch/XHR interception
