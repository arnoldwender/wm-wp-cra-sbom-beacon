<?php
/**
 * Standalone test suite for wm-cra-sbom-beacon. No WordPress, no MySQL.
 *
 * The mock $wpdb evaluates the statements the plugin sends (prepared %s/%d/%i, SHOW TABLES, COUNT, ordered
 * selects, a WHERE on tracking_id, DROP TABLE) and throws on anything else, so a query the mock does not
 * understand fails the run instead of returning a harmless default. A PHP warning or notice fails the run too.
 *
 *   php tests/test-suite.php          exit 0 = green
 *   bash tests/run-mutations.sh       each entry in tests/mutations.php undoes one fix; the suite must turn red
 *
 * @package WMCyber\CRA
 */

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

define('ABSPATH', dirname(__DIR__) . '/');
define('WM_CRA_VERSION', '1.2.2');
define('WM_CRA_TESTING', true);
define('WM_CRA_FILE', dirname(__DIR__) . '/wm-cra-sbom-beacon.php');
define('WM_CRA_PATH', dirname(__DIR__) . '/');
define('WM_CRA_URL', 'https://demo.example.test/wp-content/plugins/wm-cra-sbom-beacon/');
define('DAY_IN_SECONDS', 86400);
define('YEAR_IN_SECONDS', 365 * 86400);
define('WP_PLUGIN_DIR', sys_get_temp_dir() . '/wm-cra-suite-plugins');
define('SUITE_THEMES', sys_get_temp_dir() . '/wm-cra-suite-themes');
define('ARRAY_A', 'ARRAY_A');
define('OBJECT', 'OBJECT');

// -----------------------------------------------------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------------------------------------------------
$GLOBALS['passed_count'] = 0;
$GLOBALS['failed_count'] = 0;

function assert_test(string $name, bool $condition, string $details = ''): void {
    if ($condition) {
        echo "  [PASS] {$name}\n";
        $GLOBALS['passed_count']++;
    } else {
        echo "  [FAIL] {$name}" . ('' !== $details ? ": {$details}" : '') . "\n";
        $GLOBALS['failed_count']++;
    }
}

set_error_handler(static function (int $errno, string $errstr, string $file, int $line): bool {
    if (!(error_reporting() & $errno)) {
        return false; // silenced with @ on purpose (e.g. the CLI checks the return value of file_put_contents)
    }
    assert_test('no PHP warning or notice', false, "{$errstr} in " . basename($file) . ":{$line}");
    return true;
});

function render(callable $fn): string {
    ob_start();
    $fn();
    return (string) ob_get_clean();
}

// -----------------------------------------------------------------------------------------------------------------
// Mock database
// -----------------------------------------------------------------------------------------------------------------
final class Mock_WPDB_CRA {
    public string $prefix = 'wp_';
    public int $insert_id = 0;
    public string $last_error = '';
    /** @var array<string, array<int, array<string, mixed>>> */
    public array $tables = [];
    /** @var array<string, int> */
    private array $auto = [];
    public bool $fail_writes = false;
    /** @var list<string> */
    public array $queries = [];

    public function get_charset_collate(): string { return 'DEFAULT CHARSET=utf8mb4'; }
    public function esc_like(string $text): string { return addcslashes($text, '_%\\'); }

    public function prepare(string $query, ...$args): string {
        if (1 === count($args) && is_array($args[0])) {
            $args = $args[0];
        }
        $i = 0;
        return (string) preg_replace_callback('/%[sdif]/', static function (array $m) use (&$i, $args): string {
            $v = $args[$i++] ?? null;
            return match ($m[0]) {
                '%i' => '`' . str_replace('`', '', (string) $v) . '`',
                '%d' => (string) (int) $v,
                '%f' => (string) (float) $v,
                default => "'" . addslashes((string) $v) . "'",
            };
        }, $query);
    }

    public function get_var(string $query) {
        $this->queries[] = $query;
        if (preg_match("/^SHOW TABLES LIKE '(.+)'$/", $query, $m)) {
            $t = str_replace('\\', '', $m[1]);
            return array_key_exists($t, $this->tables) ? $t : null;
        }
        if (preg_match('/^SELECT COUNT\(\*\) FROM `([a-z0-9_]+)`$/', $query, $m)) {
            $this->require_table($m[1]);
            return (string) count($this->tables[$m[1]]);
        }
        throw new RuntimeException("Mock_WPDB: unsupported get_var: {$query}");
    }

    public function get_results(string $query, string $output = 'OBJECT'): array {
        $this->queries[] = $query;
        if (preg_match('/^SELECT ([a-z0-9_, ]+) FROM `([a-z0-9_]+)` ORDER BY id DESC LIMIT (\d+)$/', $query, $m)) {
            $this->require_table($m[2]);
            $rows = array_slice(array_reverse(array_values($this->tables[$m[2]])), 0, (int) $m[3]);
            $cols = array_map('trim', explode(',', $m[1]));
            $rows = array_map(static fn(array $r): array => array_intersect_key($r, array_flip($cols)), $rows);
            return 'ARRAY_A' === $output ? $rows : array_map(static fn(array $r) => (object) $r, $rows);
        }
        throw new RuntimeException("Mock_WPDB: unsupported get_results: {$query}");
    }

    public function get_row(string $query, string $output = 'OBJECT') {
        $this->queries[] = $query;
        if (preg_match("/^SELECT ([a-z0-9_, ]+) FROM `([a-z0-9_]+)` WHERE tracking_id = '(.*)'$/", $query, $m)) {
            $this->require_table($m[2]);
            foreach ($this->tables[$m[2]] as $row) {
                if ((string) $row['tracking_id'] === stripslashes($m[3])) {
                    $r = array_intersect_key($row, array_flip(array_map('trim', explode(',', $m[1]))));
                    return 'ARRAY_A' === $output ? $r : (object) $r;
                }
            }
            return null;
        }
        if (preg_match('/^SELECT ([a-z_0-9]+) FROM `([a-z0-9_]+)` ORDER BY id DESC LIMIT 1$/', $query, $m)) {
            $this->require_table($m[2]);
            $rows = array_values($this->tables[$m[2]]);
            if ([] === $rows) {
                return null;
            }
            $r = [$m[1] => end($rows)[$m[1]]];
            return 'ARRAY_A' === $output ? $r : (object) $r;
        }
        throw new RuntimeException("Mock_WPDB: unsupported get_row: {$query}");
    }

    public function insert(string $table, array $data, $format = null) {
        if ($this->fail_writes || !array_key_exists($table, $this->tables)) {
            $this->last_error = 'insert failed';
            return false;
        }
        foreach ($this->tables[$table] as $row) {
            if (isset($data['tracking_id'], $row['tracking_id']) && $row['tracking_id'] === $data['tracking_id']) {
                $this->last_error = 'Duplicate entry';
                return false;
            }
        }
        $this->auto[$table] = ($this->auto[$table] ?? 0) + 1;
        $this->insert_id = $this->auto[$table];
        $this->tables[$table][$this->insert_id] = ['id' => $this->insert_id] + $data;
        return 1;
    }

    public function update(string $table, array $data, array $where, $format = null, $where_format = null) {
        if ($this->fail_writes || !array_key_exists($table, $this->tables)) {
            return false;
        }
        $n = 0;
        foreach ($this->tables[$table] as $id => $row) {
            if (array_intersect_assoc($where, $row) === $where) {
                $this->tables[$table][$id] = array_merge($row, $data);
                $n++;
            }
        }
        return $n;
    }

    public function delete(string $table, array $where, $where_format = null) {
        if (!array_key_exists($table, $this->tables)) {
            return false;
        }
        $n = 0;
        foreach ($this->tables[$table] as $id => $row) {
            if (array_intersect_assoc(array_map('strval', $where), array_map('strval', $row)) === array_map('strval', $where)) {
                unset($this->tables[$table][$id]);
                $n++;
            }
        }
        return $n;
    }

    public function get_col(string $query): array {
        $this->queries[] = $query;
        if (preg_match('/^SELECT DISTINCT ([a-z0-9_]+) FROM `([a-z0-9_]+)`$/', $query, $m)) {
            $this->require_table($m[2]);
            return array_values(array_unique(array_map(static fn(array $r): string => (string) ($r[$m[1]] ?? ''), $this->tables[$m[2]])));
        }
        throw new RuntimeException("Mock_WPDB: unsupported get_col: {$query}");
    }

    public function query(string $query) {
        $this->queries[] = $query;
        if (preg_match('/^DROP TABLE IF EXISTS `([a-z0-9_]+)`$/', $query, $m)) {
            unset($this->tables[$m[1]]);
            return true;
        }
        throw new RuntimeException("Mock_WPDB: unsupported query: {$query}");
    }

    private function require_table(string $table): void {
        if (!array_key_exists($table, $this->tables)) {
            throw new RuntimeException("Mock_WPDB: table {$table} does not exist but was queried without a check");
        }
    }
}

$GLOBALS['wpdb'] = new Mock_WPDB_CRA();

function reset_db(bool $with_tables = true): Mock_WPDB_CRA {
    $db = new Mock_WPDB_CRA();
    if ($with_tables) {
        $db->tables = ['wp_wm_cra_sbom_snapshots' => [], 'wp_wm_cra_advisories' => []];
    }
    $GLOBALS['wpdb'] = $db;
    return $db;
}

// -----------------------------------------------------------------------------------------------------------------
// WordPress stubs
// -----------------------------------------------------------------------------------------------------------------
$GLOBALS['mock_options']      = [];
$GLOBALS['mock_transients']   = [];
$GLOBALS['mock_rest_routes']  = [];
$GLOBALS['mock_can_manage']   = true;
$GLOBALS['mock_rules']        = [];
$GLOBALS['mock_flushes']      = 0;
$GLOBALS['mock_hooks']        = [];
$GLOBALS['mock_styles']       = [];
$GLOBALS['mock_redirect']     = null;
$GLOBALS['mock_file_headers'] = [];
$GLOBALS['mock_cron'] = [];
$GLOBALS['mock_http'] = [];
$GLOBALS['mock_http_requests'] = [];
$GLOBALS['mock_option_autoloads'] = [];
$GLOBALS['mock_multisite'] = false;
$GLOBALS['mock_network_active'] = false;
$GLOBALS['mock_sites'] = [1];
$GLOBALS['mock_current_blog_id'] = 1;
$GLOBALS['mock_blog_stack'] = [];
$GLOBALS['mock_blog_options'] = [];
$GLOBALS['mock_blog_autoloads'] = [];
$GLOBALS['mock_switch_log'] = [];
$GLOBALS['mock_dbdelta_throw_on_prefix'] = '';

function get_option(string $option, $default = false) { return array_key_exists($option, $GLOBALS['mock_options']) ? $GLOBALS['mock_options'][$option] : $default; }
function update_option(string $option, $value, $autoload = null): bool { $GLOBALS['mock_options'][$option] = $value; $GLOBALS['mock_option_autoloads'][$option] = $autoload; return true; }
function delete_option(string $option): bool { unset($GLOBALS['mock_options'][$option], $GLOBALS['mock_option_autoloads'][$option]); return true; }
function get_transient(string $transient) { return array_key_exists($transient, $GLOBALS['mock_transients']) ? $GLOBALS['mock_transients'][$transient] : false; }
function set_transient(string $transient, $value, int $expiration = 0): bool { $GLOBALS['mock_transients'][$transient] = $value; return true; }
function delete_transient(string $transient): bool { unset($GLOBALS['mock_transients'][$transient]); return true; }
function wp_salt(string $scheme = 'auth'): string { return 'wm-cra-test-salt-' . $scheme; }
function register_rest_route(string $ns, string $route, array $args): bool { $GLOBALS['mock_rest_routes'][$ns . $route] = $args; return true; }
function get_site_option(string $option, $default = false) { return $default; }
function delete_site_option(string $option): bool { return true; }
function is_multisite(): bool { return (bool) ($GLOBALS['mock_multisite'] ?? false); }
function is_plugin_active_for_network(string $plugin): bool { return (bool) ($GLOBALS['mock_network_active'] ?? false); }
function switch_to_blog(int $new_blog_id, bool $deprecated = false): bool {
    $cur = (int) ($GLOBALS['mock_current_blog_id'] ?? 1);
    $GLOBALS['mock_blog_stack'][] = $cur;
    $GLOBALS['mock_blog_options'][$cur] = $GLOBALS['mock_options'];
    $GLOBALS['mock_blog_autoloads'][$cur] = $GLOBALS['mock_option_autoloads'];
    $GLOBALS['mock_current_blog_id'] = $new_blog_id;
    $GLOBALS['wpdb']->prefix = 1 === $new_blog_id ? 'wp_' : "wp_{$new_blog_id}_";
    $GLOBALS['mock_options'] = $GLOBALS['mock_blog_options'][$new_blog_id] ?? [];
    $GLOBALS['mock_option_autoloads'] = $GLOBALS['mock_blog_autoloads'][$new_blog_id] ?? [];
    $GLOBALS['mock_switch_log'][] = "switch:{$new_blog_id}";
    return true;
}
function restore_current_blog(): bool {
    $cur = (int) ($GLOBALS['mock_current_blog_id'] ?? 1);
    $GLOBALS['mock_blog_options'][$cur] = $GLOBALS['mock_options'];
    $GLOBALS['mock_blog_autoloads'][$cur] = $GLOBALS['mock_option_autoloads'];
    $prev = [] !== $GLOBALS['mock_blog_stack'] ? (int) array_pop($GLOBALS['mock_blog_stack']) : 1;
    $GLOBALS['mock_current_blog_id'] = $prev;
    $GLOBALS['wpdb']->prefix = 1 === $prev ? 'wp_' : "wp_{$prev}_";
    $GLOBALS['mock_options'] = $GLOBALS['mock_blog_options'][$prev] ?? [];
    $GLOBALS['mock_option_autoloads'] = $GLOBALS['mock_blog_autoloads'][$prev] ?? [];
    $GLOBALS['mock_switch_log'][] = "restore:{$prev}";
    return true;
}
function add_action(string $tag, $cb, int $priority = 10, int $args = 1): void { $GLOBALS['mock_hooks'][$tag][] = [$cb, $priority]; }
function add_filter(string $tag, $cb, int $priority = 10, int $args = 1): void { $GLOBALS['mock_hooks'][$tag][] = [$cb, $priority]; }
function apply_filters(string $tag, $value, ...$rest) { foreach ($GLOBALS['mock_hooks'][$tag] ?? [] as [$cb, $priority]) { $value = $cb($value, ...$rest); } return $value; }
function do_action(string $tag, ...$rest): void { foreach ($GLOBALS['mock_hooks'][$tag] ?? [] as [$cb, $priority]) { $cb(...$rest); } }
function __return_true(): bool { return true; }
function wp_next_scheduled(string $hook) { return $GLOBALS['mock_cron'][$hook] ?? false; }
function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool { $GLOBALS['mock_cron'][$hook] = $timestamp; return true; }
function wp_clear_scheduled_hook(string $hook): int { unset($GLOBALS['mock_cron'][$hook]); return 1; }
// The vulnerability databases. $mock_http answers by URL substring; every request is recorded, so a
// test can see which source was asked about what — and that a source was not asked at all.
function wp_remote_get(string $url, array $args = []) {
    $GLOBALS['mock_http_requests'][] = ['method' => 'GET', 'url' => $url, 'body' => ''];
    return wm_cra_mock_http_answer($url);
}
function wp_remote_post(string $url, array $args = []) {
    $GLOBALS['mock_http_requests'][] = ['method' => 'POST', 'url' => $url, 'body' => (string) ($args['body'] ?? '')];
    return wm_cra_mock_http_answer($url);
}
function wm_cra_mock_http_answer(string $url) {
    foreach ($GLOBALS['mock_http'] as $needle => $answer) {
        if (str_contains($url, (string) $needle)) {
            return is_callable($answer) ? $answer($url) : $answer;
        }
    }
    return ['response' => ['code' => 404], 'body' => ''];
}
function wp_remote_retrieve_response_code($r): int { return (int) ($r['response']['code'] ?? 0); }
function wp_remote_retrieve_body($r): string { return (string) ($r['body'] ?? ''); }
function is_wp_error($thing): bool { return $thing instanceof WP_Error_CRA || $thing instanceof WP_Error; }
class WP_Error_CRA {}
class WP_Error {
    public function __construct(public string $code = '', public string $message = '', public array $data = []) {}
    public function get_error_code(): string { return $this->code; }
    public function get_error_data(): array { return $this->data; }
}
class WP_REST_Response {
    public function __construct(public $data = null, public int $status = 200) {}
    public function get_data() { return $this->data; }
    public function get_status(): int { return $this->status; }
}
class WP_REST_Request {
    /** @param array<string, string> $headers */
    public function __construct(public array $headers = []) {}
    public function get_header(string $key): string { return $this->headers[strtolower($key)] ?? ''; }
}
function checked($checked, $current = true, bool $echo = true): string { $out = ((string) $checked === (string) $current) ? " checked='checked'" : ''; if ($echo) { echo $out; } return $out; }
$GLOBALS['mock_in_plugins_loaded'] = false;
function add_rewrite_rule(string $regex, string $query, string $after = 'bottom'): void {
    if ($GLOBALS['mock_in_plugins_loaded'] ?? false) {
        throw new Error('Call to a member function add_rule() on null');
    }
    $GLOBALS['mock_rules'][$regex] = $query;
}
// WordPress stores the rules registered at flush time; a soft or hard flush behaves the same here.
function flush_rewrite_rules(bool $hard = true): void {
    if ($GLOBALS['mock_in_plugins_loaded'] ?? false) {
        throw new Error('Call to a member function flush_rules() on null');
    }
    $GLOBALS['mock_flushes']++;
    $GLOBALS['mock_options']['rewrite_rules'] = $GLOBALS['mock_rules'];
}
function dbDelta($sql): array {
    if ('' !== (string) ($GLOBALS['mock_dbdelta_throw_on_prefix'] ?? '') && str_contains((string) $sql, (string) $GLOBALS['mock_dbdelta_throw_on_prefix'])) {
        throw new RuntimeException('simulated dbDelta failure');
    }
    if (preg_match('/CREATE TABLE ([a-z0-9_]+) \(/', (string) $sql, $m)) {
        $GLOBALS['wpdb']->tables[$m[1]] = $GLOBALS['wpdb']->tables[$m[1]] ?? [];
    }
    return [];
}
function wp_generate_uuid4(): string { return 'c0a80101-1234-4567-89ab-cdef01234567'; }
function home_url(string $path = ''): string {
    $blog_id = (int) ($GLOBALS['mock_current_blog_id'] ?? 1);
    $host = 1 === $blog_id ? 'demo.example.test' : "site{$blog_id}.example.test";
    return "https://{$host}" . ('' === $path ? '' : '/' . ltrim($path, '/'));
}
function admin_url(string $path = ''): string { return 'https://demo.example.test/wp-admin/' . ltrim($path, '/'); }
function rest_url(string $path = ''): string { return 'https://demo.example.test/wp-json/' . ltrim($path, '/'); }
function get_bloginfo(string $show = '', string $filter = 'raw'): string { return match ($show) { 'name' => 'Example Site', 'version' => '6.9.4', default => '' }; }
function current_time(string $type, $gmt = 0) { return 'mysql' === $type ? gmdate('Y-m-d H:i:s') : time(); }
function esc_html($t): string { return htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'); }
function esc_attr($t): string { return htmlspecialchars((string) $t, ENT_QUOTES, 'UTF-8'); }
function esc_url($u): string { return htmlspecialchars((string) $u, ENT_QUOTES, 'UTF-8'); }
// Mirrors the measured WordPress 7.1 behaviour: a value without a scheme gets one prepended
// (esc_url_raw('not-an-email', ['https']) === 'https://not-an-email').
function esc_url_raw(string $url, ?array $protocols = null): string {
    if ('' !== $url && !str_contains($url, ':') && !in_array($url[0], ['/', '#', '?'], true)) {
        $url = (null !== $protocols && in_array('https', $protocols, true) ? 'https://' : 'http://') . $url;
    }
    $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
    if (null !== $protocols && !in_array($scheme, $protocols, true)) {
        return '';
    }
    return false === filter_var($url, FILTER_VALIDATE_URL) ? '' : $url;
}
function __(string $t, string $d = ''): string { return $t; }
function esc_html__(string $t, string $d = ''): string { return esc_html($t); }
function esc_html_e(string $t, string $d = ''): void { echo esc_html($t); }
function esc_attr_e(string $t, string $d = ''): void { echo esc_attr($t); }
function esc_attr__(string $t, string $d = ''): string { return esc_attr($t); }
function sanitize_text_field($s): string { return trim(strip_tags((string) $s)); }
function sanitize_key($k): string { return (string) preg_replace('/[^a-z0-9_\-]/', '', strtolower((string) $k)); }
function sanitize_title($t): string { return (string) preg_replace('/[^a-z0-9_-]/', '', strtolower((string) $t)); }
function wp_unslash($v) { return $v; }
function is_email(string $e) { return false === filter_var($e, FILTER_VALIDATE_EMAIL) ? false : $e; }
function wp_parse_url(string $url, int $component = -1) { return parse_url($url, $component); }
function wp_strip_all_tags($s): string { return trim(strip_tags((string) $s)); }
function wp_json_encode($data, int $flags = 0) { return json_encode($data, $flags); }
$GLOBALS['mock_query_vars'] = [];
$GLOBALS['mock_registered_settings'] = [];
$GLOBALS['mock_registered_scripts'] = [];
$GLOBALS['mock_script_translations'] = [];
$GLOBALS['mock_registered_blocks'] = [];
$GLOBALS['mock_block_bindings'] = [];
function get_query_var(string $v) { return $GLOBALS['mock_query_vars'][$v] ?? ''; }
function add_query_arg(array $args, string $url): string { return $url . '?' . http_build_query($args); }
function wp_safe_redirect(string $url): bool { $GLOBALS['mock_redirect'] = $url; throw new RuntimeException('redirect'); }
function check_admin_referer(string $action, string $name): bool { return true; }
function current_user_can(string $cap): bool { return (bool) ($GLOBALS['mock_can_manage'] ?? true); }
function wp_nonce_field(string $action, string $name): void { echo '<input type="hidden" name="' . esc_attr($name) . '" value="nonce" />'; }
function wp_enqueue_style(string $handle, ...$rest): void { $GLOBALS['mock_styles'][] = $handle; }
function wp_add_dashboard_widget(...$args): void {}
function add_menu_page(...$args): string { return 'toplevel_page_wm-cra-beacon'; }
function add_shortcode(string $tag, $cb): void {}
function register_setting(string $option_group, string $option_name, $args = []): void { $GLOBALS['mock_registered_settings'][$option_name] = ['group' => $option_group, 'args' => $args]; }
function wp_register_script(string $handle, string $src = '', array $deps = [], $ver = false, $args = false): bool { $GLOBALS['mock_registered_scripts'][$handle] = ['src' => $src, 'deps' => $deps, 'ver' => $ver, 'args' => $args]; return true; }
function wp_set_script_translations(string $handle, string $domain = 'default', string $path = ''): bool { $GLOBALS['mock_script_translations'][$handle] = ['domain' => $domain, 'path' => $path]; return true; }
function register_block_type($block_type, array $args = []): bool { $GLOBALS['mock_registered_blocks'][(string) $block_type] = $args; return true; }
function register_block_bindings_source(string $source_name, array $source_properties): bool { $GLOBALS['mock_block_bindings'][$source_name] = $source_properties; return true; }
function load_plugin_textdomain(string $domain, $deprecated = false, string $plugin_rel_path = ''): bool { return true; }
function plugin_basename(string $file): string { return 'wm-cra-sbom-beacon/wm-cra-sbom-beacon.php'; }
function plugin_dir_path(string $file): string { return rtrim(dirname($file), '/\\') . '/'; }
function plugin_dir_url(string $file): string { return 'https://demo.example.test/wp-content/plugins/wm-cra-sbom-beacon/'; }
function register_activation_hook(string $file, $cb): void {}
function register_deactivation_hook(string $file, $cb): void {}
function is_admin(): bool { return true; }
class GenerateBlocks_Register_Dynamic_Tag {
    public static array $registered = [];
    public function __construct(array $args) { self::$registered[(string) ($args['tag'] ?? '')] = $args; }
}
function trailingslashit(string $s): string { return rtrim($s, '/\\') . '/'; }
function wp_upload_dir($time = null, bool $create = true): array { return ['basedir' => $GLOBALS['mock_uploads_basedir'] ?? '']; }
function wp_delete_file(string $file): void { @unlink($file); }
function get_sites(array $args = []): array { return $GLOBALS['mock_sites'] ?? [1]; }
function get_plugins(): array {
    return [
        'akismet/akismet.php'     => ['Name' => 'Akismet Anti-spam', 'Version' => '5.4', 'Author' => 'Automattic'],
        'noversion/noversion.php' => ['Name' => 'No Version', 'Version' => '', 'Author' => ''],
        'inactive/inactive.php'   => ['Name' => 'Inactive', 'Version' => '1.2.3', 'Author' => 'X'],
    ];
}
function get_mu_plugins(): array { return []; }
function get_file_data(string $file, array $headers): array {
    return ['License' => $GLOBALS['mock_file_headers'][$file] ?? ''];
}
function wp_get_theme() {
    return new class {
        public function get_stylesheet(): string { return 'child-theme'; }
        public function get_stylesheet_directory(): string { return SUITE_THEMES . '/child-theme'; }
        public function get(string $h): string { return match ($h) { 'Name' => 'Child Theme', 'Version' => '', 'Author' => 'Someone', default => '' }; }
        public function parent() {
            return new class {
                public function get_stylesheet(): string { return 'parent-theme'; }
                public function get_stylesheet_directory(): string { return SUITE_THEMES . '/parent-theme'; }
                public function get(string $h): string { return match ($h) { 'Name' => 'Parent Theme', 'Version' => '3.5.0', 'Author' => 'Vendor', default => '' }; }
            };
        }
    };
}

// WP-CLI stubs: error() ends the command the way WP-CLI does (exit), here with an exception.
final class CliExit extends RuntimeException {}
class WP_CLI_Command {}
final class WP_CLI {
    public static array $out = [];
    public static function line(string $m = ''): void { self::$out[] = ['STDOUT', $m]; }
    public static function success(string $m): void { self::$out[] = ['STDOUT', 'Success: ' . $m]; }
    public static function warning(string $m): void { self::$out[] = ['STDERR', 'Warning: ' . $m]; }
    public static function debug(string $m, $group = false): void { self::$out[] = ['STDERR', 'Debug: ' . $m]; }
    public static function error(string $m): void { self::$out[] = ['STDERR', 'Error: ' . $m]; throw new CliExit($m); }
    public static function add_command(...$a): void {}
    public static function stdout(): string { return implode("\n", array_column(array_filter(self::$out, static fn($o) => 'STDOUT' === $o[0]), 1)); }
    public static function run(callable $fn): string { self::$out = []; try { $fn(); return 'ok'; } catch (CliExit $e) { return 'error'; } }
}

require __DIR__ . '/stubs/hub-interface.php';

spl_autoload_register(static function (string $class): void {
    $prefix = 'WMCyber\\CRA\\';
    if (0 !== strncmp($prefix, $class, strlen($prefix))) {
        return;
    }
    $file = WM_CRA_PATH . 'includes/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require_once $file;
    }
});

use WMCyber\CRA\Admin\AdminDashboard;
use WMCyber\CRA\API\RestController;
use WMCyber\CRA\Adapters\Cra_Spoke_Adapter;
use WMCyber\CRA\Beacon\SecurityTxtHandler;
use WMCyber\CRA\CLI\CraCommand;
use WMCyber\CRA\CSAF\CsafPublisher;
use WMCyber\CRA\Database\Schema;
use WMCyber\CRA\Frontend\PsirtPortal;
use WMCyber\CRA\SBOM\CycloneDxGenerator;
use WMCyber\CRA\SPDX\Spdx3Generator;
use WMCyber\CRA\Vuln\CpeMatcher;
use WMCyber\CRA\Vuln\OpenVexEngine;
use WMCyber\CRA\Vuln\NvdClient;
use WMCyber\CRA\Vuln\OsvClient;
use WMCyber\CRA\Vuln\VulnerabilityAudit;

const RULE = '^\.well-known/security\.txt$';

/** A usable file: contact, Expires in 200 days, stored route, confirmed by an administrator. */
function good_options(): void {
    $GLOBALS['mock_options'] = [
        SecurityTxtHandler::OPT_CONTACT   => 'mailto:security@example.test',
        SecurityTxtHandler::OPT_EXPIRES   => gmdate('Y-m-d\TH:i:s\Z', time() + 200 * DAY_IN_SECONDS),
        SecurityTxtHandler::OPT_LANGUAGES => 'de, en',
        SecurityTxtHandler::OPT_CONFIRMED => '2026-09-15T10:00:00Z',
        'permalink_structure'             => '/%postname%/',
        'rewrite_rules'                   => [RULE => 'index.php?wm_cra_security_txt=1'],
        'active_plugins'                  => ['akismet/akismet.php', 'noversion/noversion.php'],
    ];
}

echo "==============================================================================\n";
echo "  WM CRA SBOM BEACON — STANDALONE TEST SUITE\n";
echo "==============================================================================\n\n";

// =================================================================================================================
echo "[GROUP 1] security.txt content and field validation\n";
// =================================================================================================================
good_options();
reset_db();
$handler = new SecurityTxtHandler();
$txt     = $handler->generate_security_txt_content();
assert_test('file has Contact, Expires, Preferred-Languages and Canonical', str_contains($txt, "Contact: mailto:security@example.test\n") && 1 === preg_match('/^Expires: \d{4}-\d{2}-\d{2}T/m', $txt) && str_contains($txt, 'Preferred-Languages: de, en') && str_contains($txt, 'Canonical: https://demo.example.test/.well-known/security.txt'), $txt);
assert_test('no CSAF: or SBOM: field line (CSAF must point to a provider-metadata.json)', 0 === preg_match('/^(CSAF|SBOM):/m', $txt), $txt);
assert_test('no BSI TR-03183 claim in the served file', !str_contains($txt, 'TR-03183'), $txt);
unset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES]);
assert_test('a missing Expires is not invented', !str_contains($handler->generate_security_txt_content(), 'Expires:'));

$now = gmmktime(12, 0, 0, 9, 15, 2026);
assert_test('e-mail contact becomes mailto:', 'mailto:psirt@example.test' === SecurityTxtHandler::sanitize_contact('psirt@example.test'));
assert_test('mailto: input is not doubled', 'mailto:psirt@example.test' === SecurityTxtHandler::sanitize_contact('mailto:psirt@example.test'));
assert_test('invalid or empty contact is refused', null === SecurityTxtHandler::sanitize_contact('not-an-email') && null === SecurityTxtHandler::sanitize_contact(''));
assert_test('https contact form kept, http refused', 'https://example.test/form' === SecurityTxtHandler::sanitize_contact('https://example.test/form') && null === SecurityTxtHandler::sanitize_contact('http://example.test/form'));
assert_test('Expires in the past is refused', null === SecurityTxtHandler::sanitize_expires('2026-09-01', $now));
assert_test('Expires more than a year ahead is refused', null === SecurityTxtHandler::sanitize_expires('2027-09-20', $now));
assert_test('Expires within a year becomes RFC 3339 end of day UTC', '2027-03-01T23:59:59Z' === SecurityTxtHandler::sanitize_expires('2027-03-01', $now));
assert_test('impossible date refused', null === SecurityTxtHandler::sanitize_expires('2027-02-30', $now));
assert_test('language tags normalised, garbage refused', 'de, en-GB' === SecurityTxtHandler::sanitize_languages(' de ,en-GB') && null === SecurityTxtHandler::sanitize_languages('deutsch!'));
assert_test('policy must be https or empty', '' === SecurityTxtHandler::sanitize_https_url('') && null === SecurityTxtHandler::sanitize_https_url('ftp://example.test/p') && null === SecurityTxtHandler::sanitize_https_url('http://example.test/p'));
assert_test('a bare word or a user-info URL is not an https URL', null === SecurityTxtHandler::sanitize_https_url('not-a-url') && null === SecurityTxtHandler::sanitize_https_url('https://security@localhost'));
$GLOBALS['mock_hooks'] = [];
$handler->init();
$render_priority = null;
foreach ($GLOBALS['mock_hooks']['template_redirect'] ?? [] as [$cb, $prio]) {
    if (is_array($cb) && 'render_security_txt' === $cb[1]) {
        $render_priority = $prio;
    }
}
assert_test('security.txt is printed before redirect_canonical (template_redirect priority < 10)', null !== $render_priority && $render_priority < 10, var_export($render_priority, true));

// =================================================================================================================
echo "\n[GROUP 2] security.txt state\n";
// =================================================================================================================
good_options();
$s = $handler->status();
assert_test('usable file is ok and confirmed', 'ok' === $s['state'] && $s['confirmed'] && $s['route'], (string) json_encode($s));
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES] = '2025-01-01T00:00:00Z';
assert_test('past Expires is expired', 'expired' === $handler->status()['state']);
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES] = gmdate('Y-m-d\TH:i:s\Z', time() + 10 * DAY_IN_SECONDS);
assert_test('Expires within 30 days is expiring', 'expiring' === $handler->status()['state']);
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES] = 'next year';
assert_test('unreadable Expires is invalid', 'invalid' === $handler->status()['state']);
good_options();
unset($GLOBALS['mock_options']['rewrite_rules']);
assert_test('route not stored is no_route', 'no_route' === $handler->status()['state']);
good_options();
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONTACT] = '';
assert_test('no contact is not_configured', 'not_configured' === $handler->status()['state']);
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONTACT] = 'mailto:security@localhost';
assert_test('an undeliverable default contact (host without a dot) is invalid', 'invalid' === $handler->status()['state']);
good_options();
unset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONFIRMED]);
assert_test('activation default is reported as unconfirmed', false === $handler->status()['confirmed']);

// =================================================================================================================
echo "\n[GROUP 3] Activation, deactivation and route repair\n";
// =================================================================================================================
$GLOBALS['mock_options'] = [];
$GLOBALS['mock_rules']   = [];
reset_db(false);
Schema::activate(false);
assert_test('activation stores the security.txt route (was 404 until permalinks were saved)', isset($GLOBALS['mock_options']['rewrite_rules'][RULE]), (string) json_encode(array_keys((array) ($GLOBALS['mock_options']['rewrite_rules'] ?? []))));
assert_test('activation creates both tables and no audit table', isset($GLOBALS['wpdb']->tables['wp_wm_cra_sbom_snapshots'], $GLOBALS['wpdb']->tables['wp_wm_cra_advisories']) && !isset($GLOBALS['wpdb']->tables['wp_wm_cra_audit_log']));
$exp = SecurityTxtHandler::parse_rfc3339((string) get_option(SecurityTxtHandler::OPT_EXPIRES));
assert_test('activation Expires is under one year ahead', null !== $exp && $exp < time() + YEAR_IN_SECONDS && $exp > time(), (string) get_option(SecurityTxtHandler::OPT_EXPIRES));
assert_test('activation does not mark the guessed contact as confirmed', '' === (string) get_option(SecurityTxtHandler::OPT_CONFIRMED, ''));
Schema::deactivate();
assert_test('deactivation drops the stored rules instead of re-storing them', !array_key_exists('rewrite_rules', $GLOBALS['mock_options']));

good_options();
$GLOBALS['mock_options']['rewrite_rules'] = ['^other$' => 'index.php'];
$GLOBALS['mock_rules'] = [];
$handler->add_rewrite_rules();
$GLOBALS['mock_flushes'] = 0;
$handler->ensure_rules_stored();
assert_test('a site activated before the fix gets the route with one flush', 1 === $GLOBALS['mock_flushes'] && isset($GLOBALS['mock_options']['rewrite_rules'][RULE]));
$handler->ensure_rules_stored();
assert_test('no further flush once stored', 1 === $GLOBALS['mock_flushes']);
$GLOBALS['mock_options']['permalink_structure'] = '';
unset($GLOBALS['mock_options']['rewrite_rules']);
$handler->ensure_rules_stored();
assert_test('plain permalinks: no flush on every request', 1 === $GLOBALS['mock_flushes']);

// =================================================================================================================
echo "\n[GROUP 4] Settings form writes what the served file reads\n";
// =================================================================================================================
good_options();
reset_db();
$dash    = new AdminDashboard(new CycloneDxGenerator(), $handler, new CsafPublisher());
$in_year = gmdate('Y-m-d', time() + 100 * DAY_IN_SECONDS);
$errors  = $dash->save_settings(['contact' => 'psirt@example.test', 'expires' => $in_year, 'languages' => 'en', 'policy' => 'https://example.test/new-policy', 'encryption' => '']);
$served  = $handler->generate_security_txt_content();
assert_test('saved values reach the served security.txt', [] === $errors && str_contains($served, 'Contact: mailto:psirt@example.test') && str_contains($served, 'Policy: https://example.test/new-policy') && str_contains($served, 'Preferred-Languages: en') && str_contains($served, "Expires: {$in_year}T23:59:59Z"), $served);
assert_test('saving confirms the contact and writes no wm_cra_settings', '' !== (string) get_option(SecurityTxtHandler::OPT_CONFIRMED, '') && !array_key_exists('wm_cra_settings', $GLOBALS['mock_options']));
$before = $GLOBALS['mock_options'];
$errors = $dash->save_settings(['contact' => 'not-an-email', 'expires' => $in_year, 'languages' => 'en', 'policy' => 'https://example.test/other', 'encryption' => '']);
assert_test('an invalid contact is reported and nothing is written', ['contact'] === $errors && $before === $GLOBALS['mock_options'], (string) json_encode($errors));
$errors = $dash->save_settings(['contact' => 'psirt@example.test', 'expires' => '2020-01-01', 'languages' => 'en', 'policy' => '', 'encryption' => 'http://example.test/key']);
assert_test('past Expires and http key are both reported', ['expires', 'encryption'] === $errors, (string) json_encode($errors));

// =================================================================================================================
echo "\n[GROUP 5] CycloneDX inventory\n";
// =================================================================================================================
good_options();
reset_db();
$GLOBALS['mock_file_headers'] = [WP_PLUGIN_DIR . '/akismet/akismet.php' => 'GPLv2 or later', SUITE_THEMES . '/parent-theme/style.css' => 'GNU General Public License v2 or later'];
@mkdir(SUITE_THEMES . '/parent-theme', 0777, true);
touch(SUITE_THEMES . '/parent-theme/style.css');
@mkdir(WP_PLUGIN_DIR . '/akismet', 0777, true);
@mkdir(WP_PLUGIN_DIR . '/noversion', 0777, true);
touch(WP_PLUGIN_DIR . '/akismet/akismet.php');
touch(WP_PLUGIN_DIR . '/noversion/noversion.php');
// A plugin that bundles a Composer library, so the served document is measured with one in it and
// not only the scanner in isolation.
file_put_contents(WP_PLUGIN_DIR . '/akismet/composer.lock', (string) json_encode(['packages' => [['name' => 'monolog/monolog', 'version' => '3.5.0', 'license' => ['MIT']]]]));
$generator = new CycloneDxGenerator();
$sbom      = $generator->generate_sbom();
$by_name   = array_column($sbom['components'], null, 'name');
$flat      = (string) json_encode($sbom);
// The installed units, separated from the bundled libraries and the runtime that now sit beside them.
$installed = array_values(array_filter($sbom['components'], static fn(array $c): bool => in_array($c['type'], ['application', 'framework'], true)));
assert_test('components: core, two active plugins, child and parent theme; not the inactive plugin', ['wordpress-core', 'akismet', 'noversion', 'child-theme', 'parent-theme'] === array_column($installed, 'name'), implode(',', array_column($installed, 'name')));
assert_test('no component carries a hash (the core hash was sha256 of the version string)', !str_contains($flat, '"hashes"'), $flat);
assert_test('licence comes from the plugin header as a name', [['license' => ['name' => 'GPLv2 or later']]] === ($by_name['akismet']['licenses'] ?? null), (string) json_encode($by_name['akismet'] ?? null));
assert_test('no "Proprietary" licence invented and no licence without a header', !str_contains($flat, 'Proprietary') && !isset($by_name['noversion']['licenses']));
assert_test('an unknown version stays out of version and purl', !isset($by_name['noversion']['version']) && 'pkg:generic/wordpress-plugin/noversion' === $by_name['noversion']['purl'], (string) json_encode($by_name['noversion']));
assert_test('child theme without version has none; parent keeps 3.5.0 and its licence', !isset($by_name['child-theme']['version']) && '3.5.0' === ($by_name['parent-theme']['version'] ?? null) && isset($by_name['parent-theme']['licenses']));
assert_test('registered purl type generic, authors instead of deprecated author', str_starts_with($by_name['akismet']['purl'], 'pkg:generic/') && [['name' => 'Automattic']] === ($by_name['akismet']['authors'] ?? null) && !str_contains($flat, '"author"'));
assert_test('site component has no invented version', !isset($sbom['metadata']['component']['version']));
assert_test(
    'a library a plugin bundles reaches the served document with its ecosystem purl',
    'pkg:composer/monolog/monolog@3.5.0' === ($by_name['monolog/monolog']['purl'] ?? null),
    implode(',', array_keys($by_name))
);
assert_test('the runtime the site executes on is part of the inventory', isset($by_name['php']) && 'platform' === $by_name['php']['type'], implode(',', array_keys($by_name)));
$saved = $generator->save_snapshot($sbom);
assert_test('snapshot stores the shared serialisation and returns saved', $saved['saved'] && hash('sha256', CycloneDxGenerator::serialize($sbom)) === $saved['sha256'] && 1 === count($GLOBALS['wpdb']->tables['wp_wm_cra_sbom_snapshots']));
$GLOBALS['wpdb']->fail_writes = true;
$failed = $generator->save_snapshot($sbom);
assert_test('a failed insert is reported as not saved', false === $failed['saved'] && 0 === $failed['snapshot_id']);

// =================================================================================================================
echo "\n[GROUP 5b] Bundled dependencies, runtime and the CBOM\n";
// =================================================================================================================
// The spec asks the inventory to map the Composer packages, the npm dependencies, the runtime
// library versions and the cryptographic algorithms — not only the units an administrator installs.
$dep_root = sys_get_temp_dir() . '/wm-cra-deps-' . getmypid();
@mkdir($dep_root . '/wm-demo/lib', 0777, true);
@mkdir($dep_root . '/wm-demo/vendor/acme', 0777, true);
@mkdir($dep_root . '/wm-demo/node_modules/left-pad', 0777, true);
file_put_contents($dep_root . '/wm-demo/composer.lock', (string) json_encode([
    'packages' => [
        ['name' => 'guzzlehttp/guzzle', 'version' => '7.8.1', 'license' => ['MIT'], 'description' => 'HTTP client'],
        ['name' => 'psr/log', 'version' => '3.0.0', 'license' => ['MIT']],
        ['name' => 'broken/no-version'],
    ],
    'packages-dev' => [['name' => 'phpunit/phpunit', 'version' => '10.5.0', 'license' => ['BSD-3-Clause']]],
]));
file_put_contents($dep_root . '/wm-demo/package-lock.json', (string) json_encode([
    'lockfileVersion' => 3,
    'packages' => [
        '' => ['name' => 'wm-demo', 'version' => '1.0.0'],
        'node_modules/lodash' => ['version' => '4.17.21', 'license' => 'MIT'],
        'node_modules/@babel/core' => ['version' => '7.24.0', 'license' => 'MIT'],
        'node_modules/mocha' => ['version' => '10.0.0', 'dev' => true],
    ],
]));
// Lock files belonging to other projects, in the directories a scan must not walk into.
file_put_contents($dep_root . '/wm-demo/vendor/acme/composer.lock', (string) json_encode(['packages' => [['name' => 'never/seen', 'version' => '9.9.9']]]));
file_put_contents($dep_root . '/wm-demo/node_modules/left-pad/package-lock.json', (string) json_encode(['lockfileVersion' => 3, 'packages' => ['node_modules/never-seen' => ['version' => '1.0.0']]]));

$deps    = \WMCyber\CRA\SBOM\DependencyScanner::components(['wm-demo' => $dep_root . '/wm-demo']);
$dep_map = array_column($deps, null, 'name');
assert_test(
    'Composer and npm packages are listed with the version the lock file states',
    '7.8.1' === ($dep_map['guzzlehttp/guzzle']['version'] ?? null) && '4.17.21' === ($dep_map['lodash']['version'] ?? null),
    implode(',', array_keys($dep_map))
);
// One assertion per name: `!isset($a, $b)` is true when EITHER is missing, so a single
// assertion over both would stay green while half the behaviour was broken (measured 2026-09-16,
// two mutations SURVIVED on exactly that).
assert_test('a composer.lock inside vendor/ describes another project and is not walked into', !isset($dep_map['never/seen']), implode(',', array_keys($dep_map)));
assert_test('a package-lock.json inside node_modules is not walked into either', !isset($dep_map['never-seen']), implode(',', array_keys($dep_map)));
assert_test('Composer development dependencies are not installed by a distribution build, so they are not claimed', !isset($dep_map['phpunit/phpunit']), implode(',', array_keys($dep_map)));
assert_test('npm development dependencies are not claimed either', !isset($dep_map['mocha']), implode(',', array_keys($dep_map)));
assert_test('a package without a version is left out rather than given one', !isset($dep_map['broken/no-version']));
assert_test(
    'the purl carries the ecosystem a vulnerability database can query, and an npm scope is a namespace',
    'pkg:composer/guzzlehttp/guzzle@7.8.1' === ($dep_map['guzzlehttp/guzzle']['purl'] ?? null)
        && 'pkg:npm/%40babel/core@7.24.0' === ($dep_map['@babel/core']['purl'] ?? null),
    (string) json_encode(array_column($deps, 'purl'))
);
assert_test('every bundled library names the plugin that brought it in', [['name' => 'wm-cra:bundled-by', 'value' => 'wm-demo']] === ($dep_map['psr/log']['properties'] ?? null), (string) json_encode($dep_map['psr/log'] ?? null));

// A library two plugins bundle is one component that names both, not two components.
@mkdir($dep_root . '/wm-other', 0777, true);
copy($dep_root . '/wm-demo/composer.lock', $dep_root . '/wm-other/composer.lock');
$shared = \WMCyber\CRA\SBOM\DependencyScanner::components(['wm-demo' => $dep_root . '/wm-demo', 'wm-other' => $dep_root . '/wm-other']);
$shared_guzzle = array_values(array_filter($shared, static fn(array $c): bool => 'guzzlehttp/guzzle' === $c['name']));
assert_test(
    'a library two plugins bundle is one component naming both owners',
    1 === count($shared_guzzle) && 2 === count($shared_guzzle[0]['properties'] ?? []),
    (string) json_encode($shared_guzzle)
);

// npm lockfileVersion 1 stores a nested tree instead of a flat map.
file_put_contents($dep_root . '/wm-other/package-lock.json', (string) json_encode([
    'lockfileVersion' => 1,
    'dependencies' => [
        'jquery'  => ['version' => '3.7.1'],
        'grunt'   => ['version' => '1.6.1', 'dev' => true],
        'wrapper' => ['version' => '2.0.0', 'dependencies' => ['nested-dep' => ['version' => '0.1.0']]],
    ],
]));
$v1 = array_column(\WMCyber\CRA\SBOM\DependencyScanner::npm_components($dep_root . '/wm-other/package-lock.json', 'wm-other'), 'version', 'name');
assert_test('a lockfileVersion 1 tree is flattened and its dev entries dropped', ['jquery' => '3.7.1', 'wrapper' => '2.0.0', 'nested-dep' => '0.1.0'] === $v1, (string) json_encode($v1));

$runtime = array_column(\WMCyber\CRA\SBOM\RuntimeInventory::components([
    'php_version' => '8.3.33',
    'extensions'  => ['openssl' => '8.3.33', 'pcre' => ''],
    'database'    => '10.11.6-MariaDB-1:10.11.6+maria~ubu2204',
    'server'      => 'Apache/2.4.57 (Debian)',
]), null, 'name');
assert_test('the PHP runtime and its versioned extensions are components', '8.3.33' === ($runtime['php']['version'] ?? null) && '8.3.33' === ($runtime['php-ext-openssl']['version'] ?? null));
assert_test('an extension without a version of its own gets none invented', !isset($runtime['php-ext-pcre']['version']) && isset($runtime['php-ext-pcre']));
assert_test(
    'MariaDB is not reported as MySQL: the two have different advisories',
    isset($runtime['mariadb']) && '10.11.6' === $runtime['mariadb']['version'] && !isset($runtime['mysql']),
    implode(',', array_keys($runtime))
);
assert_test('a version the server does not state is not derived', '' === \WMCyber\CRA\SBOM\RuntimeInventory::version_number('Percona Server'));
// The SERVER_SOFTWARE banner goes into a document another tool will parse. Until 2026-09-17 nothing
// tested that markup and control characters are removed from it; Plugin Check also asked for
// wp_strip_all_tags() instead of strip_tags() (WordPress.WP.AlternativeFunctions.strip_tags_strip_tags).
$saved_software = $_SERVER['SERVER_SOFTWARE'] ?? null;
$_SERVER['SERVER_SOFTWARE'] = "Apache/2.4.57 <b>(Debian)</b>\x07\x1B";
$banner = \WMCyber\CRA\SBOM\RuntimeInventory::web_server();
if (null === $saved_software) { unset($_SERVER['SERVER_SOFTWARE']); } else { $_SERVER['SERVER_SOFTWARE'] = $saved_software; }
assert_test(
    'the web server banner reaches the SBOM without markup or control characters',
    'Apache/2.4.57 (Debian)' === $banner,
    (string) json_encode($banner)
);
// phpversion('openssl') returns the PHP version on a stock build (measured 2026-09-16: 8.5.10).
// An SBOM carrying php-ext-openssl@8.5.10 sends a scanner after an OpenSSL release that does not
// exist, which is worse than omitting the field.
assert_test(
    "an extension that only reports PHP's own version gets none",
    '' === \WMCyber\CRA\SBOM\RuntimeInventory::usable_version('8.5.10', '8.5.10')
        && '' === \WMCyber\CRA\SBOM\RuntimeInventory::usable_version('', '8.5.10')
        && '1.22.8' === \WMCyber\CRA\SBOM\RuntimeInventory::usable_version('1.22.8', '8.5.10')
);
assert_test(
    'the openssl and curl extensions carry the version of the library they wrap, not PHP\'s',
    (!extension_loaded('openssl') || PHP_VERSION !== \WMCyber\CRA\SBOM\RuntimeInventory::library_version('openssl'))
        && (!extension_loaded('curl') || PHP_VERSION !== \WMCyber\CRA\SBOM\RuntimeInventory::library_version('curl')),
    \WMCyber\CRA\SBOM\RuntimeInventory::library_version('openssl') . ' / ' . \WMCyber\CRA\SBOM\RuntimeInventory::library_version('curl')
);
$measured_ext = \WMCyber\CRA\SBOM\RuntimeInventory::extension_versions();
$php_versioned = array_filter($measured_ext, static fn(string $v): bool => $v === PHP_VERSION);
assert_test('no loaded extension is listed with the PHP version as its own', [] === $php_versioned, (string) json_encode($php_versioned));
// Omitting the version is the honest fallback, but for openssl and curl the real one is obtainable,
// and a vulnerability database can only match a component that carries one.
assert_test(
    'openssl and curl reach the inventory with the version of the library, not with none',
    (!extension_loaded('openssl') || '' !== ($measured_ext['openssl'] ?? ''))
        && (!extension_loaded('curl') || '' !== ($measured_ext['curl'] ?? '')),
    (string) json_encode(['openssl' => $measured_ext['openssl'] ?? null, 'curl' => $measured_ext['curl'] ?? null])
);

// The CBOM: off by default, because it adds 186 components on a stock PHP 8.3 with OpenSSL 3.5.
unset($GLOBALS['mock_options'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE]);
assert_test('the CBOM is off until it is switched on', false === \WMCyber\CRA\SBOM\CryptoInventory::enabled());
$crypto = \WMCyber\CRA\SBOM\CryptoInventory::components([
    'hashes'  => ['md5', 'sha256', 'shake128', 'crc32b'],
    'ciphers' => ['aes-256-gcm', 'aes-128-cbc', 'rc4', 'des-ede3-cbc'],
    'tls'     => ['1.2', '1.3'],
    'openssl' => 'OpenSSL 3.5.6 7 Apr 2026',
]);
$crypto_map = array_column($crypto, null, 'name');
assert_test(
    'the weak algorithms a host still offers are in the inventory: that is what a CBOM is for',
    isset($crypto_map['md5'], $crypto_map['rc4'], $crypto_map['des-ede3-cbc']),
    implode(',', array_keys($crypto_map))
);
assert_test(
    'an extendable-output function and a checksum are not called hashes',
    'xof' === $crypto_map['shake128']['cryptoProperties']['algorithmProperties']['primitive']
        && 'other' === $crypto_map['crc32b']['cryptoProperties']['algorithmProperties']['primitive']
        && 'hash' === $crypto_map['sha256']['cryptoProperties']['algorithmProperties']['primitive']
);
assert_test(
    'an authenticating mode makes the primitive authenticated encryption, not a block cipher',
    'ae' === $crypto_map['aes-256-gcm']['cryptoProperties']['algorithmProperties']['primitive']
        && 'gcm' === $crypto_map['aes-256-gcm']['cryptoProperties']['algorithmProperties']['mode']
        && 'block-cipher' === $crypto_map['aes-128-cbc']['cryptoProperties']['algorithmProperties']['primitive']
        && 'stream-cipher' === $crypto_map['rc4']['cryptoProperties']['algorithmProperties']['primitive']
);
assert_test(
    'a key length is taken from the name and never derived for a name that states none',
    '256' === $crypto_map['aes-256-gcm']['cryptoProperties']['algorithmProperties']['parameterSetIdentifier']
        && !isset($crypto_map['rc4']['cryptoProperties']['algorithmProperties']['parameterSetIdentifier'])
);
assert_test(
    'TLS versions are protocol assets and OpenSSL is a library with its version',
    'tls' === ($crypto_map['TLS 1.3']['cryptoProperties']['protocolProperties']['type'] ?? null)
        && '1.3' === ($crypto_map['TLS 1.3']['cryptoProperties']['protocolProperties']['version'] ?? null)
        && '3.5.6' === ($crypto_map['openssl']['version'] ?? null),
    (string) json_encode($crypto_map['TLS 1.3'] ?? null)
);
// Every enum value must be one the CycloneDX 1.6 schema defines; an invented one makes the document
// invalid for every consumer, and nothing in the plugin would notice.
$cdx_primitives = ['drbg', 'mac', 'block-cipher', 'stream-cipher', 'signature', 'hash', 'pke', 'xof', 'kdf', 'key-agree', 'kem', 'ae', 'combiner', 'other', 'unknown'];
$cdx_modes      = ['cbc', 'ecb', 'ccm', 'gcm', 'cfb', 'ofb', 'ctr', 'other', 'unknown'];
$bad_enum       = [];
foreach ($crypto as $c) {
    $props = $c['cryptoProperties']['algorithmProperties'] ?? [];
    if (isset($props['primitive']) && !in_array($props['primitive'], $cdx_primitives, true)) { $bad_enum[] = $c['name'] . ':' . $props['primitive']; }
    if (isset($props['mode']) && !in_array($props['mode'], $cdx_modes, true)) { $bad_enum[] = $c['name'] . ':' . $props['mode']; }
}
assert_test('every primitive and mode is a value the CycloneDX 1.6 schema defines', [] === $bad_enum, implode(',', $bad_enum));

// The flag on the command and the setting go through the same decision, so a one-off run and the
// screen cannot produce two different documents.
$GLOBALS['mock_hooks'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE] = [];
assert_test('the CBOM stays off without the flag', false === \WMCyber\CRA\SBOM\CryptoInventory::enabled());
add_filter(\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE, '__return_true');
assert_test('the command flag switches the CBOM on for one run without touching the setting', true === \WMCyber\CRA\SBOM\CryptoInventory::enabled() && false === (bool) get_option(\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE, 0));
$GLOBALS['mock_hooks'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE] = [];

// With the setting on, the crypto assets reach the document the plugin actually serves.
$GLOBALS['mock_options'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE] = 1;
$with_crypto = (new CycloneDxGenerator())->generate_sbom();
assert_test(
    'switching the CBOM on puts cryptographic assets into the served document',
    [] !== array_filter($with_crypto['components'], static fn(array $c): bool => 'cryptographic-asset' === $c['type'])
        && [] === array_filter($sbom['components'], static fn(array $c): bool => 'cryptographic-asset' === $c['type'])
);
unset($GLOBALS['mock_options'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE]);

array_map('unlink', (array) glob($dep_root . '/*/*.lock') ?: []);
array_map('unlink', (array) glob($dep_root . '/*/*.json') ?: []);
array_map('unlink', (array) glob($dep_root . '/*/*/*.lock') ?: []);
array_map('unlink', (array) glob($dep_root . '/*/*/*/*.json') ?: []);

// =================================================================================================================
echo "\n[GROUP 6] WP-CLI\n";
// =================================================================================================================
good_options();
$db  = reset_db();
$cmd = new CraCommand();
$r   = WP_CLI::run(static fn() => $cmd->sbom_generate([], []));
$out = WP_CLI::stdout();
assert_test('sbom-generate without --output prints JSON only and stores nothing', 'ok' === $r && is_array(json_decode($out, true)) && [] === $db->tables['wp_wm_cra_sbom_snapshots'], substr($out, -120));
$db->fail_writes = true;
$r = WP_CLI::run(static fn() => $cmd->sbom_generate([], ['snapshot' => true]));
assert_test('sbom-generate --snapshot fails loudly when the insert fails', 'error' === $r);
$db->fail_writes = false;
$r = WP_CLI::run(static fn() => $cmd->sbom_generate([], ['output' => sys_get_temp_dir() . '/no-such-dir-wm-cra/x/sbom.json']));
assert_test('an unwritable --output is an error, not "Success"', 'error' === $r && !str_contains(WP_CLI::stdout(), 'Success'));

$r = WP_CLI::run(static fn() => $cmd->csaf_publish(['WM-2026-001'], ['title' => 'XSS', 'severity' => 'banana']));
assert_test('csaf-publish refuses an unknown severity', 'error' === $r && [] === $db->tables['wp_wm_cra_advisories']);
$r   = WP_CLI::run(static fn() => $cmd->csaf_publish(['WM-2026-001'], ['title' => 'Stored XSS', 'severity' => 'high']));
$doc = json_decode((string) (array_values($db->tables['wp_wm_cra_advisories'])[0]['csaf_json'] ?? ''), true);
assert_test('csaf-publish invents no CVE and no score', 'ok' === $r && !str_contains((string) json_encode($doc), 'CVE-') && !str_contains((string) json_encode($doc), 'cvss'), (string) json_encode($doc));

// =================================================================================================================
echo "\n[GROUP 7] CSAF documents and index\n";
// =================================================================================================================
good_options();
$db  = reset_db();
$pub = new CsafPublisher();
$res = $pub->publish_advisory('WM-2026-002', 'SQL injection in the search form', 'critical', ['cve' => 'CVE-2026-12345', 'description' => 'Fixed in 2.1.']);
$d   = $res['document']['document'] ?? [];
$t   = $d['tracking'] ?? [];
assert_test('document uses the base profile category', $res['saved'] && 'csaf_base' === ($d['category'] ?? ''), (string) json_encode($d));
assert_test('document has every field CSAF 2.0 requires in /document', [] === array_diff(['category', 'csaf_version', 'publisher', 'title', 'tracking'], array_keys($d)) && [] === array_diff(['category', 'name', 'namespace'], array_keys($d['publisher'] ?? [])));
assert_test('tracking has revision_history, integer version and both dates', [] === array_diff(['current_release_date', 'id', 'initial_release_date', 'revision_history', 'status', 'version'], array_keys($t)) && '1' === ($t['version'] ?? '') && 1 === count($t['revision_history'] ?? []) && [] === array_diff(['date', 'number', 'summary'], array_keys($t['revision_history'][0] ?? [])));
assert_test('severity as aggregate_severity, CVE only when given', 'critical' === ($d['aggregate_severity']['text'] ?? '') && 'CVE-2026-12345' === ($res['document']['vulnerabilities'][0]['cve'] ?? ''));
// Move the stored initial date back so a re-publication in the same second can tell kept from overwritten.
$row_id = array_key_first($db->tables['wp_wm_cra_advisories']);
$stored = json_decode((string) $db->tables['wp_wm_cra_advisories'][$row_id]['csaf_json'], true);
$stored['document']['tracking']['initial_release_date'] = '2026-01-01T00:00:00Z';
$db->tables['wp_wm_cra_advisories'][$row_id]['csaf_json'] = (string) json_encode($stored);
$res2 = $pub->publish_advisory('WM-2026-002', 'SQL injection in the search form', 'high', []);
$t2   = $res2['document']['document']['tracking'] ?? [];
assert_test('re-publication keeps the initial date, raises the version and extends the history', $res2['saved'] && '2026-01-01T00:00:00Z' === ($t2['initial_release_date'] ?? '') && '2' === ($t2['version'] ?? '') && 2 === count($t2['revision_history'] ?? []) && 1 === count($db->tables['wp_wm_cra_advisories']), (string) json_encode($t2));
assert_test('invalid CVE and empty title are refused', false === $pub->publish_advisory('WM-2026-003', 'x', 'low', ['cve' => 'CVE-2026-CRA-LOCAL'])['saved'] && false === $pub->publish_advisory('WM-2026-004', ' ', 'low')['saved']);
$feed = $pub->get_feed();
$feed_json = (string) json_encode($feed);
assert_test('index names no issuing authority and says it is not a provider feed', !str_contains($feed_json, 'issuing_authority') && !str_contains($feed_json, 'BSI') && str_contains((string) $feed['index'], 'Not a CSAF provider-metadata.json') && 1 === count($feed['advisories']));
$db->fail_writes = true;
assert_test('a failed write is reported', false === $pub->publish_advisory('WM-2026-005', 'x', 'low')['saved']);
reset_db(false);
assert_test('missing table: empty index, count 0, publish refused', [] === $pub->get_feed()['advisories'] && 0 === $pub->count_advisories() && false === $pub->publish_advisory('WM-2026-006', 'x', 'low')['saved']);

// =================================================================================================================
echo "\n[GROUP 8] Hub adapter\n";
// =================================================================================================================
good_options();
reset_db();
$adapter = new Cra_Spoke_Adapter();
assert_test('HEALTHY and self test success for a usable, confirmed file', 'HEALTHY' === $adapter->get_health_status() && true === $adapter->execute_action('self_test')['success']);
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES] = '2025-01-01T00:00:00Z';
$st = $adapter->execute_action('self_test');
assert_test('expired file: ERROR and self test failure', 'ERROR' === $adapter->get_health_status() && false === $st['success'] && str_contains($st['message'], 'expired'), (string) json_encode($st));
good_options();
unset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONFIRMED]);
assert_test('unconfirmed activation default: NEEDS_CONFIG', 'NEEDS_CONFIG' === $adapter->get_health_status());
good_options();
unset($GLOBALS['mock_options']['rewrite_rules']);
assert_test('route missing: ERROR', 'ERROR' === $adapter->get_health_status());
good_options();
reset_db(false);
assert_test('tables missing: ERROR and self test failure', 'ERROR' === $adapter->get_health_status() && false === $adapter->execute_action('self_test')['success']);
reset_db();
assert_test('settings link opens the registered page', str_contains((string) $adapter->get_settings_url(), 'page=wm-cra-beacon'));
$sbom_data = $adapter->get_sbom_data();
$lic       = $sbom_data['licenses'][0]['license'] ?? [];
assert_test('SBOM licence uses name only, properties describe features not conformance', !(isset($lic['id']) && isset($lic['name'])) && !preg_match('/compliance|TR-03183|Annex/i', (string) json_encode($sbom_data['properties'])), (string) json_encode($sbom_data));
$tm = $adapter->get_telemetry_metrics();
assert_test('telemetry reports the security.txt state, not ACTIVE for any contact', 'ok' === ($tm['security_txt_state'] ?? '') && !in_array('ACTIVE', $tm, true), (string) json_encode($tm));
$GLOBALS['wpdb']->fail_writes = true;
assert_test('generate_sbom action fails when the snapshot is not stored', false === $adapter->execute_action('generate_sbom')['success']);

// =================================================================================================================
echo "\n[GROUP 9] Admin screen and widget\n";
// =================================================================================================================
good_options();
$db     = reset_db();
$dash   = new AdminDashboard(new CycloneDxGenerator(), $handler, new CsafPublisher());
$widget = render(static fn() => $dash->render_dashboard_widget());
assert_test('widget without snapshot shows a dash, no fixed 18, no signature claim', str_contains($widget, '>–<') && !preg_match('/>\s*18\s*</', $widget) && !str_contains($widget, 'Signatur'), $widget);
unset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONFIRMED]);
$widget = render(static fn() => $dash->render_dashboard_widget());
assert_test('widget warns while the contact is unconfirmed', str_contains($widget, 'is-warning') && str_contains($widget, 'nicht bestätigt'));
good_options();
$_GET = ['page' => 'wm-cra-beacon', 'tab' => 'overview'];
$page = render(static fn() => $dash->render_dashboard_page());
assert_test('overview preview is the served file', str_contains($page, esc_html($handler->generate_security_txt_content())));
assert_test('no fixed status badges or Spanish claims', !preg_match('/CIBERRESILIENCIA|SECURITY\.TXT ACTIVO|RFC 9116 verificado|2027-08-27|Estándar oficial/u', $page));
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_EXPIRES] = '2025-01-01T00:00:00Z';
$page = render(static fn() => $dash->render_dashboard_page());
assert_test('header badge follows the expired state', str_contains($page, 'wm-badge-red') && str_contains($page, 'Abgelaufen am 2025-01-01'));
good_options();
$GLOBALS['mock_file_headers'] = [WP_PLUGIN_DIR . '/akismet/akismet.php' => 'GPLv2 or later'];
$_GET['tab'] = 'sbom';
$page = render(static fn() => $dash->render_dashboard_page());
assert_test('SBOM tab licence column shows the header licence, not the description', str_contains($page, '<td>GPLv2 or later</td>') && !str_contains($page, 'GPL-2.0+'));
assert_test('SBOM tab says when no snapshot is stored', str_contains($page, 'Noch keine Momentaufnahme'));
$_GET = [];
$GLOBALS['mock_styles'] = [];
$dash->enqueue_admin_assets('index.php');
assert_test('family sheets load on the WordPress dashboard for the widget', in_array('wm-admin-ui', $GLOBALS['mock_styles'], true));
try {
    $_POST = ['wm_cra_action' => 'publish_csaf', 'csaf_title' => 'x'];
    $dash->handle_form_actions();
    $admin_csaf = 'no redirect';
} catch (RuntimeException $e) {
    $admin_csaf = $e->getMessage();
}
$_POST = [];
assert_test('the unreachable admin CSAF path is gone', 'no redirect' === $admin_csaf && [] === $db->tables['wp_wm_cra_advisories']);

// The audit has to be reachable from the screen. The SIEM forwarder of the sibling plugin shipped
// with its settings readable only through `wp option update`, which is not a feature the operator
// has; this assertion is what stops the same thing happening here.
$GLOBALS['mock_options'][VulnerabilityAudit::OPT_STATE] = [
    'pkg:generic/wordpress-plugin/contact-form-7@5.7.1' => [ 'state' => 'checked', 'source' => 'nvd', 'checked' => '2026-09-16T10:00:00Z', 'findings' => 1, 'name' => 'contact-form-7', 'version' => '5.7.1' ],
    'pkg:generic/wordpress-plugin/akismet@5.4'          => [ 'state' => 'never_checked', 'source' => '', 'checked' => '', 'findings' => 0, 'name' => 'akismet', 'version' => '5.4' ],
];
$_GET = ['page' => 'wm-cra-beacon', 'tab' => 'vuln'];
$vuln_page = render(static fn() => $dash->render_dashboard_page());
assert_test('the vulnerability tab exists and is reachable', str_contains($vuln_page, 'Schwachstellen'), substr($vuln_page, 0, 200));
assert_test(
    'an unchecked component is shown as unchecked, never as a clean one',
    str_contains($vuln_page, 'noch nie geprüft') && str_contains($vuln_page, 'Eine nicht geprüfte Komponente ist keine unauffällige Komponente'),
    $vuln_page
);
assert_test('the switch and the API key field are on the screen, not only in wp option update', str_contains($vuln_page, 'name="vuln_enabled"') && str_contains($vuln_page, 'name="nvd_api_key"'));
assert_test('the stored API key is never printed back into the form', !str_contains($vuln_page, 'value="secret-key-value"'));
$_GET = [];
unset($GLOBALS['mock_options'][VulnerabilityAudit::OPT_STATE]);

// The key raises a rate limit; a value that cannot be one is not stored, so the client falls back
// to the slower budget instead of sending a header the API will reject.
$GLOBALS['mock_cron'] = [];
try {
    $_POST = ['wm_cra_action' => 'save_vuln_options', 'vuln_enabled' => '1', 'nvd_api_key' => 'not a key!!'];
    $dash->handle_form_actions();
} catch (RuntimeException $e) {
    // redirect
}
$_POST = [];
assert_test('the audit switch and the schedule follow the form', 1 === (int) get_option(VulnerabilityAudit::OPT_ENABLED, 0) && false !== wp_next_scheduled(VulnerabilityAudit::CRON_HOOK));
assert_test('a malformed NVD key is not stored', '' === (string) get_option(NvdClient::OPT_API_KEY, 'x'));
try {
    $_POST = ['wm_cra_action' => 'save_vuln_options', 'nvd_api_key' => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'];
    $dash->handle_form_actions();
} catch (RuntimeException $e) {
    // redirect
}
$_POST = [];
assert_test('a well-formed key is stored and switching the audit off removes the schedule', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' === (string) get_option(NvdClient::OPT_API_KEY, '') && false === wp_next_scheduled(VulnerabilityAudit::CRON_HOOK));
assert_test('a key raises the budget, because it raises the rate limit', NvdClient::BUDGET_WITH_KEY === NvdClient::budget() && NvdClient::PAUSE_WITH_KEY === NvdClient::pause());
delete_option(NvdClient::OPT_API_KEY);
assert_test('without a key the slower budget applies', NvdClient::BUDGET_WITHOUT_KEY === NvdClient::budget());
$GLOBALS['mock_options'][VulnerabilityAudit::OPT_ENABLED] = 1;

// =================================================================================================================
echo "\n[GROUP 10] Public portal\n";
// =================================================================================================================
good_options();
reset_db();
$portal = new PsirtPortal(new CsafPublisher(), $handler);
$html   = $portal->render_portal();
assert_test('empty portal states no patch level and no official status', str_contains($html, 'keine Sicherheitshinweise veröffentlicht') && !preg_match('/Patch-Stand|Offizielle|TR-03183/u', $html));
assert_test('portal shows the served contact', str_contains($html, 'security@example.test'));
(new CsafPublisher())->publish_advisory('WM-2026-010', 'Open redirect', 'medium');
$html = $portal->render_portal();
assert_test('advisory without CVE or score shows none', str_contains($html, 'Open redirect') && !str_contains($html, 'CVE-2026') && !str_contains($html, 'CVSS') && str_contains($html, 'Schweregrad: medium'));

// =================================================================================================================
echo "\n[GROUP 11] Source checks\n";
// =================================================================================================================
$root       = dirname(__DIR__);
$plugin_src = (string) file_get_contents($root . '/includes/Core/Plugin.php');
assert_test('no site-wide RequestShield or DirectoryProtector call', 0 === preg_match('/RequestShield::|DirectoryProtector::/', $plugin_src));
assert_test('the five unused security classes are gone', !is_dir($root . '/includes/Security'));
foreach (['includes/Database/Schema.php', 'includes/SBOM/CycloneDxGenerator.php'] as $rel) {
    assert_test("ABSPATH guard in {$rel}", str_contains((string) file_get_contents($root . '/' . $rel), "defined( 'ABSPATH' )"));
}
$emoji = '/[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{FE0F}]/u';
$ui    = (string) file_get_contents($root . '/includes/Admin/AdminDashboard.php') . (string) file_get_contents($root . '/includes/Frontend/PsirtPortal.php');
assert_test('no emoji in admin or portal source', 0 === preg_match($emoji, $ui));

// =================================================================================================================
echo "\n[GROUP 11a] Vulnerability audit: OSV, NVD and what neither of them covers\n";
// =================================================================================================================
// Shapes recorded from live responses on 2026-09-16, not invented: the NVD 2.0 cpeMatch carries
// `criteria`, `vulnerable` and up to four bounds, and the eleventh field of the CPE is target_sw.

$wp_cpe    = 'cpe:2.3:a:rocklobster:contact_form_7:*:*:*:*:*:wordpress:*:*';
$other_cpe = 'cpe:2.3:a:someone:contact_form_7:*:*:*:*:*:windows:*:*';

assert_test('target_sw is what separates a WordPress plugin from unrelated software with the same name', CpeMatcher::targets_wordpress($wp_cpe) && !CpeMatcher::targets_wordpress($other_cpe));
assert_test('a WordPress slug becomes the CPE product name without a vendor being guessed', 'contact_form_7' === CpeMatcher::product_from_slug('Contact-Form-7'));
assert_test('a Composer v prefix is not part of the version number', '5.4.45' === CpeMatcher::normalise('v5.4.45') && '' === CpeMatcher::normalise('*'));

$upper = ['criteria' => $wp_cpe, 'vulnerable' => true, 'versionEndExcluding' => '5.9.2'];
assert_test('a version below an exclusive upper bound is affected, one at the bound is not', CpeMatcher::matches($upper, '5.9.1', 'contact_form_7') && !CpeMatcher::matches($upper, '5.9.2', 'contact_form_7'));
$inclusive = ['criteria' => $wp_cpe, 'vulnerable' => true, 'versionEndIncluding' => '3.7.1'];
assert_test('a version at an inclusive upper bound is affected', CpeMatcher::matches($inclusive, '3.7.1', 'contact_form_7') && !CpeMatcher::matches($inclusive, '3.7.2', 'contact_form_7'));
$window = ['criteria' => $wp_cpe, 'vulnerable' => true, 'versionStartIncluding' => '4.0', 'versionEndExcluding' => '5.0'];
assert_test('a window excludes what is below its start', !CpeMatcher::matches($window, '3.9', 'contact_form_7') && CpeMatcher::matches($window, '4.2', 'contact_form_7'));
assert_test('a match on other software is not a match here', !CpeMatcher::matches(['criteria' => $other_cpe, 'vulnerable' => true, 'versionEndExcluding' => '9.9'], '1.0', 'contact_form_7'));
// `vulnerable: false` marks a platform the vulnerability needs, not the affected product; reading it
// as a hit would report the operating system as vulnerable.
assert_test('a non-vulnerable platform entry is not a finding', !CpeMatcher::matches(['criteria' => $wp_cpe, 'vulnerable' => false, 'versionEndExcluding' => '9.9'], '1.0', 'contact_form_7'));
assert_test('a component with no version is not declared unaffected', !CpeMatcher::matches($upper, '', 'contact_form_7'));
$pinned = ['criteria' => 'cpe:2.3:a:rocklobster:contact_form_7:3.7:*:*:*:*:wordpress:*:*', 'vulnerable' => true];
assert_test('a pinned version in the criteria matches only that version', CpeMatcher::matches($pinned, '3.7', 'contact_form_7') && !CpeMatcher::matches($pinned, '3.8', 'contact_form_7'));

// A CVE scored under both v2 and v3.1 is a v3.1 score; reporting the v2 number would understate it.
$both = ['metrics' => [
    'cvssMetricV2'  => [['cvssData' => ['baseScore' => 5.0], 'baseSeverity' => 'MEDIUM']],
    'cvssMetricV31' => [['cvssData' => ['baseScore' => 9.8, 'baseSeverity' => 'CRITICAL']]],
]];
$sev = CpeMatcher::severity_of($both);
assert_test('the newer CVSS metric wins and nothing is computed when there is none', 9.8 === $sev['score'] && 'critical' === $sev['severity'] && null === CpeMatcher::severity_of([])['score']);

$nvd_body = [
    'totalResults'    => 2,
    'vulnerabilities' => [
        ['cve' => [
            'id'             => 'CVE-2024-2242',
            'published'      => '2024-03-13T00:00:00.000',
            'descriptions'   => [['lang' => 'de', 'value' => 'ignoriert'], ['lang' => 'en', 'value' => 'Reflected XSS in Contact Form 7.']],
            'metrics'        => ['cvssMetricV31' => [['cvssData' => ['baseScore' => 6.1, 'baseSeverity' => 'MEDIUM']]]],
            'configurations' => [['nodes' => [['cpeMatch' => [['vulnerable' => true, 'criteria' => $wp_cpe, 'versionEndExcluding' => '5.9.2']]]]]],
        ]],
        ['cve' => [
            'id'             => 'CVE-2014-2265',
            'published'      => '2014-03-14T00:00:00.000',
            'descriptions'   => [['lang' => 'en', 'value' => 'CAPTCHA bypass before 3.7.2.']],
            'metrics'        => ['cvssMetricV2' => [['cvssData' => ['baseScore' => 5.0], 'baseSeverity' => 'MEDIUM']]],
            'configurations' => [['nodes' => [['cpeMatch' => [['vulnerable' => true, 'criteria' => $wp_cpe, 'versionEndIncluding' => '3.7.1']]]]]],
        ]],
    ],
];
$affected = NvdClient::findings_from($nvd_body, 'contact_form_7', '5.7.1');
assert_test('only the CVE whose range contains the installed version is reported', ['CVE-2024-2242'] === array_column($affected['findings'], 'cve'), (string) json_encode(array_column($affected['findings'], 'cve')));
assert_test('the finding carries the English description and the CVSS the database states', 'Reflected XSS in Contact Form 7.' === $affected['findings'][0]['summary'] && 6.1 === $affected['findings'][0]['score'] && 'medium' === $affected['findings'][0]['severity']);
assert_test('a version past every range produces no finding', [] === NvdClient::findings_from($nvd_body, 'contact_form_7', '6.0')['findings']);
// Not having a version to compare is not the same as having compared and found nothing.
$no_version = NvdClient::findings_from($nvd_body, 'contact_form_7', '');
assert_test('a component without a version is an error, never an empty clean result', [] === $no_version['findings'] && null !== $no_version['error']);
assert_test('a truncated page is reported as truncated', true === NvdClient::findings_from(['totalResults' => 500, 'vulnerabilities' => []], 'x', '1.0')['truncated']);
assert_test('the query asks for the product with a wildcard vendor, never a guessed one', str_contains(NvdClient::url('contact_form_7'), 'cpe%3A2.3%3Aa%3A%2A%3Acontact_form_7') || str_contains(urldecode(NvdClient::url('contact_form_7')), 'cpe:2.3:a:*:contact_form_7'), NvdClient::url('contact_form_7'));

// OSV: only the ecosystems it holds data for. WordPress components must never be sent here — the
// API accepts the ecosystem and answers {} for everything, which reads exactly like a clean result.
assert_test(
    'only Composer and npm purls go to OSV',
    ['pkg:composer/monolog/monolog@3.5.0', 'pkg:npm/lodash@4.17.21'] === OsvClient::supported(['pkg:composer/monolog/monolog@3.5.0', 'pkg:generic/wordpress-plugin/akismet@5.4', 'pkg:npm/lodash@4.17.21', 'pkg:generic/php@8.3'])
);
$batch = ['results' => [[], ['vulns' => [['id' => 'GHSA-1111-aaaa-bbbb'], ['id' => 'CVE-2021-23337']]], []]];
$ids   = OsvClient::ids_by_purl($batch, ['pkg:composer/a/a@1.0', 'pkg:npm/lodash@4.17.15', 'pkg:npm/b@2.0']);
assert_test(
    'the batch answer is read by position, which is the only thing that identifies it',
    ['pkg:npm/lodash@4.17.15' => ['GHSA-1111-aaaa-bbbb', 'CVE-2021-23337']] === $ids,
    (string) json_encode($ids)
);
$finding = OsvClient::finding('GHSA-1111-aaaa-bbbb', ['aliases' => ['CVE-2021-23337'], 'summary' => 'ReDoS', 'severity' => [['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H']]]);
assert_test('the CVE alias is used and the CVSS vector kept as stated, with no score computed from it', 'CVE-2021-23337' === $finding['cve'] && str_starts_with($finding['cvss_vector'], 'CVSS:3.1/') && null === $finding['score']);

$sbom_for_audit = ['components' => [
    ['type' => 'framework',   'name' => 'wordpress-core', 'version' => '6.8.2', 'purl' => 'pkg:generic/wordpress@6.8.2'],
    ['type' => 'application', 'name' => 'contact-form-7', 'version' => '5.7.1', 'purl' => 'pkg:generic/wordpress-plugin/contact-form-7@5.7.1'],
    ['type' => 'library',     'name' => 'monolog/monolog', 'version' => '3.5.0', 'purl' => 'pkg:composer/monolog/monolog@3.5.0'],
    ['type' => 'library',     'name' => 'php-ext-openssl', 'version' => '3.5.6', 'purl' => 'pkg:generic/php-ext/openssl@3.5.6'],
    ['type' => 'platform',    'name' => 'php',             'version' => '8.3.33', 'purl' => 'pkg:generic/php@8.3.33'],
    ['type' => 'cryptographic-asset', 'name' => 'md5', 'purl' => 'pkg:generic/algorithm/md5'],
]];
$split = VulnerabilityAudit::split_components($sbom_for_audit);
assert_test(
    'each source is asked only about what it holds; the runtime and the crypto assets are asked of neither',
    ['pkg:generic/wordpress@6.8.2', 'pkg:generic/wordpress-plugin/contact-form-7@5.7.1'] === array_column($split['wordpress'], 'purl')
        && ['pkg:composer/monolog/monolog@3.5.0'] === array_column($split['packages'], 'purl'),
    (string) json_encode([array_column($split['wordpress'], 'purl'), array_column($split['packages'], 'purl')])
);

$five = [['slug' => 'a', 'version' => '1', 'purl' => 'a'], ['slug' => 'b', 'version' => '1', 'purl' => 'b'], ['slug' => 'c', 'version' => '1', 'purl' => 'c'], ['slug' => 'd', 'version' => '1', 'purl' => 'd'], ['slug' => 'e', 'version' => '1', 'purl' => 'e']];
$first_pass  = VulnerabilityAudit::slice($five, 0, 2);
$second_pass = VulnerabilityAudit::slice($five, $first_pass['next'], 2);
$third_pass  = VulnerabilityAudit::slice($five, $second_pass['next'], 2);
assert_test(
    'the cursor walks the whole list across runs and wraps round',
    ['a', 'b'] === array_column($first_pass['items'], 'purl') && ['c', 'd'] === array_column($second_pass['items'], 'purl') && ['e', 'a'] === array_column($third_pass['items'], 'purl'),
    (string) json_encode([array_column($second_pass['items'], 'purl'), array_column($third_pass['items'], 'purl')])
);

// End to end, with both databases answered from fixtures.
$db = reset_db();
$db->tables['wp_wm_cra_vulnerabilities'] = [];
$GLOBALS['mock_options'] = ['active_plugins' => []];
$GLOBALS['mock_cron'] = [];
$GLOBALS['mock_http_requests'] = [];
add_filter('wm_cra_nvd_pause', static fn() => 0);
$GLOBALS['mock_http'] = [
    'api.osv.dev/v1/querybatch' => ['response' => ['code' => 200], 'body' => (string) json_encode(['results' => [['vulns' => [['id' => 'GHSA-xxxx-yyyy-zzzz']]]]])],
    'api.osv.dev/v1/vulns/'     => ['response' => ['code' => 200], 'body' => (string) json_encode(['id' => 'GHSA-xxxx-yyyy-zzzz', 'summary' => 'Something in monolog', 'aliases' => ['CVE-2099-0001']])],
    'services.nvd.nist.gov'     => ['response' => ['code' => 200], 'body' => (string) json_encode($nvd_body)],
];
$audit   = new VulnerabilityAudit(new CycloneDxGenerator());
$summary = $audit->run('cli', $sbom_for_audit);
$state   = VulnerabilityAudit::state();
assert_test('the OSV finding is recorded against the package that carries it', 'checked' === $state['pkg:composer/monolog/monolog@3.5.0']['state'] && 1 === $state['pkg:composer/monolog/monolog@3.5.0']['findings'], (string) json_encode($state['pkg:composer/monolog/monolog@3.5.0'] ?? null));
assert_test('the NVD finding is recorded against the plugin whose installed version is in range', 1 === ($state['pkg:generic/wordpress-plugin/contact-form-7@5.7.1']['findings'] ?? -1), (string) json_encode($state['pkg:generic/wordpress-plugin/contact-form-7@5.7.1'] ?? null));
$stored = VulnerabilityAudit::findings();
assert_test('both findings are stored with the advisory that produced them', 2 === count($stored) && ['CVE-2024-2242', 'CVE-2099-0001'] === array_column($stored, 'cve_id'), (string) json_encode(array_column($stored, 'cve_id')));
// Nothing was sent to OSV about a WordPress component, and nothing to NVD about a Composer package.
$osv_bodies = implode(' ', array_column(array_filter($GLOBALS['mock_http_requests'], static fn(array $r): bool => str_contains($r['url'], 'osv.dev')), 'body'));
$nvd_urls   = implode(' ', array_column(array_filter($GLOBALS['mock_http_requests'], static fn(array $r): bool => str_contains($r['url'], 'nist.gov')), 'url'));
assert_test('no WordPress component is sent to OSV, where every answer would be an empty one', !str_contains($osv_bodies, 'wordpress-plugin') && !str_contains($osv_bodies, 'pkg:generic'), $osv_bodies);
assert_test('no Composer package is sent to NVD by a name it does not index', !str_contains($nvd_urls, 'monolog'), $nvd_urls);

// A source that could not be reached must not leave its components looking clean.
$db = reset_db();
$db->tables['wp_wm_cra_vulnerabilities'] = [];
$GLOBALS['mock_options'] = ['active_plugins' => []];
$GLOBALS['mock_http'] = [
    'api.osv.dev' => ['response' => ['code' => 503], 'body' => ''],
    'services.nvd.nist.gov' => ['response' => ['code' => 503], 'body' => ''],
];
$down = (new VulnerabilityAudit(new CycloneDxGenerator()))->run('cli', $sbom_for_audit);
$down_state = VulnerabilityAudit::state();
assert_test(
    'an unreachable database leaves every component in source_error, not in checked',
    'source_error' === ($down_state['pkg:composer/monolog/monolog@3.5.0']['state'] ?? '')
        && 'source_error' === ($down_state['pkg:generic/wordpress-plugin/contact-form-7@5.7.1']['state'] ?? '')
        && 0 === $down['counts']['checked'],
    (string) json_encode($down['counts'])
);
assert_test('a run that could not reach everything does not report itself complete', false === $down['complete']);

// With a budget smaller than the component list, the rest is never_checked — which is a state the
// screen shows, not a silent pass.
$db = reset_db();
$db->tables['wp_wm_cra_vulnerabilities'] = [];
$GLOBALS['mock_options'] = ['active_plugins' => []];
$GLOBALS['mock_http'] = ['services.nvd.nist.gov' => ['response' => ['code' => 200], 'body' => (string) json_encode(['totalResults' => 0, 'vulnerabilities' => []])], 'api.osv.dev' => ['response' => ['code' => 200], 'body' => '{"results":[{}]}']];
$partial = (new VulnerabilityAudit(new CycloneDxGenerator()))->run('cli', $sbom_for_audit);
$partial_state = VulnerabilityAudit::state();
// Every component the audit covers carries a state, and the four states add up to the component
// count: nothing falls out of the map into an implicit pass. (An earlier version of this assertion
// ended in `|| count >= 0`, which is true whatever happens — measured and removed 2026-09-16.)
assert_test(
    'every covered component carries one of the four states and none of them is an implicit pass',
    3 === $partial['components']
        && 3 === count($partial_state)
        && 3 === array_sum($partial['counts'])
        && [] === array_diff(array_column($partial_state, 'state'), ['checked', 'never_checked', 'unknown_version', 'source_error']),
    (string) json_encode([$partial['counts'], array_column($partial_state, 'state')])
);
$GLOBALS['mock_http'] = [];
$GLOBALS['mock_hooks']['wm_cra_nvd_pause'] = [];

// =================================================================================================================
echo "\n[GROUP 11c] SPDX 3.0.1 and OpenVEX\n";
// =================================================================================================================
// Every term and every vocabulary entry below was read from the published specifications on
// 2026-09-16. SPDX 3 renamed what SPDX 2 users know, and the names that look right are the wrong ones.
$spdx_inventory = ['metadata' => ['component' => ['type' => 'application', 'name' => 'Example Site']], 'components' => [
    ['type' => 'framework',   'name' => 'wordpress-core', 'version' => '6.8.2', 'purl' => 'pkg:generic/wordpress@6.8.2', 'licenses' => [['license' => ['name' => 'GPLv2 or later']]]],
    ['type' => 'application', 'name' => 'noversion',      'purl' => 'pkg:generic/wordpress-plugin/noversion'],
    ['type' => 'library',     'name' => 'monolog/monolog', 'version' => '3.5.0', 'purl' => 'pkg:composer/monolog/monolog@3.5.0'],
    ['type' => 'cryptographic-asset', 'name' => 'md5', 'purl' => 'pkg:generic/algorithm/md5'],
    // A type the map does not cover. Without a component like this one the fallback never runs and
    // the vocabulary check measures nothing — which is exactly how its mutation SURVIVED once.
    ['type' => 'machine-learning-model', 'name' => 'some-model', 'version' => '1.0', 'purl' => 'pkg:generic/model/some-model@1.0'],
]];
$spdx = (new Spdx3Generator())->generate($spdx_inventory);
$spdx_flat = (string) json_encode($spdx);
$spdx_by_type = [];
foreach ($spdx['@graph'] as $node) { $spdx_by_type[$node['type']][] = $node; }

assert_test('the document carries the context that resolves and the version it conforms to', Spdx3Generator::CONTEXT === $spdx['@context'] && '3.0.1' === $spdx_by_type['CreationInfo'][0]['specVersion']);
// `Package` is not in the SPDX 3.0.1 context at all; the class is `software_Package`. Writing the
// SPDX 2 name produces a document that validates against nothing, and nothing here would notice.
// One node per component plus the site itself as the root package.
assert_test(
    'packages use the profile-prefixed class name, which is the only one the 3.0.1 context defines',
    1 + count($spdx_inventory['components']) === count($spdx_by_type['software_Package'] ?? [])
        && 0 === preg_match('/"type"\s*:\s*"Package"/', $spdx_flat),
    implode(',', array_keys($spdx_by_type)) . ' | packages=' . count($spdx_by_type['software_Package'] ?? [])
);
$spdx_packages = array_column($spdx_by_type['software_Package'], null, 'name');
assert_test('a version uses the profile-prefixed property', '6.8.2' === ($spdx_packages['wordpress-core']['software_packageVersion'] ?? null));
assert_test('a component the inventory has no version for gets none here either', !isset($spdx_packages['noversion']['software_packageVersion']));
assert_test(
    'the purl is both a package URL and an external identifier of the type SPDX defines for it',
    'pkg:composer/monolog/monolog@3.5.0' === ($spdx_packages['monolog/monolog']['software_packageUrl'] ?? null)
        && 'packageUrl' === ($spdx_packages['monolog/monolog']['externalIdentifier'][0]['externalIdentifierType'] ?? null)
);
// A licence taken from a free-text file header is not an SPDX identifier, so it is a comment rather
// than a declared licence the plugin cannot verify.
assert_test('a header licence is a comment, never a declared SPDX licence', str_contains((string) ($spdx_packages['wordpress-core']['comment'] ?? ''), 'GPLv2 or later') && !str_contains($spdx_flat, 'hasDeclaredLicense'));

// Every vocabulary entry the generator can emit, checked against the lists read from the spec.
$spdx_purposes = ['application','archive','bom','configuration','container','data','device','deviceDriver','diskImage','documentation','evidence','executable','file','filesystemImage','firmware','framework','install','library','manifest','model','module','operatingSystem','other','patch','platform','requirement','source','specification','test'];
$spdx_relationships = ['affects','amendedBy','ancestorOf','availableFrom','configures','contains','coordinatedBy','copiedTo','delegatedTo','dependsOn','descendantOf','describes','doesNotAffect','expandsTo','exploitCreatedBy','fixedBy','fixedIn','foundBy','generates','hasAddedFile','hasAssessmentFor','hasAssociatedVulnerability','hasConcludedLicense','hasDataFile','hasDeclaredLicense','hasDeletedFile','hasDependencyManifest','hasDistributionArtifact','hasDocumentation','hasDynamicLink','hasEvidence','hasExample','hasHost','hasInput','hasMetadata','hasOptionalComponent','hasOptionalDependency','hasOutput','hasPrerequisite','hasProvidedDependency','hasRequirement','hasSpecification','hasStaticLink','hasTest','hasTestCase','hasVariant','invokedBy','modifiedBy','other','packagedBy','patchedBy','publishedBy','reportedBy','republishedBy','serializedInArtifact','testedOn','trainedOn','underInvestigationFor','usesTool'];
$spdx_sbom_types = ['analyzed','build','deployed','design','runtime','source'];
$spdx_identifier_types = ['cpe22','cpe23','cve','email','gitoid','other','packageUrl','securityOther','swhid','swid','urlScheme'];
$bad_spdx = array_values(array_diff(Spdx3Generator::PURPOSE, $spdx_purposes));
foreach ($spdx['@graph'] as $node) {
    if (isset($node['software_primaryPurpose']) && !in_array($node['software_primaryPurpose'], $spdx_purposes, true)) { $bad_spdx[] = 'purpose:' . $node['software_primaryPurpose']; }
    if (isset($node['relationshipType']) && !in_array($node['relationshipType'], $spdx_relationships, true)) { $bad_spdx[] = 'relationship:' . $node['relationshipType']; }
    foreach ((array) ($node['software_sbomType'] ?? []) as $t) { if (!in_array($t, $spdx_sbom_types, true)) { $bad_spdx[] = 'sbomType:' . $t; } }
    foreach ((array) ($node['externalIdentifier'] ?? []) as $e) { if (!in_array($e['externalIdentifierType'], $spdx_identifier_types, true)) { $bad_spdx[] = 'identifier:' . $e['externalIdentifierType']; } }
}
assert_test('every vocabulary entry is one the SPDX 3.0.1 specification defines', [] === $bad_spdx, implode(',', $bad_spdx));
assert_test('the SBOM element says it describes deployed software, which is what the plugin can see', ['deployed'] === ($spdx_by_type['software_Sbom'][0]['software_sbomType'] ?? null));
// Two serialisations of one measurement. A second format that disagreed with the first would be
// worse than not shipping one.
assert_test(
    'the SPDX document names exactly the components the CycloneDX document does, with the same versions',
    count($spdx_inventory['components']) === count($spdx_by_type['software_Package']) - 1
        && array_column($spdx_inventory['components'], 'name') === array_values(array_filter(array_column($spdx_by_type['software_Package'], 'name'), static fn(string $n): bool => 'Example Site' !== $n)),
    implode(',', array_column($spdx_by_type['software_Package'], 'name'))
);
assert_test('the identifiers are stable per site, so two runs are comparable', str_starts_with(Spdx3Generator::namespace_iri(), 'https://demo.example.test/spdx/'));

// OpenVEX.
$GLOBALS['mock_options'] = ['permalink_structure' => '/%postname%/'];
$vex_findings = [
    ['component_purl' => 'pkg:composer/monolog/monolog@3.5.0', 'source' => 'osv', 'advisory_id' => 'GHSA-aaaa', 'cve_id' => 'CVE-2099-0001', 'severity' => 'high', 'cvss_score' => 7.5, 'summary' => 'Something', 'detected_at' => '2026-09-16 10:00:00'],
];
$vex = OpenVexEngine::document([], $vex_findings);
assert_test('the document carries the fields the specification requires', OpenVexEngine::CONTEXT === $vex['@context'] && isset($vex['@id'], $vex['author'], $vex['timestamp'], $vex['version'], $vex['statements']));
// The very first statement is a content change like any other. Measured on a local WordPress install: reading the
// stored counter directly made the empty document and the one-statement document both version 1.
$vex_empty_version = OpenVexEngine::document([], [])['version'];
OpenVexEngine::record('pkg:first', 'CVE-0000-0000', 'fixed');
assert_test('the first statement changes the document version, not only the later ones', OpenVexEngine::document([], [])['version'] > $vex_empty_version, $vex_empty_version . ' -> ' . OpenVexEngine::document([], [])['version']);
assert_test('the document IRI follows the version, because the content did', str_ends_with(OpenVexEngine::document_iri(), '/vex/' . OpenVexEngine::version()));
delete_option(OpenVexEngine::OPT_STATEMENTS);
// Nobody has assessed this finding, and VEX has a label for exactly that. Publishing it as
// not_affected would be the plugin making a claim on the operator's behalf.
assert_test('a finding nobody has assessed is published as under_investigation', 'under_investigation' === $vex['statements'][0]['status'] && 'CVE-2099-0001' === $vex['statements'][0]['vulnerability']['name']);
assert_test('the product is identified by its purl, which is what the SBOM lists', 'pkg:composer/monolog/monolog@3.5.0' === $vex['statements'][0]['products'][0]['@id']);

assert_test('an unknown status is refused', false === OpenVexEngine::record('pkg:x', 'CVE-1', 'probably_fine')['saved']);
// The specification requires one of the two for not_affected; a bare "not affected" would publish an
// assertion nobody can check.
assert_test('not_affected without a justification or an impact statement is refused', false === OpenVexEngine::record('pkg:x', 'CVE-1', 'not_affected')['saved']);
assert_test('a justification outside the VEX catalogue is refused', false === OpenVexEngine::record('pkg:x', 'CVE-1', 'not_affected', ['justification' => 'we_looked_and_its_fine'])['saved']);
assert_test('affected without an action statement is refused', false === OpenVexEngine::record('pkg:x', 'CVE-1', 'affected')['saved']);
assert_test('a catalogue justification is accepted', true === OpenVexEngine::record('pkg:composer/monolog/monolog@3.5.0', 'CVE-2099-0001', 'not_affected', ['justification' => 'vulnerable_code_not_in_execute_path'])['saved']);

$vex = OpenVexEngine::document([], $vex_findings);
assert_test('the recorded position replaces under_investigation for that finding', 'not_affected' === $vex['statements'][0]['status'] && 'vulnerable_code_not_in_execute_path' === $vex['statements'][0]['justification']);
$vex_version = $vex['version'];
// Both timestamps are generated in the same second, so comparing them measures nothing. The stored
// date is pushed into the past first; only then does resetting it look different from keeping it.
$vex_stored = get_option(OpenVexEngine::OPT_STATEMENTS, []);
$vex_stored[OpenVexEngine::key('pkg:composer/monolog/monolog@3.5.0', 'CVE-2099-0001')]['first_issued'] = '2026-01-02T03:04:05Z';
update_option(OpenVexEngine::OPT_STATEMENTS, $vex_stored);
$vex_first_issued = '2026-01-02T03:04:05Z';

assert_test('an impact statement is an accepted alternative to a label', true === OpenVexEngine::record('pkg:y', 'CVE-2', 'not_affected', ['impact_statement' => 'The function is never called on this site.'])['saved']);
assert_test('the document version changes whenever its content does, as the specification requires', OpenVexEngine::document([], $vex_findings)['version'] > $vex_version);

OpenVexEngine::record('pkg:composer/monolog/monolog@3.5.0', 'CVE-2099-0001', 'fixed');
$vex = OpenVexEngine::document([], $vex_findings);
assert_test(
    'a restatement raises the statement version and keeps the date the position was first taken',
    'fixed' === $vex['statements'][0]['status'] && 2 === $vex['statements'][0]['version'] && $vex_first_issued === $vex['statements'][0]['timestamp'],
    (string) json_encode($vex['statements'][0])
);
// Withdrawing a statement because the scan no longer reports the finding would leave a consumer
// holding the old finding and no answer.
$vex_without = OpenVexEngine::document([], []);
assert_test('a statement about a finding the scan no longer reports stays in the document', 2 === count($vex_without['statements']), (string) json_encode(array_column($vex_without['statements'], 'status')));

$vex_statuses = ['not_affected','affected','fixed','under_investigation'];
$vex_bad = [];
foreach ($vex_without['statements'] as $st) {
    if (!in_array($st['status'], $vex_statuses, true)) { $vex_bad[] = 'status:' . $st['status']; }
    if (isset($st['justification']) && !in_array($st['justification'], OpenVexEngine::JUSTIFICATIONS, true)) { $vex_bad[] = 'justification:' . $st['justification']; }
}
assert_test('every status and justification is one the VEX specification defines', [] === $vex_bad && OpenVexEngine::JUSTIFICATIONS === ['component_not_present','vulnerable_code_not_present','vulnerable_code_not_in_execute_path','vulnerable_code_cannot_be_controlled_by_adversary','inline_mitigations_already_exist'], implode(',', $vex_bad));
// The author must be an identity somebody agreed to. An unconfirmed contact is a guess the plugin
// wrote on activation, so the site URL stands in instead of naming a person who never agreed.
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONTACT] = 'mailto:security@example.test';
unset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONFIRMED]);
assert_test('a contact the plugin guessed on activation is not published as the document author', 'https://demo.example.test' === OpenVexEngine::author());
$GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONFIRMED] = '2026-09-16T10:00:00Z';
assert_test('a confirmed contact is', 'mailto:security@example.test' === OpenVexEngine::author());
$GLOBALS['mock_options'] = [];

// =================================================================================================================
echo "\n[GROUP 11b] WP-CLI command synopsis\n";
// =================================================================================================================
// WP-CLI builds the synopsis from the "## OPTIONS" block of the docblock. Measured on a local WordPress install
// 2026-09-16: a parameter whose description is spread over two ": " lines makes WP-CLI treat the
// words of the first line as synopsis parts and print one warning per word on STDOUT — which also
// destroys the JSON pipe the command promises. One ": " line per parameter.
$cli_src = (string) file_get_contents(WM_CRA_PATH . 'includes/CLI/CraCommand.php');
$synopsis_faults = [];
foreach (explode('/**', $cli_src) as $doc) {
    $options = strstr($doc, '## OPTIONS');
    if (false === $options) {
        continue;
    }
    $options = strstr($options, '## EXAMPLES', true) ?: $options;
    // Only the measured rule: two ": " lines in a row. WP-CLI's own grammar for the token lines
    // (brackets, <required>, --flag=<value>, YAML "options:" blocks) is not reimplemented here —
    // guessing at it would trade a real check for an invented one.
    $consecutive = 0;
    foreach (explode("\n", $options) as $raw) {
        $line = trim(ltrim(trim($raw), '*'));
        if (str_starts_with($line, ':')) {
            if (++$consecutive > 1) {
                $synopsis_faults[] = $line;
            }
            continue;
        }
        $consecutive = 0;
    }
}
assert_test('every WP-CLI parameter has exactly one description line, which is what the synopsis parser accepts', [] === $synopsis_faults, implode(' | ', $synopsis_faults));

// =================================================================================================================
echo "\n[GROUP 12] Uninstall (default statutory retention vs opt-in deletion)\n";
// =================================================================================================================
good_options();
$GLOBALS['mock_options']['wm_cra_settings'] = ['security_email' => 'x@example.test'];
$GLOBALS['mock_options']['wm_cra_sbom_include_crypto'] = 1;
$GLOBALS['mock_options']['wm_cra_public_endpoints'] = 0;
$GLOBALS['mock_options']['wm_cra_api_token_hash'] = str_repeat('a', 64);
$GLOBALS['mock_options']['wm_cra_cache_bust'] = 2;
$GLOBALS['mock_options']['wm_cra_vuln_enabled'] = 1;
$GLOBALS['mock_options']['wm_cra_nvd_api_key'] = '';
$GLOBALS['mock_options']['wm_cra_vuln_state'] = ['pkg:x' => ['state' => 'checked']];
$GLOBALS['mock_options']['wm_cra_vuln_cursor'] = 3;
$GLOBALS['mock_options']['wm_cra_vex_statements'] = ['pkg:x|CVE-1' => ['status' => 'fixed']];
$GLOBALS['mock_options']['wm_cra_vex_version'] = 4;
$db = reset_db();
$db->tables['wp_wm_cra_audit_log'] = [];
$db->tables['wp_wm_cra_vulnerabilities'] = [];
$base = sys_get_temp_dir() . '/wm-cra-suite-uploads-' . getmypid();
@mkdir($base . '/wm-cra/sbom', 0777, true);
foreach (['.htaccess', 'web.config', 'index.php', 'index.html'] as $guard) {
    file_put_contents($base . '/wm-cra/sbom/' . $guard, 'x');
}
$GLOBALS['mock_uploads_basedir'] = $base;
define('WP_UNINSTALL_PLUGIN', 'wm-cra-sbom-beacon/wm-cra-sbom-beacon.php');

// 12a: Default uninstall (wm_cra_beacon_delete_data_on_uninstall = 0) preserves options and all tables.
require $root . '/uninstall.php';
assert_test(
    'default uninstall preserves all options and the 3 CRA Beacon tables when wm_cra_beacon_delete_data_on_uninstall is 0',
    isset($db->tables['wp_wm_cra_sbom_snapshots'], $db->tables['wp_wm_cra_advisories'], $db->tables['wp_wm_cra_vulnerabilities'])
        && isset($GLOBALS['mock_options']['wm_cra_vex_statements'], $GLOBALS['mock_options']['wm_cra_vuln_state'], $GLOBALS['mock_options']['wm_cra_settings'], $GLOBALS['mock_options']['wm_cra_api_token_hash'])
        && is_dir($base . '/wm-cra/sbom')
);

// 12b: Opt-in full deletion (wm_cra_beacon_delete_data_on_uninstall = 1) drops all tables, removes every wm_cra_* option, and cleans guard dir.
$GLOBALS['mock_options']['wm_cra_beacon_delete_data_on_uninstall'] = '1';
require $root . '/uninstall.php';
$left = array_values(array_filter(array_keys($GLOBALS['mock_options']), static fn($k) => str_starts_with((string) $k, 'wm_cra_')));
assert_test('opt-in uninstall removes every plugin option, including wm_cra_settings, VEX and audit state', [] === $left, implode(',', $left));
assert_test('opt-in uninstall drops all four tables', [] === array_intersect(['wp_wm_cra_sbom_snapshots', 'wp_wm_cra_advisories', 'wp_wm_cra_vulnerabilities', 'wp_wm_cra_audit_log'], array_keys($db->tables)));
assert_test('opt-in uninstall removes the guard-only uploads/wm-cra directory', !is_dir($base . '/wm-cra'));
@rmdir($base);

// =================================================================================================================
echo "\n[GROUP 13] REST endpoint auth, Bearer token hashing, 1h cache and rate limiting\n";
// =================================================================================================================
good_options();
reset_db();
$GLOBALS['mock_transients']  = [];
$GLOBALS['mock_rest_routes'] = [];
$GLOBALS['mock_hooks']       = [];
$rest = new RestController(new CycloneDxGenerator(), $handler, new CsafPublisher());
$rest->register_routes();
foreach ($GLOBALS['mock_hooks']['rest_api_init'] ?? [] as [$cb, $prio]) {
    $cb();
}
assert_test(
    'all four REST routes use check_read_permission, never __return_true',
    4 === count($GLOBALS['mock_rest_routes'])
        && [] === array_filter($GLOBALS['mock_rest_routes'], static fn(array $r): bool => '__return_true' === $r['permission_callback'])
);

// Anonymous caller denied by default (401).
$GLOBALS['mock_can_manage'] = false;
$anon_perm = $rest->check_read_permission(new WP_REST_Request());
assert_test(
    'anonymous caller is denied with 401 when public endpoints are off (default)',
    $anon_perm instanceof WP_Error && 401 === ($anon_perm->get_error_data()['status'] ?? 0)
);

// Bearer token rotation stores SHA-256 digest only and authorizes read access.
$raw_token   = RestController::rotate_api_token();
$stored_hash = (string) get_option(RestController::OPT_API_TOKEN_HASH, '');
assert_test(
    'rotated Bearer token stores only its 64-hex SHA-256 hash in wp_options, never the cleartext token',
    64 === strlen($raw_token) && $stored_hash === hash('sha256', $raw_token) && $stored_hash !== $raw_token
);
assert_test(
    'valid Bearer token grants access; wrong Bearer token returns 401',
    true === $rest->check_read_permission(new WP_REST_Request(['authorization' => 'Bearer ' . $raw_token]))
        && ($rest->check_read_permission(new WP_REST_Request(['authorization' => 'Bearer wrong-token'])) instanceof WP_Error)
);
RestController::revoke_api_token();
assert_test('revoked Bearer token is no longer accepted', !RestController::has_api_token() && ($rest->check_read_permission(new WP_REST_Request(['authorization' => 'Bearer ' . $raw_token])) instanceof WP_Error));

// Opt-in public access + per-IP rate limiting (60 req/min).
update_option(RestController::OPT_PUBLIC_ENDPOINTS, 1);
$allowed_count = 0;
for ($i = 0; $i < RestController::RATE_LIMIT_MAX; $i++) {
    if (true === $rest->check_read_permission(new WP_REST_Request())) {
        $allowed_count++;
    }
}
$throttled = $rest->check_read_permission(new WP_REST_Request());
assert_test(
    'opt-in public access allows up to 60 requests/min per salted IP hash and throttles the 61st with 429',
    RestController::RATE_LIMIT_MAX === $allowed_count && $throttled instanceof WP_Error && 429 === ($throttled->get_error_data()['status'] ?? 0)
);
update_option(RestController::OPT_PUBLIC_ENDPOINTS, 0);
$GLOBALS['mock_can_manage'] = true;

// 1-hour transient cache + invalidation on flush_caches().
$GLOBALS['mock_transients'] = [];
$resp1 = $rest->get_sbom();
$sbom_cache_keys = array_values(array_filter(array_keys($GLOBALS['mock_transients']), static fn(string $k): bool => str_starts_with($k, 'wm_cra_sbom_')));
assert_test('get_sbom() caches the CycloneDX payload in a transient', 200 === $resp1->get_status() && 1 === count($sbom_cache_keys));
$GLOBALS['mock_transients'][$sbom_cache_keys[0]] = ['bomFormat' => 'CycloneDX', 'cached_marker' => true];
assert_test('subsequent get_sbom() serves from the transient cache', true === ($rest->get_sbom()->get_data()['cached_marker'] ?? false));
RestController::flush_caches();
assert_test('RestController::flush_caches() invalidates the cached SBOM immediately', false === ($rest->get_sbom()->get_data()['cached_marker'] ?? false));

// =================================================================================================================
echo "\n[GROUP 14] Gutenberg block, Block Bindings, GenerateBlocks tag, hooks & register_setting\n";
// =================================================================================================================
good_options();
reset_db();
$GLOBALS['mock_hooks'] = [];
$GLOBALS['mock_registered_settings'] = [];
$GLOBALS['mock_registered_scripts'] = [];
$GLOBALS['mock_script_translations'] = [];
$GLOBALS['mock_registered_blocks'] = [];
$GLOBALS['mock_block_bindings'] = [];
GenerateBlocks_Register_Dynamic_Tag::$registered = [];

// 14a: Gutenberg block metadata + compiled editor script registration.
$block_json_path = $root . '/blocks/cra-psirt/block.json';
$block_meta      = is_file($block_json_path) ? json_decode((string) file_get_contents($block_json_path), true) : null;
assert_test(
    'blocks/cra-psirt/block.json declares wm/cra-psirt with editorScript wm-cra-beacon-blocks-editor and the plugin version',
    is_array($block_meta)
        && 'wm/cra-psirt' === ($block_meta['name'] ?? '')
        && 'wm-cra-beacon-blocks-editor' === ($block_meta['editorScript'] ?? '')
        && WM_CRA_VERSION === ($block_meta['version'] ?? '')
);
$asset_meta = require $root . '/build/index.asset.php';
assert_test(
    'build/index.asset.php declares wp-server-side-render dependency and matches WM_CRA_VERSION',
    is_array($asset_meta)
        && in_array('wp-server-side-render', $asset_meta['dependencies'] ?? [], true)
        && WM_CRA_VERSION === ($asset_meta['version'] ?? '')
);

$portal_ext = new PsirtPortal(new CsafPublisher(), $handler);
$portal_ext->register_block();
$block_dir_key = WM_CRA_PATH . 'blocks/cra-psirt';
assert_test(
    'PsirtPortal::register_block() registers editor script, translations, and block directory with editor_script',
    isset($GLOBALS['mock_registered_scripts']['wm-cra-beacon-blocks-editor'])
        && 'wm-cra-sbom-beacon' === ($GLOBALS['mock_script_translations']['wm-cra-beacon-blocks-editor']['domain'] ?? '')
        && 'wm-cra-beacon-blocks-editor' === ($GLOBALS['mock_registered_blocks'][$block_dir_key]['editor_script'] ?? '')
);
$minimal_html = $portal_ext->render_portal(['showJsonLinks' => false, 'showAdvisories' => false]);
assert_test(
    'PsirtPortal::render_portal() honors showJsonLinks=false and showAdvisories=false block attributes',
    str_contains($minimal_html, 'security@example.test')
        && !str_contains($minimal_html, '/wp-json/wm-cra/v1/sbom')
        && !str_contains($minimal_html, 'Veröffentlichte Sicherheitshinweise')
);

// 14b: WP 6.5+ Block Bindings + GenerateBlocks 2.x Dynamic Tag.
$portal_ext->register_integrations();
assert_test(
    'PsirtPortal::register_integrations() registers wm-cra-beacon/status block binding source',
    isset($GLOBALS['mock_block_bindings']['wm-cra-beacon/status'])
        && is_callable($GLOBALS['mock_block_bindings']['wm-cra-beacon/status']['get_value_callback'] ?? null)
);
assert_test(
    'PsirtPortal::register_integrations() registers GenerateBlocks 2.x dynamic tag wm_cra_beacon_status',
    isset(GenerateBlocks_Register_Dynamic_Tag::$registered['wm_cra_beacon_status'])
        && is_callable(GenerateBlocks_Register_Dynamic_Tag::$registered['wm_cra_beacon_status']['return'] ?? null)
);
assert_test(
    'Block Bindings and GenerateBlocks dynamic tag return computed security.txt state',
    'ok' === $portal_ext->get_block_binding_value(['key' => 'state'])
        && str_starts_with($portal_ext->render_dynamic_tag(), 'Gültig bis ')
        && 'ok' === $portal_ext->filter_generateblocks_dynamic_tag('fallback', ['tag' => 'wm_cra_beacon_status', 'options' => ['key' => 'state']])
        && 'unchanged' === $portal_ext->filter_generateblocks_dynamic_tag('unchanged', ['tag' => 'other_tag'])
        && null === $portal_ext->filter_generateblocks_dynamic_tag(null, ['tag' => 'other_tag'])
);

// 14c: wm_cra_security_txt_output filter & wm_cra_beacon_ready action & register_setting.
$GLOBALS['mock_query_vars'] = ['wm_cra_security_txt' => 1];
add_filter('wm_cra_security_txt_output', static fn(string $content): string => $content . "# Filtered-By-Test: yes\n");
$filtered_txt = render(static fn() => $handler->render_security_txt());
$GLOBALS['mock_query_vars'] = [];
$GLOBALS['mock_hooks']['wm_cra_security_txt_output'] = [];
assert_test(
    'SecurityTxtHandler::render_security_txt() applies wm_cra_security_txt_output filter while preserving RFC 9116 lines',
    str_contains($filtered_txt, 'Contact: mailto:security@example.test') && str_contains($filtered_txt, '# Filtered-By-Test: yes')
);

$ready_fired = null;
add_action('wm_cra_beacon_ready', static function ($instance) use (&$ready_fired): void {
    $ready_fired = $instance;
});
\WMCyber\CRA\Core\Plugin::instance()->boot();
assert_test(
    'Plugin::boot() fires do_action( wm_cra_beacon_ready ) with the Plugin singleton',
    $ready_fired instanceof \WMCyber\CRA\Core\Plugin
);

$dash_settings = new AdminDashboard(new CycloneDxGenerator(), $handler, new CsafPublisher());
$dash_settings->register_settings();
assert_test(
    'AdminDashboard::register_settings() registers wm_cra_beacon_delete_data_on_uninstall via register_setting',
    isset($GLOBALS['mock_registered_settings']['wm_cra_beacon_delete_data_on_uninstall'])
);

// =================================================================================================================
echo "\n[GROUP 15] Multisite wp_initialize_site and non-frontend option autoload = false\n";
// =================================================================================================================
$GLOBALS['mock_hooks'] = [];
$GLOBALS['mock_options'] = [];
$GLOBALS['mock_option_autoloads'] = [];
$GLOBALS['mock_blog_options'] = [];
$GLOBALS['mock_blog_autoloads'] = [];
$GLOBALS['mock_blog_stack'] = [];
$GLOBALS['mock_current_blog_id'] = 1;
$GLOBALS['mock_switch_log'] = [];
$GLOBALS['mock_rules'] = [];
reset_db(false);

require_once $root . '/wm-cra-sbom-beacon.php';
assert_test(
    'main plugin file registers wp_initialize_site hook',
    !empty($GLOBALS['mock_hooks']['wp_initialize_site'])
);

// Non-multisite: wp_initialize_site is a no-op.
$GLOBALS['mock_multisite'] = false;
$GLOBALS['mock_network_active'] = true;
do_action('wp_initialize_site', (object) ['blog_id' => 2]);
assert_test(
    'wp_initialize_site does nothing outside multisite',
    !isset($GLOBALS['wpdb']->tables['wp_2_wm_cra_sbom_snapshots']) && [] === $GLOBALS['mock_switch_log']
);

// Multisite without network activation: wp_initialize_site is a no-op.
$GLOBALS['mock_multisite'] = true;
$GLOBALS['mock_network_active'] = false;
do_action('wp_initialize_site', (object) ['blog_id' => 2]);
assert_test(
    'wp_initialize_site does nothing when plugin is not network-activated',
    !isset($GLOBALS['wpdb']->tables['wp_2_wm_cra_sbom_snapshots']) && [] === $GLOBALS['mock_switch_log']
);

// Multisite + network-activated: provisions new subsite tables, defaults with autoload=false, and restores blog.
$GLOBALS['mock_multisite'] = true;
$GLOBALS['mock_network_active'] = true;
do_action('wp_initialize_site', (object) ['blog_id' => 2]);
assert_test(
    'wp_initialize_site creates all 3 tables on the new subsite without touching main site tables',
    isset(
        $GLOBALS['wpdb']->tables['wp_2_wm_cra_sbom_snapshots'],
        $GLOBALS['wpdb']->tables['wp_2_wm_cra_vulnerabilities'],
        $GLOBALS['wpdb']->tables['wp_2_wm_cra_advisories']
    ) && !isset($GLOBALS['wpdb']->tables['wp_wm_cra_sbom_snapshots'])
);
assert_test(
    'wp_initialize_site writes subsite default contact without polluting main site options',
    'mailto:security@site2.example.test' === ($GLOBALS['mock_blog_options'][2][SecurityTxtHandler::OPT_CONTACT] ?? '')
        && !isset($GLOBALS['mock_options'][SecurityTxtHandler::OPT_CONTACT])
);
assert_test(
    'wp_initialize_site restores original blog context and table prefix',
    1 === $GLOBALS['mock_current_blog_id']
        && 'wp_' === $GLOBALS['wpdb']->prefix
        && ['switch:2', 'restore:1'] === $GLOBALS['mock_switch_log']
);
assert_test(
    'Schema::activate_site() writes OPT_CONTACT with autoload = false',
    false === ($GLOBALS['mock_blog_autoloads'][2][SecurityTxtHandler::OPT_CONTACT] ?? null)
);
assert_test(
    'Schema::activate_site() writes OPT_EXPIRES with autoload = false',
    false === ($GLOBALS['mock_blog_autoloads'][2][SecurityTxtHandler::OPT_EXPIRES] ?? null)
);
assert_test(
    'Schema::activate_site() writes OPT_LANGUAGES with autoload = false',
    false === ($GLOBALS['mock_blog_autoloads'][2][SecurityTxtHandler::OPT_LANGUAGES] ?? null)
);

// Exception safety: restore_current_blog() still runs inside try/finally if activation fails.
reset_db(false);
$GLOBALS['mock_switch_log'] = [];
$GLOBALS['mock_dbdelta_throw_on_prefix'] = 'wp_3_';
$init_error = '';
try {
    do_action('wp_initialize_site', (object) ['blog_id' => 3]);
} catch (RuntimeException $e) {
    $init_error = $e->getMessage();
}
$GLOBALS['mock_dbdelta_throw_on_prefix'] = '';
assert_test(
    'wp_initialize_site restores blog context in finally even when activation throws',
    'simulated dbDelta failure' === $init_error
        && 1 === $GLOBALS['mock_current_blog_id']
        && 'wp_' === $GLOBALS['wpdb']->prefix
        && ['switch:3', 'restore:1'] === $GLOBALS['mock_switch_log']
);

// Network-wide Schema::activate(true) across multiple sites.
reset_db(false);
$GLOBALS['mock_options'] = [];
$GLOBALS['mock_option_autoloads'] = [];
$GLOBALS['mock_blog_options'] = [];
$GLOBALS['mock_blog_autoloads'] = [];
$GLOBALS['mock_switch_log'] = [];
$GLOBALS['mock_sites'] = [1, 2];
Schema::activate(true);
assert_test(
    'Schema::activate(true) creates tables for every site in multisite and restores current blog',
    isset($GLOBALS['wpdb']->tables['wp_wm_cra_sbom_snapshots'], $GLOBALS['wpdb']->tables['wp_2_wm_cra_sbom_snapshots'])
        && 1 === $GLOBALS['mock_current_blog_id']
        && 'wp_' === $GLOBALS['wpdb']->prefix
);
$GLOBALS['mock_multisite'] = false;
$GLOBALS['mock_network_active'] = false;
$GLOBALS['mock_sites'] = [1];

// AdminDashboard non-frontend update_option() calls pass explicit $autoload = false.
good_options();
reset_db();
$GLOBALS['mock_option_autoloads'] = [];
$GLOBALS['mock_cron'] = [];
$dash_auto = new AdminDashboard(new CycloneDxGenerator(), $handler, new CsafPublisher());

try {
    $_POST = ['wm_cra_action' => 'save_vuln_options', 'vuln_enabled' => '1', 'nvd_api_key' => ''];
    $dash_auto->handle_form_actions();
} catch (RuntimeException $e) {
    // redirect
}
assert_test(
    'AdminDashboard save_vuln_options writes OPT_ENABLED with autoload = false',
    false === ($GLOBALS['mock_option_autoloads'][VulnerabilityAudit::OPT_ENABLED] ?? null)
);

try {
    $_POST = ['wm_cra_action' => 'save_sbom_options', 'include_crypto' => '1', 'public_endpoints' => '1'];
    $dash_auto->handle_form_actions();
} catch (RuntimeException $e) {
    // redirect
}
assert_test(
    'AdminDashboard save_sbom_options writes CryptoInventory::OPT_INCLUDE with autoload = false',
    false === ($GLOBALS['mock_option_autoloads'][\WMCyber\CRA\SBOM\CryptoInventory::OPT_INCLUDE] ?? null)
);
assert_test(
    'AdminDashboard save_sbom_options writes RestController::OPT_PUBLIC_ENDPOINTS with autoload = false',
    false === ($GLOBALS['mock_option_autoloads'][RestController::OPT_PUBLIC_ENDPOINTS] ?? null)
);

try {
    $_POST = ['wm_cra_action' => 'save_uninstall_options', 'delete_data_on_uninstall' => '1'];
    $dash_auto->handle_form_actions();
} catch (RuntimeException $e) {
    // redirect
}
$_POST = [];
assert_test(
    'AdminDashboard save_uninstall_options writes wm_cra_beacon_delete_data_on_uninstall with autoload = false',
    false === ($GLOBALS['mock_option_autoloads']['wm_cra_beacon_delete_data_on_uninstall'] ?? null)
);

$dash_auto->save_settings([
    'contact'    => 'psirt@example.test',
    'expires'    => gmdate('Y-m-d', time() + 100 * DAY_IN_SECONDS),
    'languages'  => 'en',
    'policy'     => '',
    'encryption' => '',
]);
assert_test(
    'AdminDashboard save_settings writes SecurityTxtHandler::OPT_CONFIRMED with autoload = false',
    false === ($GLOBALS['mock_option_autoloads'][SecurityTxtHandler::OPT_CONFIRMED] ?? null)
);

// Schema::maybe_upgrade() during plugins_loaded when $wp_rewrite is still null.
reset_db(false);
$GLOBALS['mock_options']          = ['permalink_structure' => '/%postname%/', 'rewrite_rules' => ['^other$' => 'index.php']];
$GLOBALS['mock_option_autoloads'] = [];
$GLOBALS['mock_hooks']            = [];
$GLOBALS['mock_rules']            = [];
$GLOBALS['mock_flushes']          = 0;
$GLOBALS['mock_in_plugins_loaded'] = true;
$boot_upgrade_err = '';
try {
    \WMCyber\CRA\Core\Plugin::instance()->boot();
} catch (Throwable $e) {
    $boot_upgrade_err = $e->getMessage();
} finally {
    $GLOBALS['mock_in_plugins_loaded'] = false;
}
assert_test(
    'Plugin::boot() upgrades schema on plugins_loaded without calling add_rewrite_rule before $wp_rewrite exists',
    '' === $boot_upgrade_err
        && isset($GLOBALS['wpdb']->tables['wp_wm_cra_sbom_snapshots'], $GLOBALS['wpdb']->tables['wp_wm_cra_vulnerabilities'], $GLOBALS['wpdb']->tables['wp_wm_cra_advisories'])
        && 2 === (int) get_option('wm_cra_db_version', 0)
        && false === ($GLOBALS['mock_option_autoloads']['wm_cra_db_version'] ?? null)
        && 0 === $GLOBALS['mock_flushes'],
    'err=' . $boot_upgrade_err . ' flushes=' . $GLOBALS['mock_flushes']
);
do_action('init');
do_action('wp_loaded');
assert_test(
    'after plugins_loaded upgrade, init + wp_loaded register and store the security.txt route once',
    1 === $GLOBALS['mock_flushes'] && isset($GLOBALS['mock_options']['rewrite_rules'][RULE])
);

// -----------------------------------------------------------------------------------------------------------------
echo "\n==============================================================================\n";
echo "  TEST SUITE RESULTS: {$GLOBALS['passed_count']} PASSED | {$GLOBALS['failed_count']} FAILED\n";
echo "==============================================================================\n\n";

exit(0 === $GLOBALS['failed_count'] ? 0 : 1);
