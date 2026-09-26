<?php
/******************************************************************************
 * dns1 - shared helpers
 *
 * Auth model mirrors /bones/docker/gandolf/www/html/lifevue.
 * Domain matching mirrors org.dns1.Main so the web UI and the DNS daemon
 * always agree on what "whitelisted" means.
 ******************************************************************************/

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'use_strict_mode'  => true,
    'cookie_lifetime'  => 2592000,
    'gc_maxlifetime'   => 2592000
]);

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-cache, must-revalidate');
header('Pragma: no-cache');

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrfToken = $_SESSION['csrf_token'];

// Kept outside DocumentRoot so the database can never be downloaded over HTTP.
// Shares /var/www/dbs with the other applications' databases; must match
// DNS1_DB in the container's entrypoint.sh, which is what the daemon opens.
$dbPath = dirname(__DIR__, 2) . '/dbs/dns1.db';

function getDb() {
    global $dbPath;
    $db = new PDO('sqlite:' . $dbPath);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA busy_timeout=5000');
    ensureDns1Schema($db);
    return $db;
}

/* The games list matches the whitelist's shape and starts empty. "filtered"
 * was whitelist-only; that behaviour is now the whitelist policy, so rewrite
 * any stored value before the control page draws it. Both statements are
 * idempotent. The daemon performs the same migration at startup. */
function ensureDns1Schema($db) {
    $db->exec("CREATE TABLE IF NOT EXISTS games (
        name TEXT PRIMARY KEY,
        date_approved DATETIME
    )");
    $db->exec("UPDATE settings SET value = 'whitelist'
               WHERE key = 'default_mode' AND value = 'filtered'");
    $db->exec("UPDATE clients SET mode = 'whitelist' WHERE mode = 'filtered'");
}

/* True after the daemon has rebuilt history with a client address. The web UI
 * does not rebuild that table itself. */
function historyHasClientIp($db) {
    foreach ($db->query('PRAGMA table_info(history)') as $row) {
        if (strcasecmp($row['name'], 'client_ip') === 0) return true;
    }
    return false;
}

function domainList($name) {
    if ($name !== 'whitelist' && $name !== 'games') {
        return null;
    }
    return $name;
}

function jsonOut($payload) {
    header('Content-Type: application/json');
    echo json_encode($payload);
    exit;
}

function verifyCsrf() {
    $token = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        http_response_code(403);
        jsonOut(['success' => false, 'error' => 'Invalid CSRF token']);
    }
}

function requireLogin() {
    if (empty($_SESSION['logged_in'])) {
        header('Location: index.php?action=login');
        exit;
    }
}

function isAdmin() {
    return ($_SESSION['level'] ?? 'user') === 'admin';
}

/* Mutations are admin-only; everyone approved may look. */
function requireAdminApi() {
    if (empty($_SESSION['logged_in'])) {
        http_response_code(401);
        jsonOut(['success' => false, 'error' => 'Not authenticated']);
    }
    if (!isAdmin()) {
        http_response_code(403);
        jsonOut(['success' => false, 'error' => 'Administrator access required']);
    }
}

function getVanityDomain() {
    try {
        $db = getDb();
        $stmt = $db->query("SELECT property_value FROM config WHERE request_type='global' AND property_name='vanity_domain'");
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ? $row['property_value'] : ($_SERVER['HTTP_HOST'] ?? 'localhost');
    } catch (Exception $e) {
        return $_SERVER['HTTP_HOST'] ?? 'localhost';
    }
}

function sendEmail($to, $subject, $bodyHtml) {
    if (!filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    $domain  = getVanityDomain();
    $from    = "noreply@{$domain}";
    $subject = str_replace(["\r", "\n"], '', $subject);
    $from    = str_replace(["\r", "\n"], '', $from);
    $to      = str_replace(["\r", "\n"], '', $to);

    $db = getDb();
    $stmt = $db->query("SELECT property_value FROM config WHERE request_type='global' AND property_name='smtp_relay'");
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    $relay = $row ? $row['property_value'] : '172.17.0.1';

    $sock = @fsockopen($relay, 25, $errno, $errstr, 10);
    if (!$sock) return false;
    $read = function() use ($sock) { $r=''; while($l=fgets($sock,512)){$r.=$l; if(isset($l[3])&&$l[3]===' ')break;} return $r; };
    $send = function($cmd) use ($sock,$read) { fwrite($sock,$cmd."\r\n"); return $read(); };
    $read();
    $send("EHLO {$domain}");
    $send("MAIL FROM:<{$from}>");
    $send("RCPT TO:<{$to}>");
    $resp = $send("DATA");
    if (substr($resp,0,3) !== '354') { fclose($sock); return false; }
    $headers = "From: DNS1 <{$from}>\r\nTo: {$to}\r\nSubject: {$subject}\r\n"
             . "MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n"
             . "Date: ".date('r')."\r\nMessage-ID: <".bin2hex(random_bytes(12))."@{$domain}>\r\n";
    $safeBody = preg_replace('/^\./m', '..', $bodyHtml);
    fwrite($sock, $headers."\r\n".$safeBody."\r\n.\r\n");
    $resp = $read();
    $send("QUIT");
    fclose($sock);
    return substr($resp,0,3)==='250';
}

/******************************************************************************
 * Domain helpers - keep in step with org.dns1.Main
 ******************************************************************************/

function normalizeDomain($raw) {
    if ($raw === null) return '';
    $t = strtolower(trim($raw));
    $t = rtrim($t, '.');
    $t = ltrim($t, '.');
    return $t;
}

/* A whitelist entry needs at least two labels; a bare TLD such as "com" would
 * otherwise allow every domain beneath it. */
/******************************************************************************
 * isValidWhitelistEntry
 *
 * Mirrors isValidWhitelistEntry() in the daemon's Main.java. The two must agree:
 * a name accepted here but rejected there is written to the table and then
 * silently ignored by the resolver, which looks like the whitelist not working.
 ******************************************************************************/
function isValidWhitelistEntry($domain) {
    if ($domain === null || $domain === '' || strlen($domain) > 253) return false;
    /* A leading or trailing dot would produce an empty label, and requiring an
       interior dot is what keeps single-label names out: those are handled as
       local names, which are a separate class. */
    if ($domain[0] === '.' || substr($domain, -1) === '.') return false;
    $pos = strpos($domain, '.');
    if ($pos === false || $pos === 0) return false;

    foreach (explode('.', $domain) as $label) {
        if ($label === '' || strlen($label) > 63) return false;
        if ($label[0] === '-' || substr($label, -1) === '-') return false;
        /* Underscore is not in RFC 1035 but is what service names such as
           _dmarc use in practice. Input is already lower-cased by
           normalizeDomain, so upper case here means it was not normalized. */
        if (!preg_match('/\A[a-z0-9_-]+\z/', $label)) return false;
    }
    return true;
}

/* Single-label names such as "elrond" cannot resolve on the public internet,
 * because ICANN prohibits dotless domains, so they are necessarily names of the
 * local network and the daemon allows them as a class.
 *
 * This must stay in step with the daemon's --allow-local flag, which
 * entrypoint.sh derives from DNS1_ALLOW_LOCAL. If the two disagree the resolver
 * still decides what is answered; only the status shown here would be wrong. */
defined('ALLOW_LOCAL_NAMES') || define('ALLOW_LOCAL_NAMES', true);

function isLocalName($domain) {
    return $domain !== null && $domain !== '' && strpos($domain, '.') === false;
}

function isAutoAllowed($domain) {
    return ALLOW_LOCAL_NAMES && isLocalName($domain);
}

/* The name itself plus each parent domain, cut only at label boundaries, so
 * "notmicrosoft.com" can never match an entry for "microsoft.com". The bare
 * TLD is deliberately never produced. */
function candidateSuffixes($domain) {
    $out = [];
    if ($domain === null || $domain === '') return $out;
    $candidate = $domain;
    while (strpos($candidate, '.') !== false) {
        $out[] = $candidate;
        $pos = strpos($candidate, '.');
        if ($pos + 1 >= strlen($candidate)) break;
        $candidate = substr($candidate, $pos + 1);
    }
    return $out;
}

function loadDomainSet($db, $list) {
    $list = domainList($list);
    if ($list === null) return [];
    $set = [];
    foreach ($db->query('SELECT name FROM ' . $list) as $row) {
        $n = normalizeDomain($row['name']);
        if ($n !== '') $set[$n] = true;
    }
    return $set;
}

function loadWhitelistSet($db) {
    return loadDomainSet($db, 'whitelist');
}

function isWhitelisted($domain, $whitelistSet) {
    foreach (candidateSuffixes($domain) as $candidate) {
        if (isset($whitelistSet[$candidate])) return $candidate;
    }
    return null;
}

/* The inverse of isWhitelisted: existing entries that $name would now cover,
 * because $name is one of their parent suffixes. Adding "google.com" makes an
 * existing "www.google.com" redundant, since the daemon matches it either way. */
function redundantChildren($db, $name, $list = 'whitelist') {
    $name = normalizeDomain($name);
    $list = domainList($list);
    $out  = [];
    if ($name === '' || $list === null) return $out;
    foreach ($db->query('SELECT name FROM ' . $list) as $row) {
        $existing = normalizeDomain($row['name']);
        if ($existing === '' || $existing === $name) continue;
        foreach (candidateSuffixes($existing) as $suffix) {
            if ($suffix === $name) { $out[] = $existing; break; }
        }
    }
    return $out;
}

/******************************************************************************
 * DAEMON CONTROL SOCKET
 *
 * The daemon listens for plain-text commands on loopback. Fields are separated
 * by a lower-case thorn, field 1 is the command and the rest are its arguments.
 *
 * This replaced the whitelist_actions queue table: the daemon applies the
 * change to its in-memory cache during this request instead of discovering it
 * on a later poll, so a whitelist edit takes effect immediately.
 ******************************************************************************/
const DAEMON_HOST = '127.0.0.1';
const DAEMON_PORT = 22700;
const DAEMON_TIMEOUT = 2;
const DAEMON_SEP = "\u{00FE}";

/******************************************************************************
 * daemonCommand
 *
 * Sends one command and returns [ok, detail]. The timeout is deliberately
 * short: this runs inside an admin page request, and a wedged daemon must not
 * hold the request open.
 ******************************************************************************/
function daemonCommand(array $fields) {
    $sock = @fsockopen(DAEMON_HOST, DAEMON_PORT, $errno, $errstr, DAEMON_TIMEOUT);
    if (!$sock) {
        return [false, "daemon not reachable on " . DAEMON_HOST . ":" . DAEMON_PORT
                       . ($errstr !== '' ? " ($errstr)" : '')];
    }
    stream_set_timeout($sock, DAEMON_TIMEOUT);

    fwrite($sock, implode(DAEMON_SEP, $fields) . "\n");
    $line = fgets($sock, 4096);
    $meta = stream_get_meta_data($sock);
    fclose($sock);

    if ($meta['timed_out']) {
        return [false, 'daemon did not respond within ' . DAEMON_TIMEOUT . 's'];
    }
    if ($line === false) {
        return [false, 'daemon closed the connection without replying'];
    }

    $parts  = explode(DAEMON_SEP, trim($line));
    $status = array_shift($parts);
    return [$status === 'ok', implode(' ', $parts)];
}

/******************************************************************************
 * daemonIsRunning
 ******************************************************************************/
function daemonIsRunning() {
    [$ok] = daemonCommand(['ping']);
    return $ok;
}

/******************************************************************************
 * joinNotes
 *
 * Combines optional advisory strings into one, dropping the empty ones, so a
 * caller can pass several without testing each.
 ******************************************************************************/
function joinNotes(...$notes) {
    $kept = array_filter($notes, function ($n) { return $n !== null && $n !== ''; });
    return empty($kept) ? null : implode(' ', $kept);
}

/******************************************************************************
 * applyWhitelistChange
 *
 * Writes the whitelist table, which is the record of truth, then tells the
 * daemon to mirror the change in its cache.
 *
 * $approvedAt overrides the recorded approval date, which a rename uses to
 * carry the original entry's date across the delete/insert pair. The default
 * of false means "stamp it now"; an explicit null carries a missing date
 * forward, so renaming an entry from before this column existed does not
 * invent an approval date it never had.
 *
 * The table write is what matters for correctness: the daemon reloads the whole
 * table at startup, so a change made while it is down is picked up anyway. A
 * failed notification therefore leaves the change saved but not yet in effect,
 * which is returned as a warning rather than an error so the caller can say so
 * instead of reporting a success that has not reached the resolver.
 ******************************************************************************/
function listLabel($list) {
    return $list === 'games' ? 'games list' : 'whitelist';
}

function applyListChange($db, $list, $action, $name, $approvedAt = false) {
    $list = domainList($list);
    $name = normalizeDomain($name);
    if ($list === null) {
        return [false, 'Unknown list.'];
    }
    if (!isValidWhitelistEntry($name)) {
        return [false, 'Name must be a dotted domain of letters, digits, hyphen or underscore (e.g. example.com).'];
    }
    if ($action !== 'insert' && $action !== 'delete') {
        return [false, 'Unknown action.'];
    }
    $db->beginTransaction();
    try {
        if ($action === 'insert') {
            /* Stored as UTC to match the timestamps the daemon writes, so the
               one formatter in the UI can render every column the same way.
               OR IGNORE means re-adding an existing name keeps its original
               approval date rather than moving it to now. */
            $stamp = $approvedAt === false ? gmdate('Y-m-d\TH:i:s\Z') : $approvedAt;
            $db->prepare('INSERT OR IGNORE INTO ' . $list . ' (name, date_approved) VALUES (?, ?)')
               ->execute([$name, $stamp]);
        } else {
            $db->prepare('DELETE FROM ' . $list . ' WHERE name = ? COLLATE NOCASE')->execute([$name]);
        }
        $db->commit();
    } catch (Exception $e) {
        $db->rollBack();
        return [false, 'Database error: ' . $e->getMessage()];
    }

    /* Notified only after the commit, so the cache is never told about a change
     * that the transaction then rolled back. */
    [$ok, $detail] = daemonCommand([$list, $action === 'insert' ? 'add' : 'remove', $name]);
    $warning = $ok ? null
        : 'Saved, but the DNS daemon did not confirm (' . $detail . '). '
          . 'The change takes effect when it reloads or restarts.';

    return [true, $name, $warning];
}

function applyWhitelistChange($db, $action, $name, $approvedAt = false) {
    return applyListChange($db, 'whitelist', $action, $name, $approvedAt);
}

/******************************************************************************
 * moveBetweenLists
 *
 * Removes $name from one list and places it on the other, keeping the
 * approval date. When the destination already covers the name, the destination
 * is left as it is and the source row is still removed.
 *
 * The destination add is sent before the source remove, so a name that is
 * moving is never absent from both caches.
 ******************************************************************************/
function moveBetweenLists($db, $from, $to, $name) {
    $from = domainList($from);
    $to   = domainList($to);
    $name = normalizeDomain($name);
    if ($from === null || $to === null || $from === $to) {
        return [false, 'Unknown list.'];
    }
    if (!isValidWhitelistEntry($name)) {
        return [false, 'Name must be a dotted domain of letters, digits, hyphen or underscore (e.g. example.com).'];
    }

    $db->beginTransaction();
    try {
        $prev = $db->prepare('SELECT date_approved FROM ' . $from . ' WHERE name = ? COLLATE NOCASE');
        $prev->execute([$name]);
        $row = $prev->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            $db->rollBack();
            return [false, $name . ' is not on the ' . listLabel($from) . '.'];
        }

        $covering = isWhitelisted($name, loadDomainSet($db, $to));
        if ($covering === null) {
            $db->prepare('INSERT OR IGNORE INTO ' . $to . ' (name, date_approved) VALUES (?, ?)')
               ->execute([$name, $row['date_approved']]);
        }
        $db->prepare('DELETE FROM ' . $from . ' WHERE name = ? COLLATE NOCASE')->execute([$name]);
        $db->commit();
    } catch (Exception $e) {
        if ($db->inTransaction()) $db->rollBack();
        return [false, 'Database error: ' . $e->getMessage()];
    }

    $warnings = [];
    if ($covering === null) {
        [$ok, $detail] = daemonCommand([$to, 'add', $name]);
        if (!$ok) {
            $warnings[] = 'Saved, but the DNS daemon did not confirm the add (' . $detail . ').';
        }
    }
    [$ok, $detail] = daemonCommand([$from, 'remove', $name]);
    if (!$ok) {
        $warnings[] = 'Saved, but the DNS daemon did not confirm the remove (' . $detail . ').';
    }
    if ($warnings) {
        $warnings[] = 'The change takes effect when it reloads or restarts.';
    }

    $note = null;
    if ($covering !== null) {
        $note = $covering === $name
            ? $name . ' was already on the ' . listLabel($to) . '.'
            : $name . ' is already covered by ' . $covering . ' on the ' . listLabel($to) . '.';
    } else {
        $absorbed = redundantChildren($db, $name, $to);
        if (count($absorbed) === 1) {
            $note = $absorbed[0] . ' is now redundant.';
        } elseif (count($absorbed) > 1) {
            $note = count($absorbed) . ' existing entries are now redundant.';
        }
    }

    return [true, $name, joinNotes($note, $warnings ? implode(' ', $warnings) : null)];
}

/******************************************************************************
 * bootgridQuery
 *
 * Shared paging/sorting/search handling for jQuery Bootgrid, which POSTs
 * current / rowCount / searchPhrase / sort[field].
 *
 * $searchable and $sortable are whitelists of column names, so a crafted
 * request cannot reach an arbitrary identifier.
 ******************************************************************************/
function bootgridParams($searchable, $sortable, $defaultSort) {
    $current  = max(1, (int)($_POST['current'] ?? 1));
    $rowCount = (int)($_POST['rowCount'] ?? 10);
    if (!in_array($rowCount, [10, 25, 50, -1], true)) $rowCount = 10;
    $search   = trim((string)($_POST['searchPhrase'] ?? ''));

    $orderBy = $defaultSort;
    $sort = $_POST['sort'] ?? null;
    if (is_array($sort)) {
        foreach ($sort as $field => $dir) {
            if (in_array($field, $sortable, true)) {
                $dir = (strtolower($dir) === 'desc') ? 'DESC' : 'ASC';
                $orderBy = "\"{$field}\" {$dir}";
                break;
            }
        }
    }

    $where = '';
    $params = [];
    if ($search !== '' && $searchable) {
        $clauses = [];
        foreach ($searchable as $col) {
            $clauses[] = "\"{$col}\" LIKE ? ESCAPE '\\'";
            $params[] = '%' . addcslashes($search, '%_\\') . '%';
        }
        $where = 'WHERE ' . implode(' OR ', $clauses);
    }

    return [$current, $rowCount, $where, $params, $orderBy];
}
