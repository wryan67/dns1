<?php
/******************************************************************************
 * dns1 - JSON API
 *
 * Included by index.php. Serves jQuery Bootgrid data requests and the
 * whitelist mutations driven by the grid command buttons.
 ******************************************************************************/

if (!isset($_GET['api'])) return;

$api = $_GET['api'];

/* Reads require a session; writes additionally require admin. */
if (empty($_SESSION['logged_in'])) {
    http_response_code(401);
    jsonOut(['success' => false, 'error' => 'Not authenticated']);
}

$db = getDb();

/* ---- Bootgrid: whitelist ---- */
if ($api === 'whitelist_data') {
    [$current, $rowCount, $where, $params, $orderBy] =
        bootgridParams(['name'], ['name', 'date_approved'], '"name" ASC');

    $countStmt = $db->prepare("SELECT COUNT(*) AS c FROM whitelist {$where}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['c'];

    $sql = "SELECT name, date_approved FROM whitelist {$where} ORDER BY {$orderBy}";
    if ($rowCount > 0) {
        $sql .= ' LIMIT ' . (int)$rowCount . ' OFFSET ' . (int)(($current - 1) * $rowCount);
    }
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    jsonOut([
        'current'  => $current,
        'rowCount' => $rowCount,
        'total'    => $total,
        'rows'     => $rows
    ]);
}

/* ---- Bootgrid: history ---- */
if ($api === 'history_data') {
    [$current, $rowCount, $where, $params, $orderBy] =
        bootgridParams(['name'],
                       ['name', 'count', 'last_seen', 'allowed_count', 'allowed_last_seen',
                        'total_count', 'last_any'],
                       '"last_any" DESC');

    /* Mirrors isWhitelisted(): a row is allowed when the whitelist holds the name
     * itself or any of its parent domains. The suffix test compares the trailing
     * ".<entry>" via substr rather than LIKE, so an underscore or percent in an
     * entry cannot act as a wildcard. */
    $approvedExpr = "(EXISTS (SELECT 1 FROM whitelist w WHERE lower(history.name) = lower(w.name) "
                  . "OR substr(lower(history.name), -(length(w.name) + 1)) = '.' || lower(w.name))";
    if (ALLOW_LOCAL_NAMES) {
        /* Single-label names are allowed as a class by the daemon, so the
         * Blocked and Allowed views have to classify them the way the resolver
         * does. instr() rather than LIKE, so no wildcard interpretation. */
        $approvedExpr .= " OR instr(history.name, '.') = 0";
    }
    /* Parenthesised as a whole because it is also used as NOT (...); without the
     * outer parens the trailing OR would escape the negation. */
    $approvedExpr .= ")";

    $statusFilter = $_POST['status'] ?? 'all';
    $filterExpr   = '';
    if ($statusFilter === 'allowed') {
        $filterExpr = $approvedExpr;
    } elseif ($statusFilter === 'blocked') {
        $filterExpr = 'NOT ' . $approvedExpr;
    }

    /* The summary columns follow the active filter: a Blocked view reports only
     * denials, an Allowed view only successful lookups, and All rolls both up.
     * Reporting the combined total under a "Last Blocked" heading would count
     * hits the filter is excluding. */
    if ($statusFilter === 'allowed') {
        $totalExpr = 'COALESCE(allowed_count, 0)';
        $lastExpr  = 'allowed_last_seen';
    } elseif ($statusFilter === 'blocked') {
        $totalExpr = 'COALESCE(count, 0)';
        $lastExpr  = 'last_seen';
    } else {
        $totalExpr = '(COALESCE(count, 0) + COALESCE(allowed_count, 0))';
        $lastExpr  = 'COALESCE(MAX(last_seen, allowed_last_seen), last_seen, allowed_last_seen)';
    }
    if ($filterExpr !== '') {
        /* The search clause is parenthesised because bootgridParams ORs its
         * searchable columns together, and OR binds looser than AND. */
        $where = ($where === '')
            ? "WHERE {$filterExpr}"
            : 'WHERE (' . substr($where, 6) . ") AND ({$filterExpr})";
    }

    $countStmt = $db->prepare("SELECT COUNT(*) AS c FROM history {$where}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['c'];

    /* The summary aliases keep their names across all three views so the grid's
     * sort keys stay valid; only the backing expression changes. MAX() with two
     * arguments is the scalar form and yields NULL if either side is NULL, so
     * COALESCE supplies the other one. Timestamps are ISO 8601, which compares
     * correctly as text. */
    $sql = "SELECT name, count, last_seen, allowed_count, allowed_last_seen, "
         . "{$totalExpr} AS total_count, "
         . "{$lastExpr} AS last_any "
         . "FROM history {$where} ORDER BY {$orderBy}";
    if ($rowCount > 0) {
        $sql .= ' LIMIT ' . (int)$rowCount . ' OFFSET ' . (int)(($current - 1) * $rowCount);
    }
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    /* Approved means the name would now resolve, which covers three cases: listed
     * outright, covered by a whitelisted parent domain, or allowed as a local
     * single-label name. */
    $whitelist = loadWhitelistSet($db);
    foreach ($rows as &$r) {
        $name  = normalizeDomain($r['name']);
        $match = isWhitelisted($name, $whitelist);
        $local = $match === null && isAutoAllowed($name);
        $r['approved']   = ($match !== null || $local) ? 1 : 0;
        $r['covered_by'] = $match;
        $r['local']      = $local ? 1 : 0;
    }
    unset($r);

    jsonOut([
        'current'  => $current,
        'rowCount' => $rowCount,
        'total'    => $total,
        'rows'     => $rows
    ]);
}

/* ---- Bootgrid: clients (Control page) ---- */
if ($api === 'client_data') {
    [$current, $rowCount, $where, $params, $orderBy] =
        bootgridParams(['ip', 'hostname'],
                       ['ip', 'hostname', 'mode', 'query_count', 'last_seen'],
                       '"last_seen" DESC');

    $countStmt = $db->prepare("SELECT COUNT(*) AS c FROM clients {$where}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['c'];

    $sql = "SELECT ip, hostname, mode, query_count, last_seen, first_seen FROM clients {$where} ORDER BY {$orderBy}";
    if ($rowCount > 0) {
        $sql .= ' LIMIT ' . (int)$rowCount . ' OFFSET ' . (int)(($current - 1) * $rowCount);
    }
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    jsonOut([
        'current'  => $current,
        'rowCount' => $rowCount,
        'total'    => $total,
        'rows'     => $stmt->fetchAll(PDO::FETCH_ASSOC)
    ]);
}

/* ---- Control: default policy ----
   Read from the daemon rather than the settings table, so the page reports
   what is actually in force instead of what was last requested. */
if ($api === 'control_status') {
    verifyCsrf();
    [$ok, $detail] = daemonCommand(['status']);
    if (!$ok) {
        jsonOut(['success' => false, 'error' => 'Daemon unreachable: ' . $detail]);
    }
    jsonOut(['success' => true, 'mode' => $detail]);
}

/* ---- Control mutations ----
   These carry no database write of their own: the daemon owns its runtime
   state and persists it, so a success here means the resolver has already
   applied the change rather than that a row was queued for it. */
if ($api === 'control_default' || $api === 'control_client') {
    requireAdminApi();
    verifyCsrf();

    /* Checked here as well as in the daemon so a typo is reported as a bad
       request rather than as the resolver refusing the command. */
    $mode = strtolower(trim($_POST['mode'] ?? ''));

    if ($api === 'control_default') {
        if (!in_array($mode, ['allowall', 'filtered', 'blocked'], true)) {
            jsonOut(['success' => false, 'error' => 'Unknown default policy.']);
        }
        [$ok, $detail] = daemonCommand(['default', 'set', $mode]);
        if (!$ok) {
            jsonOut(['success' => false,
                     'error'   => 'The daemon did not apply the change: ' . $detail]);
        }
        jsonOut(['success' => true, 'mode' => $mode]);
    }

    $ip = trim($_POST['ip'] ?? '');
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        jsonOut(['success' => false, 'error' => 'Not a valid IP address.']);
    }

    /* "default" is not a policy but a request to clear this client's own. */
    if (!in_array($mode, ['allowall', 'filtered', 'blocked', 'default'], true)) {
        jsonOut(['success' => false, 'error' => 'Unknown client policy.']);
    }

    [$ok, $detail] = daemonCommand(['client', 'set', $ip, $mode]);
    if (!$ok) {
        jsonOut(['success' => false,
                 'error'   => 'The daemon did not apply the change: ' . $detail]);
    }
    jsonOut(['success' => true, 'ip' => $ip, 'mode' => $mode]);
}

/* ---- Mutations ---- */
if ($api === 'whitelist_save' || $api === 'whitelist_delete' || $api === 'history_approve') {
    requireAdminApi();
    verifyCsrf();

    if ($api === 'whitelist_save') {
        $original = normalizeDomain($_POST['original'] ?? '');
        $name     = normalizeDomain($_POST['name'] ?? '');

        if (!isValidWhitelistEntry($name)) {
            jsonOut(['success' => false, 'error' => 'Name must be a dotted domain of letters, digits, hyphen or underscore (e.g. example.com).']);
        }

        /* Re-saving an entry unchanged is a no-op. Skipped before the checks
           below so an entry never reports itself as a duplicate of itself. */
        if ($original !== '' && $original === $name) {
            jsonOut(['success' => true, 'name' => $name]);
        }

        /* The daemon matches a name through any of its parent suffixes, so an
           entry that some existing entry already covers would never be
           consulted. Checked before the rename delete below, so that a rejected
           save leaves the table untouched. */
        $existingSet = loadWhitelistSet($db);
        if ($original !== '') unset($existingSet[$original]);
        $covering = isWhitelisted($name, $existingSet);
        if ($covering !== null) {
            jsonOut(['success' => false, 'error' => $covering === $name
                ? $name . ' is already in the whitelist.'
                : $name . ' is already covered by ' . $covering
                    . ', which also matches every subdomain of it.']);
        }

        /* A rename is a delete plus an insert, so the daemon sees both halves.
           The original's approval date rides along, so correcting a typo does
           not restamp the entry as if it were approved just now. */
        $carried = false;
        if ($original !== '' && $original !== $name) {
            $prevStmt = $db->prepare(
                'SELECT date_approved FROM whitelist WHERE name = ? COLLATE NOCASE');
            $prevStmt->execute([$original]);
            $prevRow = $prevStmt->fetch(PDO::FETCH_ASSOC);
            $carried = $prevRow ? $prevRow['date_approved'] : false;

            [$ok, $err] = applyWhitelistChange($db, 'delete', $original);
            if (!$ok) jsonOut(['success' => false, 'error' => $err]);
        }
        [$ok, $err, $warning] = applyWhitelistChange($db, 'insert', $name, $carried);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);

        /* Adding a parent can strand narrower entries; report them rather than
           deleting rows the administrator did not ask to remove. */
        $absorbed = redundantChildren($db, $name);
        $note     = null;
        if (count($absorbed) === 1) {
            $note = $absorbed[0] . ' is now redundant.';
        } elseif (count($absorbed) > 1) {
            $note = count($absorbed) . ' existing entries are now redundant.';
        }
        jsonOut(['success' => true, 'name' => $name,
                 'note' => joinNotes($warning, $note)]);
    }

    if ($api === 'whitelist_delete') {
        $name = normalizeDomain($_POST['name'] ?? '');
        [$ok, $err, $warning] = applyWhitelistChange($db, 'delete', $name);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);
        jsonOut(['success' => true, 'name' => $name, 'note' => $warning]);
    }

    if ($api === 'history_approve') {
        $name = normalizeDomain($_POST['name'] ?? '');
        if (!isValidWhitelistEntry($name)) {
            jsonOut(['success' => false, 'error' => 'Cannot approve ' . $name
                . ': not a valid domain (needs at least two dotted labels, e.g. example.com).']);
        }
        $covering = isWhitelisted($name, loadWhitelistSet($db));
        if ($covering !== null) {
            jsonOut(['success' => false, 'error' => $covering === $name
                ? $name . ' is already in the whitelist.'
                : $name . ' is already covered by ' . $covering
                    . ', which also matches every subdomain of it.']);
        }
        [$ok, $err, $warning] = applyWhitelistChange($db, 'insert', $name);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);

        /* Approving a base domain can strand narrower entries the same way a
           manual save can, so it reports them too rather than silently leaving
           rows that will never be consulted. */
        $absorbed = redundantChildren($db, $name);
        $note     = null;
        if (count($absorbed) === 1) {
            $note = $absorbed[0] . ' is now redundant.';
        } elseif (count($absorbed) > 1) {
            $note = count($absorbed) . ' existing entries are now redundant.';
        }
        jsonOut(['success' => true, 'name' => $name,
                 'note' => joinNotes($warning, $note)]);
    }
}

jsonOut(['success' => false, 'error' => 'Unknown API']);
