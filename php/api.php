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

/* ---- Bootgrid: games ---- */
if ($api === 'games_data') {
    [$current, $rowCount, $where, $params, $orderBy] =
        bootgridParams(['name'], ['name', 'date_approved'], '"name" ASC');

    $countStmt = $db->prepare("SELECT COUNT(*) AS c FROM games {$where}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['c'];

    $sql = "SELECT name, date_approved FROM games {$where} ORDER BY {$orderBy}";
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

/* ---- History client dropdown ---- */
if ($api === 'history_clients') {
    if (!historyHasClientIp($db)) {
        jsonOut(['success' => true, 'ready' => false, 'clients' => []]);
    }
    $rows = $db->query(
        "SELECT h.client_ip AS ip,
                (SELECT c.hostname FROM clients c WHERE c.ip = h.client_ip) AS hostname
         FROM history h
         WHERE h.client_ip <> ''
         GROUP BY h.client_ip
         ORDER BY h.client_ip"
    )->fetchAll(PDO::FETCH_ASSOC);
    jsonOut(['success' => true, 'ready' => true, 'clients' => $rows]);
}

/* ---- Bootgrid: history ---- */
if ($api === 'history_data') {
    $hasClient = historyHasClientIp($db);
    $sortable = ['name', 'count', 'last_seen', 'allowed_count', 'allowed_last_seen',
                 'total_count', 'last_any'];
    if ($hasClient) $sortable[] = 'client_ip';
    [$current, $rowCount, $where, $params, $orderBy] =
        bootgridParams(['name'], $sortable, '"last_any" DESC');

    /* A name is allowed when either list holds it or a parent, or it is a
     * local single-label name. The suffix test compares the trailing ".<entry>"
     * via substr rather than LIKE, so an underscore or percent in an entry
     * cannot act as a wildcard. */
    $coverExpr = function ($table, $alias) {
        return "EXISTS (SELECT 1 FROM {$table} {$alias} WHERE lower(history.name) = lower({$alias}.name) "
             . "OR substr(lower(history.name), -(length({$alias}.name) + 1)) = '.' || lower({$alias}.name))";
    };
    $whitelistExpr = '(' . $coverExpr('whitelist', 'w') . ')';
    $gamesExpr     = '(' . $coverExpr('games', 'g') . ')';
    $allowedExpr   = "({$whitelistExpr} OR {$gamesExpr}";
    if (ALLOW_LOCAL_NAMES) {
        /* Single-label names are allowed as a class under Games and Whitelist,
         * so the Blocked and Allowed views have to classify them the way the
         * resolver does. instr() rather than LIKE, so no wildcard interpretation. */
        $allowedExpr .= " OR instr(history.name, '.') = 0";
    }
    /* Parenthesised as a whole because it is also used as NOT (...); without the
     * outer parens the trailing OR would escape the negation. */
    $allowedExpr .= ")";

    $statusFilter = $_POST['status'] ?? 'all';
    $filterExpr   = '';
    if ($statusFilter === 'allowed') {
        $filterExpr = $allowedExpr;
    } elseif ($statusFilter === 'blocked') {
        $filterExpr = 'NOT ' . $allowedExpr;
    }

    /* Bound, and only after the search placeholders, so the parameter order
     * matches the SQL. A value that is not an IP is ignored. */
    $clientExpr = '';
    if ($hasClient) {
        $client = trim((string)($_POST['client'] ?? ''));
        if ($client !== '' && filter_var($client, FILTER_VALIDATE_IP) !== false) {
            $clientExpr = 'client_ip = ?';
            $params[] = $client;
        }
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
    $extra = [];
    if ($filterExpr !== '') $extra[] = $filterExpr;
    if ($clientExpr !== '') $extra[] = $clientExpr;
    if ($extra) {
        /* The search clause is parenthesised because bootgridParams ORs its
         * searchable columns together, and OR binds looser than AND. */
        $joined = implode(' AND ', $extra);
        $where = ($where === '')
            ? "WHERE {$joined}"
            : 'WHERE (' . substr($where, 6) . ") AND ({$joined})";
    }

    $countStmt = $db->prepare("SELECT COUNT(*) AS c FROM history {$where}");
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch(PDO::FETCH_ASSOC)['c'];

    /* The summary aliases keep their names across all three views so the grid's
     * sort keys stay valid; only the backing expression changes. MAX() with two
     * arguments is the scalar form and yields NULL if either side is NULL, so
     * COALESCE supplies the other one. Timestamps are ISO 8601, which compares
     * correctly as text. */
    $clientSelect = $hasClient ? 'client_ip' : "'' AS client_ip";
    $sql = "SELECT name, {$clientSelect}, count, last_seen, allowed_count, allowed_last_seen, "
         . "{$totalExpr} AS total_count, "
         . "{$lastExpr} AS last_any "
         . "FROM history {$where} ORDER BY {$orderBy}";
    if ($rowCount > 0) {
        $sql .= ' LIMIT ' . (int)$rowCount . ' OFFSET ' . (int)(($current - 1) * $rowCount);
    }
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    /* Three list states, plus local names which stay in the Allowed filter:
     * on the whitelist, on the games list only, or on neither. A whitelist hit
     * wins when a name is on both lists. */
    $whitelist = loadDomainSet($db, 'whitelist');
    $games     = loadDomainSet($db, 'games');
    foreach ($rows as &$r) {
        $name       = normalizeDomain($r['name']);
        $match      = isWhitelisted($name, $whitelist);
        $gamesMatch = isWhitelisted($name, $games);
        $local      = $match === null && $gamesMatch === null && isAutoAllowed($name);
        $r['on_whitelist'] = $match !== null ? 1 : 0;
        $r['on_games']     = $gamesMatch !== null ? 1 : 0;
        $r['covered_by']   = $match;
        $r['games_by']     = $gamesMatch;
        $r['local']        = $local ? 1 : 0;
        /* Approve is the whitelist action, so this stays true only when the
         * whitelist already covers the name or the name cannot be listed. */
        $r['approved']     = ($match !== null || $local) ? 1 : 0;
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
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    foreach ($rows as &$r) {
        if (($r['mode'] ?? null) === 'filtered') $r['mode'] = 'whitelist';
    }
    unset($r);

    jsonOut([
        'current'  => $current,
        'rowCount' => $rowCount,
        'total'    => $total,
        'rows'     => $rows
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
    /* status returns a single field. A daemon that has not migrated yet still
     * says "filtered", which is whitelist-only. */
    $mode = strtolower(trim($detail));
    if ($mode === 'filtered') $mode = 'whitelist';
    jsonOut(['success' => true, 'mode' => $mode]);
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
        if (!in_array($mode, ['allowall', 'games', 'whitelist', 'blocked'], true)) {
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
    if (!in_array($mode, ['allowall', 'games', 'whitelist', 'blocked', 'default'], true)) {
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
$mutationList = [
    'whitelist_save'   => 'whitelist',
    'whitelist_delete' => 'whitelist',
    'whitelist_move'   => 'whitelist',
    'games_save'       => 'games',
    'games_delete'     => 'games',
    'games_move'       => 'games',
    'history_approve'  => 'whitelist',
    'history_games'    => 'games',
][$api] ?? null;

if ($mutationList !== null) {
    requireAdminApi();
    verifyCsrf();

    $listWhere = $mutationList === 'games' ? 'the games list' : 'the whitelist';

    if ($api === 'whitelist_move' || $api === 'games_move') {
        $name = normalizeDomain($_POST['name'] ?? '');
        $to   = $mutationList === 'whitelist' ? 'games' : 'whitelist';
        [$ok, $err, $warning] = moveBetweenLists($db, $mutationList, $to, $name);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);
        jsonOut(['success' => true, 'name' => $err, 'note' => $warning]);
    }

    if ($api === 'whitelist_save' || $api === 'games_save') {
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
           save leaves the table untouched. Coverage is within this list only. */
        $existingSet = loadDomainSet($db, $mutationList);
        if ($original !== '') unset($existingSet[$original]);
        $covering = isWhitelisted($name, $existingSet);
        if ($covering !== null) {
            jsonOut(['success' => false, 'error' => $covering === $name
                ? $name . ' is already in ' . $listWhere . '.'
                : $name . ' is already covered by ' . $covering
                    . ', which also matches every subdomain of it.']);
        }

        /* A rename is a delete plus an insert, so the daemon sees both halves.
           The original's approval date rides along, so correcting a typo does
           not restamp the entry as if it were approved just now. */
        $carried = false;
        if ($original !== '' && $original !== $name) {
            $prevStmt = $db->prepare(
                'SELECT date_approved FROM ' . $mutationList . ' WHERE name = ? COLLATE NOCASE');
            $prevStmt->execute([$original]);
            $prevRow = $prevStmt->fetch(PDO::FETCH_ASSOC);
            $carried = $prevRow ? $prevRow['date_approved'] : false;

            [$ok, $err] = applyListChange($db, $mutationList, 'delete', $original);
            if (!$ok) jsonOut(['success' => false, 'error' => $err]);
        }
        [$ok, $err, $warning] = applyListChange($db, $mutationList, 'insert', $name, $carried);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);

        /* Adding a parent can strand narrower entries; report them rather than
           deleting rows the administrator did not ask to remove. */
        $absorbed = redundantChildren($db, $name, $mutationList);
        $note     = null;
        if (count($absorbed) === 1) {
            $note = $absorbed[0] . ' is now redundant.';
        } elseif (count($absorbed) > 1) {
            $note = count($absorbed) . ' existing entries are now redundant.';
        }
        jsonOut(['success' => true, 'name' => $name,
                 'note' => joinNotes($warning, $note)]);
    }

    if ($api === 'whitelist_delete' || $api === 'games_delete') {
        $name = normalizeDomain($_POST['name'] ?? '');
        [$ok, $err, $warning] = applyListChange($db, $mutationList, 'delete', $name);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);
        jsonOut(['success' => true, 'name' => $name, 'note' => $warning]);
    }

    if ($api === 'history_approve' || $api === 'history_games') {
        $name = normalizeDomain($_POST['name'] ?? '');
        if (!isValidWhitelistEntry($name)) {
            jsonOut(['success' => false, 'error' => 'Cannot add ' . $name
                . ': not a valid domain (needs at least two dotted labels, e.g. example.com).']);
        }
        $covering = isWhitelisted($name, loadDomainSet($db, $mutationList));
        if ($covering !== null) {
            jsonOut(['success' => false, 'error' => $covering === $name
                ? $name . ' is already in ' . $listWhere . '.'
                : $name . ' is already covered by ' . $covering
                    . ', which also matches every subdomain of it.']);
        }
        [$ok, $err, $warning] = applyListChange($db, $mutationList, 'insert', $name);
        if (!$ok) jsonOut(['success' => false, 'error' => $err]);

        /* Adding a base domain can strand narrower entries the same way a
           manual save can, so it reports them too rather than silently leaving
           rows that will never be consulted. */
        $absorbed = redundantChildren($db, $name, $mutationList);
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
