<?php
/******************************************************************************
 * dns1 - DNS whitelist administration
 *
 * Page 1: whitelist - allowed domains, editable.
 * Page 2: history   - names the DNS daemon has blocked, approvable.
 ******************************************************************************/

require_once __DIR__ . '/lib.php';
require_once __DIR__ . '/auth.php';   /* handles ?action=... then exits */
require_once __DIR__ . '/api.php';    /* handles ?api=... then exits */

/* ---- Landing page (Aerial) ---- */
if (empty($_SESSION['logged_in']) && !isset($_GET['page'])) {
    ?>
<!DOCTYPE HTML>
<!--
    Aerial by HTML5 UP - html5up.net | @ajlkn
    Free for personal and commercial use under the CCA 3.0 license
    (html5up.net/license). See assets/LICENSE-html5up-aerial.txt.
-->
<html>
<head>
    <title>DNS1</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
    <link rel="stylesheet" href="assets/css/main.css" />
    <noscript><link rel="stylesheet" href="assets/css/noscript.css" /></noscript>
</head>
<body class="is-preload">
    <div id="wrapper">
        <div id="bg"></div>
        <div id="overlay"></div>
        <div id="main">
            <header id="header">
                <h1>DNS1</h1>
                <p>Whitelist &nbsp;&bull;&nbsp; History &nbsp;&bull;&nbsp; Approvals</p>
                <nav>
                    <ul>
                        <li><a href="index.php?action=login" class="icon solid fa-sign-in-alt"><span class="label">Login</span></a></li>
                        <li><a href="index.php?action=signup" class="icon solid fa-user-plus"><span class="label">Sign Up</span></a></li>
                    </ul>
                </nav>
            </header>
            <footer id="footer">
                <span class="copyright">Design: <a href="http://html5up.net">HTML5 UP</a>.</span>
            </footer>
        </div>
    </div>
    <script>
        window.onload = function() { document.body.classList.remove('is-preload'); };
        window.onorientationchange = function() { document.body.scrollTop = 0; };
    </script>
</body>
</html>
    <?php
    exit;
}

requireLogin();

$page = $_GET['page'] ?? 'whitelist';
if (!in_array($page, ['whitelist', 'games', 'history', 'control'], true)) $page = 'whitelist';
$admin = isAdmin();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= ucfirst($page) ?> - DNS1</title>

<link rel="stylesheet" href="assets/vendor/css/bootstrap.min.css">
<link rel="stylesheet" href="assets/vendor/css/jquery.bootgrid.min.css">
<link rel="stylesheet" href="assets/vendor/css/fontawesome.min.css">
<link rel="stylesheet" href="assets/vendor/css/source-sans-pro.css">
<style>
    body { font-family: 'Source Sans Pro', Arial, sans-serif; background: #f4f4f4; padding-top: 70px; }
    .navbar-dns { background: #35312f; border: 0; border-radius: 0; }
    .navbar-dns .navbar-brand { color: #fff; font-weight: 900; letter-spacing: 0.1em; text-transform: uppercase; }
    .navbar-dns .navbar-nav > li > a { color: #ddd; }
    .navbar-dns .navbar-nav > li > a:hover { color: #fff; background: #4a4441; }
    .navbar-dns .navbar-nav > .active > a,
    .navbar-dns .navbar-nav > .active > a:hover { color: #fff; background: #337ab7; }
    .panel-dns { border-top: 3px solid #337ab7; }
    .page-title { font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em; font-size: 1.3em; margin: 0; }
    .cmd-btn { cursor: pointer; border: 0; background: none; padding: 2px 8px; font-size: 1.1em; color: #35312f; }
    .cmd-btn:hover { color: #337ab7; }
    .cmd-btn[disabled] { color: #bbb; cursor: not-allowed; }
    .cmd-btn.cmd-danger:hover { color: #c0392b; }
    .cmd-btn.cmd-danger[disabled]:hover { color: #bbb; }
    .status-approved   { color: #1e8449; font-size: 1.15em; }
    .status-games      { color: #6f42c1; font-size: 1.15em; }
    .status-unapproved { color: #c0392b; font-size: 1.15em; }
    .col-status  { width: 110px; text-align: center; white-space: nowrap; }
    .col-status i + i { margin-left: 5px; }
    .col-cmd     { width: 110px; text-align: center; }
    /* History has three command buttons. The domain lists have four. */
    .col-cmd-w3  { width: 140px; }
    .col-cmd-w4  { width: 176px; }
    #alertBox { position: fixed; top: 60px; right: 18px; z-index: 2000; min-width: 300px; display: none; }
    .covered-note { font-size: 0.85em; color: #777; }
    .readonly-note { margin-bottom: 12px; }
    /* Bootgrid right-aligns its action bar; these sit on the empty left side. */
    .bar-left { float: left; margin-right: 12px; }
    /* Sits in the right-aligned action bar, immediately before the search box. */
    .history-client {
        display: inline-block; width: auto; max-width: 280px; height: 34px;
        margin: 0 8px 0 0; vertical-align: middle; padding: 6px 8px;
    }
    .history-legend {
        margin-top: 4px; padding-top: 10px; border-top: 1px solid #e5e5e5;
        color: #666; font-size: .92em;
    }
    .history-legend span { display: inline-block; margin: 0 18px 4px 0; white-space: nowrap; }
    .history-legend i { margin-right: 6px; }
    .filter-group .btn {
        border-color: #ccc; color: #55504d; font-weight: 600;
        transition: background-color .12s ease, color .12s ease;
    }
    .filter-group .btn i { margin-right: 5px; opacity: .75; }
    .filter-group .btn:hover { background: #eceef0; }
    .filter-group .btn.active,
    .filter-group .btn.active:hover,
    .filter-group .btn.active:focus {
        background: #337ab7; border-color: #2e6da4; color: #fff; box-shadow: none;
    }
    .filter-group .btn.active i { opacity: 1; }
    /* Double-click a history name for the full value and block/allow actions. */
    #historyGrid td.col-name { cursor: pointer; user-select: none; -webkit-user-select: none; }
    #historyGrid td.col-name:hover { color: #337ab7; }
    .domain-full {
        font-family: 'Consolas', 'Menlo', monospace; font-size: 1.05em; word-break: break-all;
        background: #f7f7f9; border: 1px solid #e1e1e8; border-radius: 3px;
        padding: 9px 11px; margin-bottom: 14px;
    }
    .detail-status { margin: 0; font-size: 1.02em; }
    .detail-status .fa-solid { margin-right: 6px; }
    .detail-note {
        margin: 12px 0 0; padding: 9px 11px; border-radius: 3px;
        background: #fcf8e3; border: 1px solid #faebcc; color: #8a6d3b; font-size: .92em;
    }
    .detail-note code { background: #f7f0dd; color: #8a6d3b; }
    .scope-row { margin: 4px 0; }
    .scope-row label { font-weight: 400; }
    .scope-row code { font-size: .95em; }
    .scope-hint { display: block; margin-left: 20px; font-size: .85em; color: #999; }
    .scope-custom { margin: 6px 0 0 20px; width: calc(100% - 20px); font-family: 'Consolas', 'Menlo', monospace; }
    #detailScope { margin-top: 14px; padding-top: 12px; border-top: 1px solid #eee; }

    /* Control page */
    .default-policy {
        display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
        padding: 18px 20px; border-radius: 4px; border: 1px solid #ddd; background: #fafafa;
        transition: background-color .15s ease, border-color .15s ease;
    }
    .default-state { display: flex; align-items: center; gap: 16px; }
    .default-state > i { font-size: 2.4em; width: 44px; text-align: center; }
    .default-label { font-size: 1.25em; font-weight: 600; line-height: 1.2; }
    .default-hint { font-size: .9em; color: #777; margin-top: 2px; }
    .default-policy.is-allowall { background: #f3faf4; border-color: #cfe8d6; }
    .default-policy.is-allowall .default-state > i { color: #2e9e4f; }
    .default-policy.is-games { background: #f7f4fb; border-color: #ddd0ee; }
    .default-policy.is-games .default-state > i { color: #6f42c1; }
    .default-policy.is-whitelist { background: #fdfaf2; border-color: #f0e2c2; }
    .default-policy.is-whitelist .default-state > i { color: #d99400; }
    .default-policy.is-blocked  { background: #fdf3f2; border-color: #f0cfcb; }
    .default-policy.is-blocked  .default-state > i { color: #c0392b; }
    .default-policy.is-unknown  .default-state > i { color: #aaa; }
    .policy-note {
        margin: 14px 0 0; padding: 9px 11px; border-radius: 3px;
        background: #fcf8e3; border: 1px solid #faebcc; color: #8a6d3b; font-size: .92em;
    }
    .col-num { width: 90px; text-align: right; }
    #clientGrid td.col-num { text-align: right; }
    .client-blocked   td { background: #fdf3f2 !important; }
    .client-allowall  td { background: #f3faf4 !important; }
    .client-games     td { background: #f7f4fb !important; }
    .client-whitelist td { background: #fdfaf2 !important; }

    /* Policy picker: side-by-side buttons, current one raised. The states are
       told apart by colour, so each icon carries a text label. */
    .mode-allowall  { color: #2e9e4f; }
    .mode-games     { color: #6f42c1; }
    .mode-whitelist { color: #d99400; }
    .mode-blocked   { color: #cc3b33; }
    .mode-default   { color: #4a7fb5; }
    .mode-inactive  { color: #b6bcc2; }

    .col-policy { width: 520px; }
    /* Bottom padding leaves room for the active button to lift without the row
       growing and shifting every other row on the page. */
    #clientGrid td.col-policy { padding-top: 8px; padding-bottom: 4px; }

    .policy-group { display: inline-flex; align-items: flex-end; flex-wrap: wrap; gap: 3px; }
    .policy-btn {
        display: inline-flex; align-items: center; gap: 5px;
        padding: 3px 8px; font-size: 12px; line-height: 1.4;
        border: 1px solid #d5dade; border-radius: 3px;
        background: #f7f8f9; color: #8a9198; cursor: pointer;
        transition: transform .12s ease, box-shadow .12s ease, background .12s ease;
    }
    .policy-btn:hover:not(.is-active):not([disabled]) { background: #eef1f3; color: #5a6167; }
    .policy-btn[disabled] { cursor: default; opacity: .6; }
    .policy-btn.is-active {
        background: #fff; color: #333; font-weight: 600;
        border-color: #b9c0c6;
        transform: translateY(-3px);
        box-shadow: 0 3px 5px -1px rgba(0,0,0,.22);
    }
    .policy-btn.is-active.mode-allowall  { border-color: #2e9e4f; }
    .policy-btn.is-active.mode-games     { border-color: #6f42c1; }
    .policy-btn.is-active.mode-whitelist { border-color: #d99400; }
    .policy-btn.is-active.mode-blocked   { border-color: #cc3b33; }
    .policy-btn.is-active.mode-default   { border-color: #4a7fb5; }
    /* The icon keeps its own state colour; only the label follows the button. */
    .policy-btn.is-active > span { color: #333; }

    /* The default picker is the same control at panel scale. */
    .policy-group-lg { gap: 5px; padding-top: 4px; }
    .policy-group-lg .policy-btn { padding: 7px 14px; font-size: 14px; gap: 7px; }
    .hostname-unknown { color: #aaa; font-style: italic; }
</style>
</head>
<body>

<nav class="navbar navbar-dns navbar-fixed-top">
  <div class="container-fluid">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#dnsNav">
        <span class="icon-bar"></span><span class="icon-bar"></span><span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="index.php">DNS1</a>
    </div>
    <div class="collapse navbar-collapse" id="dnsNav">
      <ul class="nav navbar-nav">
        <li class="<?= $page === 'whitelist' ? 'active' : '' ?>">
          <a href="index.php?page=whitelist"><i class="fa-solid fa-shield-halved"></i> Whitelist</a></li>
        <li class="<?= $page === 'games' ? 'active' : '' ?>">
          <a href="index.php?page=games"><i class="fa-solid fa-gamepad"></i> Games</a></li>
        <li class="<?= $page === 'history' ? 'active' : '' ?>">
          <a href="index.php?page=history"><i class="fa-solid fa-clock-rotate-left"></i> History</a></li>
        <li class="<?= $page === 'control' ? 'active' : '' ?>">
          <a href="index.php?page=control"><i class="fa-solid fa-sliders"></i> Control</a></li>
      </ul>
      <ul class="nav navbar-nav navbar-right">
        <li><a href="index.php?action=profile"><i class="fa-regular fa-user"></i>
            <?= htmlspecialchars($_SESSION['username']) ?><?= $admin ? ' (admin)' : '' ?></a></li>
        <li>
          <form method="POST" action="index.php" style="margin:0;">
            <input type="hidden" name="action" value="logout">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">
            <button type="submit" class="btn btn-link navbar-btn" style="color:#ddd;text-decoration:none;">
              <i class="fa-solid fa-right-from-bracket"></i> Logout</button>
          </form>
        </li>
      </ul>
    </div>
  </div>
</nav>

<div id="alertBox" class="alert"></div>

<div class="container-fluid">
<?php if (!$admin): ?>
  <div class="alert alert-info readonly-note">
    <i class="fa-solid fa-circle-info"></i>
    You are signed in as a standard user, so this view is read only. Commands require administrator access.
  </div>
<?php endif; ?>

<?php if ($page === 'whitelist'): ?>
  <div class="panel panel-default panel-dns">
    <div class="panel-heading" style="display:flex;justify-content:space-between;align-items:center;">
      <h3 class="page-title">Whitelist</h3>
      <button id="autoRefreshBtn" class="btn btn-sm btn-danger" onclick="toggleAutoRefresh()">
        <i class="fa-solid fa-gem"></i> Auto refresh</button>
    </div>
    <div class="panel-body">
      <table id="whitelistGrid" class="table table-condensed table-hover table-striped">
        <thead>
          <tr>
            <th data-column-id="name" data-sortable="true" data-order="asc" data-width="55%">Name</th>
            <th data-column-id="date_approved" data-formatter="ts" data-sortable="true"
                data-searchable="false" data-width="30%">Approved</th>
            <th data-column-id="commands" data-formatter="commands" data-sortable="false"
                data-searchable="false" data-css-class="col-cmd col-cmd-w4"
                data-header-css-class="col-cmd col-cmd-w4">Commands</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>

<?php elseif ($page === 'games'): ?>
  <div class="panel panel-default panel-dns">
    <div class="panel-heading" style="display:flex;justify-content:space-between;align-items:center;">
      <h3 class="page-title">Games</h3>
      <button id="autoRefreshBtn" class="btn btn-sm btn-danger" onclick="toggleAutoRefresh()">
        <i class="fa-solid fa-gem"></i> Auto refresh</button>
    </div>
    <div class="panel-body">
      <table id="gamesGrid" class="table table-condensed table-hover table-striped">
        <thead>
          <tr>
            <th data-column-id="name" data-sortable="true" data-order="asc" data-width="55%">Name</th>
            <th data-column-id="date_approved" data-formatter="ts" data-sortable="true"
                data-searchable="false" data-width="30%">Approved</th>
            <th data-column-id="commands" data-formatter="commands" data-sortable="false"
                data-searchable="false" data-css-class="col-cmd col-cmd-w4"
                data-header-css-class="col-cmd col-cmd-w4">Commands</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>

<?php elseif ($page === 'history'): ?>
  <div class="panel panel-default panel-dns">
    <div class="panel-heading" style="display:flex;justify-content:space-between;align-items:center;">
      <h3 class="page-title">History</h3>
      <button id="autoRefreshBtn" class="btn btn-sm btn-danger" onclick="toggleAutoRefresh()">
        <i class="fa-solid fa-gem"></i> Auto refresh</button>
    </div>
    <div class="panel-body">
      <table id="historyGrid" class="table table-condensed table-hover table-striped">
        <thead>
          <tr>
            <th data-column-id="approved" data-formatter="status" data-sortable="false"
                data-searchable="false" data-css-class="col-status" data-header-css-class="col-status">Status</th>
            <th data-column-id="name" data-sortable="true" data-width="40%"
                data-css-class="col-name" data-header-css-class="col-name">Name</th>
            <th data-column-id="client_ip" data-formatter="client" data-sortable="true"
                data-searchable="false" data-width="180px">Client</th>
            <th data-column-id="total_count" data-sortable="true" data-searchable="false"
                data-width="80" data-align="right" data-header-align="right">Count</th>
            <th data-column-id="last_any" data-sortable="true" data-searchable="false"
                data-formatter="ts" data-order="desc">Last Seen</th>
            <th data-column-id="count" data-sortable="true" data-searchable="false"
                data-visible="false">Denied</th>
            <th data-column-id="last_seen" data-sortable="true" data-searchable="false"
                data-formatter="ts" data-visible="false">Last Denied</th>
            <th data-column-id="allowed_count" data-sortable="true" data-searchable="false"
                data-visible="false">Allowed</th>
            <th data-column-id="allowed_last_seen" data-sortable="true" data-searchable="false"
                data-formatter="ts" data-visible="false">Last Allowed</th>
            <th data-column-id="commands" data-formatter="commands" data-sortable="false"
                data-searchable="false" data-css-class="col-cmd col-cmd-w3"
                data-header-css-class="col-cmd col-cmd-w3">Commands</th>
          </tr>
        </thead>
      </table>
      <div class="history-legend">
        <span><i class="fa-solid fa-circle-check status-approved"></i> Whitelist — on the whitelist, including by a parent domain</span>
        <span><i class="fa-solid fa-circle-check status-approved"></i> Local name — a single-label name, always allowed</span>
        <span><i class="fa-solid fa-gamepad status-games"></i><i class="fa-solid fa-circle-check status-approved"></i> Games, allowed for this client</span>
        <span><i class="fa-solid fa-gamepad status-games"></i><i class="fa-solid fa-circle-minus status-unapproved"></i> Games, blocked for this client</span>
        <span><i class="fa-solid fa-circle-minus status-unapproved"></i> Unapproved — on neither list</span>
      </div>
    </div>
  </div>
<?php elseif ($page === 'control'): ?>
  <div class="panel panel-default panel-dns">
    <div class="panel-heading">Default policy</div>
    <div class="panel-body">
      <div id="defaultPolicy" class="default-policy is-unknown">
        <div class="default-state">
          <i id="defaultIcon" class="fa-solid fa-circle-question"></i>
          <div>
            <div id="defaultLabel" class="default-label">Checking&hellip;</div>
            <div id="defaultHint" class="default-hint">Contacting the DNS daemon.</div>
          </div>
        </div>
        <div id="defaultPicker"></div>
      </div>
      <p class="policy-note">
        <i class="fa-solid fa-flag"></i>
        This applies to every client that has not been given a policy of its own &mdash;
        including any device that appears on the network from now on. Changing it moves
        all of them at once.
      </p>
    </div>
  </div>

  <div class="panel panel-default panel-dns">
    <div class="panel-heading" style="display:flex;justify-content:space-between;align-items:center;">
      <span>Clients
        <small class="text-muted" style="margin-left:8px;">Discovered from incoming queries; names come from reverse DNS.</small>
      </span>
      <button id="autoRefreshBtn" class="btn btn-sm btn-danger" onclick="toggleAutoRefresh()">
        <i class="fa-solid fa-gem"></i> Auto refresh</button>
    </div>
    <div class="panel-body">
      <table id="clientGrid" class="table table-condensed table-hover table-striped">
        <thead>
          <tr>
            <th data-column-id="ip" data-sortable="true" data-order="asc" data-width="20%">IP address</th>
            <th data-column-id="hostname" data-formatter="hostname" data-sortable="true"
                data-width="24%">Machine name</th>
            <th data-column-id="mode" data-formatter="clientMode" data-sortable="true"
                data-searchable="false" data-width="520px"
                data-css-class="col-policy" data-header-css-class="col-policy">Policy</th>
            <th data-column-id="query_count" data-sortable="true" data-searchable="false"
                data-css-class="col-num" data-header-css-class="col-num">Queries</th>
            <th data-column-id="last_seen" data-formatter="ts" data-sortable="true"
                data-searchable="false">Last seen</th>
            <th data-column-id="commands" data-formatter="clientCommands" data-sortable="false"
                data-searchable="false" data-css-class="col-cmd"
                data-header-css-class="col-cmd">Commands</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>
<?php endif; ?>
</div>

<!-- Reusable confirmation dialog (replaces native confirm()) -->
<div class="modal fade" id="confirmModal" tabindex="-1">
  <div class="modal-dialog modal-sm">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal">&times;</button>
        <h4 class="modal-title" id="confirmTitle">Confirm</h4>
      </div>
      <div class="modal-body">
        <p id="confirmBody" style="margin:0;"></p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary" id="confirmOk">OK</button>
      </div>
    </div>
  </div>
</div>

<!-- Domain detail, opened by double-clicking a history name -->
<div class="modal fade" id="detailModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal">&times;</button>
        <h4 class="modal-title" id="detailTitle">Domain</h4>
      </div>
      <div class="modal-body">
        <div class="domain-full" id="detailName"></div>
        <p class="detail-status" id="detailStatus"></p>
        <div id="detailScope" style="display:none;">
          <div class="radio scope-row">
            <label>
              <input type="radio" name="allowScope" value="exact" checked>
              <span class="scope-verb">Allow</span> exact domain <code id="scopeExactText"></code>
            </label>
          </div>
          <div class="radio scope-row" id="scopeBaseRow">
            <label>
              <input type="radio" name="allowScope" value="base">
              <span class="scope-verb">Allow</span> base domain <code id="scopeBaseText"></code>
            </label>
            <span class="scope-hint">also allows every subdomain of it</span>
          </div>
          <div class="radio scope-row">
            <label>
              <input type="radio" name="allowScope" value="custom">
              <span class="scope-verb">Allow</span> custom
            </label>
            <input type="text" class="form-control scope-custom" id="scopeCustomText"
                   spellcheck="false" autocomplete="off" disabled>
          </div>
        </div>
        <p class="detail-note" id="detailNote" style="display:none;"></p>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
        <button type="button" class="btn" id="detailAction"></button>
      </div>
    </div>
  </div>
</div>

<!-- Edit / add whitelist or games entry -->
<div class="modal fade" id="editModal" tabindex="-1">
  <div class="modal-dialog modal-sm">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal">&times;</button>
        <h4 class="modal-title" id="editTitle">Edit Domain</h4>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label for="editName" id="editNameLabel">Domain name</label>
          <input type="text" class="form-control" id="editName" placeholder="example.com" autocomplete="off">
          <p class="help-block" id="editHelp">Matches the domain and every subdomain of it.
             Must have at least two labels, using letters, digits, hyphen or underscore.</p>
        </div>
        <div id="editScope" style="display:none;">
          <div class="radio scope-row">
            <label>
              <input type="radio" name="editScope" value="exact" checked>
              Add exact domain <code id="editExactText"></code>
            </label>
          </div>
          <div class="radio scope-row" id="editBaseRow">
            <label>
              <input type="radio" name="editScope" value="base">
              Add base domain <code id="editBaseText"></code>
            </label>
            <span class="scope-hint">also allows every subdomain of it</span>
          </div>
          <div class="radio scope-row">
            <label>
              <input type="radio" name="editScope" value="custom">
              Add custom
            </label>
            <input type="text" class="form-control scope-custom" id="editCustomText"
                   spellcheck="false" autocomplete="off" disabled>
          </div>
        </div>
        <div id="editError" class="text-danger" style="display:none;"></div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-link text-danger" id="deleteBtn" onclick="deleteEntry()"
                style="float:left;"><i class="fa-regular fa-trash-can"></i> Delete</button>
        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary" id="editSaveBtn" onclick="saveEntry()">Save</button>
      </div>
    </div>
  </div>
</div>

<script src="assets/vendor/js/jquery.min.js"></script>
<script src="assets/vendor/js/bootstrap.min.js"></script>
<script src="assets/vendor/js/jquery.bootgrid.min.js"></script>
<script>
var CSRF     = <?= json_encode($csrfToken) ?>;
var IS_ADMIN = <?= $admin ? 'true' : 'false' ?>;
var PAGE     = <?= json_encode($page) ?>;
var grid     = null;
var editOriginal = '';
/* Hostname last parsed out of the add field, so a URL edit can refresh the
   custom box without wiping a name the user has already changed. */
var editParsedHost = '';

/* Escapes for both text and attribute contexts. innerHTML leaves quotes alone,
   so the previous .text().html() form could not safely build data-name="...";
   a queried name containing a quote would have escaped the attribute. */
function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/* Converts a stored UTC ISO-8601 timestamp to "YYYY-MM-DD HH:MM:SS AM/PM" in
   the browser's zone, or null when the value will not parse.

   The daemon writes nanosecond precision ("...:44.417804935Z"), but the
   ECMAScript date format specifies exactly three fractional digits. Engines
   tolerate more to varying degrees, so the fraction is dropped before parsing
   rather than relied upon; it is well below the displayed resolution anyway. */
function toLocalTimestamp(value) {
    var s = String(value);
    var m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(s);
    if (!m) return null;

    /* A stored value without an offset is still UTC, since that is the only
       zone the daemon writes; assuming local here would shift it twice. */
    var d = new Date(m[1] + (m[2] || 'Z'));
    if (isNaN(d.getTime())) return null;

    function p(n) { return (n < 10 ? '0' : '') + n; }

    /* Hour 0 is 12 AM and hour 12 is 12 PM, so the wrap has to map 0 to 12
       rather than leaving it as a bare modulo. The hour stays zero-padded so
       the column does not ragged-edge between one- and two-digit hours. */
    var h24 = d.getHours();
    var h12 = h24 % 12;
    if (h12 === 0) h12 = 12;

    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) +
           ' ' + p(h12) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) +
           ' ' + (h24 < 12 ? 'AM' : 'PM');
}

function notify(msg, type) {
    $('#alertBox').removeClass('alert-success alert-danger alert-info')
        .addClass('alert-' + (type || 'info')).html(esc(msg)).fadeIn(150);
    clearTimeout(window._alertTimer);
    window._alertTimer = setTimeout(function () { $('#alertBox').fadeOut(300); }, 4000);
}

/* Which History rows to show: all, blocked (on neither list), or allowed.
   historyClient is empty for every client, or one IP from the dropdown. */
var historyFilter = 'all';
var historyClient = '';

/* The policies, in increasing order of strictness, plus the "default"
   pseudo-policy a client uses to say it has none of its own. Kept in one place
   so the icon, the colour and the label cannot drift apart. */
var CLIENT_MODES = {
    'default': {
        label: 'Default',
        icon:  'fa-flag',
        cls:   'mode-default',
        hint:  'Follow the default policy, whatever it is set to now or later.'
    },
    allowall: {
        label: 'Allow all',
        icon:  'fa-shield',
        cls:   'mode-allowall',
        hint:  'Allow all: every name resolves, both lists ignored.'
    },
    games: {
        label: 'Games',
        icon:  'fa-gamepad',
        cls:   'mode-games',
        hint:  'Games: whitelisted names and games names resolve.'
    },
    whitelist: {
        label: 'Whitelist',
        icon:  'fa-shield-halved',
        cls:   'mode-whitelist',
        hint:  'Whitelist: only whitelisted names resolve.'
    },
    blocked: {
        label: 'Block all',
        icon:  'fa-shield',
        cls:   'mode-blocked',
        hint:  'Block all: every query is refused, listed names included.'
    }
};

/* Fixed order for the pickers, strictest last. A client can also inherit, so it
   gets the extra button; the default itself has nothing to inherit from. */
var CLIENT_MODE_ORDER  = ['default', 'allowall', 'games', 'whitelist', 'blocked'];
var DEFAULT_MODE_ORDER = ['allowall', 'games', 'whitelist', 'blocked'];

/* The default in force, as last reported by the daemon. Null until the first
   reply arrives, or if the daemon cannot be reached. Held here because an
   inheriting client's real behaviour cannot be shown without it. */
var DEFAULT_POLICY = null;

function modeIcon(mode, active) {
    var m = CLIENT_MODES[mode];
    return '<i class="fa-solid ' + m.icon + ' ' + (active ? m.cls : 'mode-inactive') + '"></i>';
}

/* The "Default" button says what it currently resolves to, so choosing it is
   not a guess. */
function policyHint(mode) {
    if (mode === 'default' && DEFAULT_POLICY) {
        return CLIENT_MODES[mode].hint + ' Currently: '
             + CLIENT_MODES[DEFAULT_POLICY].label + '.';
    }
    return CLIENT_MODES[mode].hint;
}

/* Side-by-side buttons rather than a menu: every state stays visible and the
   one in force is raised, so it reads at a glance. Shared by the client rows
   and the default picker, which differ only in scale and in the extra button. */
function policyGroup(order, cur, opts) {
    opts = opts || {};
    var out = '<div class="policy-group' + (opts.large ? ' policy-group-lg' : '') + '"'
            + (opts.ip ? ' data-ip="' + esc(opts.ip) + '"' : '')
            + ' data-mode="' + cur + '">';

    order.forEach(function (k) {
        var on = (k === cur);
        out += '<button type="button" class="policy-btn'
             + (on ? ' is-active ' + CLIENT_MODES[k].cls : '')
             + '" data-mode="' + k + '"'
             + ' title="' + esc(policyHint(k)) + '"'
             + (IS_ADMIN ? '' : ' disabled')
             + (on ? ' aria-pressed="true"' : '') + '>'
             + modeIcon(k, on) + '<span>' + esc(CLIENT_MODES[k].label) + '</span>'
             + '</button>';
    });

    return out + '</div>';
}

/* A NULL mode means the row carries no policy of its own. */
function rowMode(row) {
    return (row && row.mode && CLIENT_MODES[row.mode]) ? row.mode : 'default';
}

/* What a client is actually judged under: its own policy, or the default. */
function effectiveMode(row) {
    var m = rowMode(row);
    return m === 'default' ? DEFAULT_POLICY : m;
}

/* Bootgrid ships Glyphicon class names, which Bootstrap 3 provides. */
var gridOptions = {
    ajax: true,
    post: function () {
        var p = { csrf_token: CSRF };
        if (PAGE === 'history') {
            p.status = historyFilter;
            if (historyClient) p.client = historyClient;
        }
        return p;
    },
    selection: false,
    rowCount: [10, 25, 50, -1],
    searchSettings: { delay: 250, characters: 2 },
    formatters: {
        commands: function (column, row) {
            var copy = '<button class="cmd-btn js-copy" title="Copy domain to clipboard"' +
                       ' data-name="' + esc(row.name) + '">' +
                       '<i class="fa-regular fa-clipboard"></i></button>';
            if (PAGE === 'whitelist' || PAGE === 'games') {
                var listName = PAGE === 'games' ? 'games list' : 'whitelist';
                var move = PAGE === 'whitelist'
                    ? '<button class="cmd-btn js-move" title="Move to Games" data-name="' + esc(row.name) + '"' +
                      (IS_ADMIN ? '' : ' disabled') +
                      '><i class="fa-solid fa-gamepad"></i></button>'
                    : '<button class="cmd-btn js-move" title="Move to Whitelist" data-name="' + esc(row.name) + '"' +
                      (IS_ADMIN ? '' : ' disabled') +
                      '><i class="fa-solid fa-shield-halved"></i></button>';
                return '<button class="cmd-btn js-edit" title="Edit" data-name="' + esc(row.name) + '"' +
                       (IS_ADMIN ? '' : ' disabled') +
                       '><i class="fa-regular fa-pen-to-square"></i></button>' + copy + move +
                       '<button class="cmd-btn cmd-danger js-delete"' +
                       ' title="Remove from ' + listName + '" data-name="' + esc(row.name) + '"' +
                       (IS_ADMIN ? '' : ' disabled') +
                       '><i class="fa-regular fa-trash-can"></i></button>';
            }
            var gamesDisabled = !IS_ADMIN || row.on_games || row.local;
            return '<button class="cmd-btn js-approve" title="Add to Whitelist" data-name="' + esc(row.name) + '"' +
                   (IS_ADMIN && !row.approved ? '' : ' disabled') +
                   '><i class="fa-solid fa-check-to-slot"></i></button>' +
                   '<button class="cmd-btn js-games" title="Add to Games" data-name="' + esc(row.name) + '"' +
                   (gamesDisabled ? ' disabled' : '') +
                   '><i class="fa-solid fa-gamepad"></i></button>' + copy;
        },
        /* Four buttons: the client's own policy, or "Default" to follow the
           network-wide one. */
        clientMode: function (column, row) {
            return policyGroup(CLIENT_MODE_ORDER, rowMode(row), { ip: row.ip });
        },
        hostname: function (column, row) {
            if (!row.hostname) {
                return '<span class="hostname-unknown" title="No PTR record returned by the secondary DNS server">unknown</span>';
            }
            /* PTR records come back fully qualified ("velky.rhost.sytes.net"),
               but the domain is the same for every device on the network and
               only the first label identifies the machine. The full name stays
               in the tooltip, and in the table so search still matches it. */
            var short = String(row.hostname).split('.')[0];
            if (!short) return esc(row.hostname);
            return '<span title="' + esc(row.hostname) + '">' + esc(short) + '</span>';
        },
        clientCommands: function (column, row) {
            return '<button class="cmd-btn js-copy" title="Copy IP to clipboard"' +
                   ' data-name="' + esc(row.ip) + '">' +
                   '<i class="fa-regular fa-clipboard"></i></button>';
        },
        client: function (column, row) {
            if (!row.client_ip) {
                return '<span class="hostname-unknown">unknown</span>';
            }
            return esc(row.client_ip);
        },
        status: function (column, row) {
            if (row.on_whitelist) {
                var t = 'Approved';
                if (row.covered_by && row.covered_by !== row.name) {
                    t = 'Approved via ' + row.covered_by;
                }
                return '<i class="fa-solid fa-circle-check status-approved" title="' + esc(t) + '"></i>';
            }
            if (row.local) {
                return '<i class="fa-solid fa-circle-check status-approved" title="Allowed: local network name"></i>';
            }
            if (row.on_games) {
                var g = 'Games';
                if (row.games_by && row.games_by !== row.name) {
                    g = 'Games via ' + row.games_by;
                }
                /* The gamepad says which list covers the name. The second icon
                 * says what happened for this client: allowed lookups, or
                 * refusals. When a row has both, the later timestamp wins. */
                var denied = parseInt(row.count, 10) || 0;
                var allowed = parseInt(row.allowed_count, 10) || 0;
                var allowedLater = row.allowed_last_seen &&
                    (!row.last_seen || String(row.allowed_last_seen) > String(row.last_seen));
                var wasAllowed = allowed > 0 && (denied === 0 || allowedLater);
                var outcome = '';
                if (wasAllowed) {
                    outcome = '<i class="fa-solid fa-circle-check status-approved" title="Allowed"></i>';
                } else if (denied > 0) {
                    outcome = '<i class="fa-solid fa-circle-minus status-unapproved" title="Blocked"></i>';
                }
                return '<i class="fa-solid fa-gamepad status-games" title="' + esc(g) + '"></i>' + outcome;
            }
            return '<i class="fa-solid fa-circle-minus status-unapproved" title="Unapproved"></i>';
        },
        /* Timestamps are stored as UTC ISO-8601 and are rendered in the
           browser's own zone, so the times read the same as the clock on the
           machine viewing them. The raw UTC value stays in the tooltip. */
        ts: function (column, row) {
            var v = row[column.id];
            if (!v) return '<span class="text-muted">&mdash;</span>';
            var local = toLocalTimestamp(v);
            return local === null
                ? esc(v)
                : '<span title="' + esc(v) + ' (UTC)">' + esc(local) + '</span>';
        }
    }
};

$(function () {
    if (PAGE === 'whitelist' || PAGE === 'games') {
        var gridSel = PAGE === 'games' ? '#gamesGrid' : '#whitelistGrid';
        var dataApi = PAGE === 'games' ? 'games_data' : 'whitelist_data';
        grid = $(gridSel).bootgrid($.extend({}, gridOptions, {
            url: 'index.php?api=' + dataApi
        })).on('loaded.rs.jquery.bootgrid', function () {
            injectAddDomainButton();
            grid.find('.js-edit').off('click').on('click', function () {
                openEdit($(this).data('name'));
            });
            grid.find('.js-delete').off('click').on('click', function () {
                removeDomain($(this).data('name'));
            });
            grid.find('.js-move').off('click').on('click', function () {
                moveDomain($(this).data('name'));
            });
            bindCopyButtons();
        });
    } else if (PAGE === 'control') {
        grid = $('#clientGrid').bootgrid($.extend({}, gridOptions, {
            url: 'index.php?api=client_data',
            rowCount: [25, 50, -1]
        })).on('loaded.rs.jquery.bootgrid', function () {
            /* Bootgrid's own row handler stops propagation, so these are bound
               directly after each render rather than delegated on the table. */
            bindPolicyButtons();
            bindCopyButtons();
            markClientRows();
        });

        $('#defaultPicker').on('click', '.policy-btn', function (e) {
            e.preventDefault();
            setDefaultPolicy($(this).data('mode'));
        });
        refreshDefaultPolicy();
        setInterval(refreshDefaultPolicy, AUTO_REFRESH_MS);
    } else {
        grid = $('#historyGrid').bootgrid($.extend({}, gridOptions, {
            url: 'index.php?api=history_data'
        })).on('loaded.rs.jquery.bootgrid', function () {
            injectHistoryFilter();
            injectHistoryClient();
            applyHistoryHeadings();
            /* Approve opens the same dialog as a double-click, so the allow
               scope can be chosen there rather than being implicitly the exact
               name. */
            grid.find('.js-approve').off('click').on('click', function () {
                openDetailForRow($(this), 'whitelist');
            });
            grid.find('.js-games').off('click').on('click', function () {
                openDetailForRow($(this), 'games');
            });
            bindCopyButtons();
        });

        /* Bootgrid binds no dblclick handler, so unlike the command buttons
           this can stay delegated on the table and survive reloads. The row
           object comes from getCurrentRows() by position instead of being
           embedded in attributes. */
        grid.on('dblclick', 'td.col-name', function () {
            openDetailForRow($(this), 'whitelist');
        });

        $('#detailAction').on('click', applyDetailAction);
        $('#scopeCustomText').on('keydown', function (e) {
            if (e.which === 13) { e.preventDefault(); applyDetailAction(); }
        });
        /* The text field only applies to its own radio, so it follows the
           selection rather than being editable while another scope is active. */
        $('input[name="allowScope"]').on('change', function () {
            var custom = $('input[name="allowScope"]:checked').val() === 'custom';
            $('#scopeCustomText').prop('disabled', !custom);
            if (custom) $('#scopeCustomText').focus().select();
        });
    }
    setAutoRefresh(true);
});

/* Bootgrid's own "> tr" click handler calls stopPropagation(), so a delegated
   click handler on the table never sees clicks inside a row. Command buttons
   are bound directly to the elements after each render instead. */
function bindCopyButtons() {
    grid.find('.js-copy').off('click').on('click', function () {
        copyToClipboard($(this).data('name'));
    });
}

/******************************************************************************
 * Control page
 ******************************************************************************/

/* Tints the whole row to match the policy the client is actually judged under,
   which the per-cell formatters cannot do because bootgrid builds the <tr>
   itself. An inheriting row is tinted by the default, so a network-wide block
   is visible on every row it affects rather than only on the panel above. */
function markClientRows() {
    var rows = grid.bootgrid('getCurrentRows') || [];
    grid.find('tbody > tr').each(function (i) {
        var mode = effectiveMode(rows[i]);
        $(this).removeClass('client-allowall client-games client-whitelist client-blocked')
               .addClass(mode ? 'client-' + mode : '');
    });
}

/* The daemon owns this state, so it is read back from the daemon rather than
   assumed from whatever was last clicked. */
function refreshDefaultPolicy() {
    $.post('index.php?api=control_status', { csrf_token: CSRF }, null, 'json')
        .done(function (res) {
            renderDefaultPolicy(res && res.success && CLIENT_MODES[res.mode] ? res.mode : null);
        })
        .fail(function () { renderDefaultPolicy(null); });
}

function renderDefaultPolicy(mode) {
    var changed = (mode !== DEFAULT_POLICY);
    DEFAULT_POLICY = mode;

    var $box = $('#defaultPolicy');
    $box.removeClass('is-allowall is-games is-whitelist is-blocked is-unknown');

    if (mode === null) {
        $box.addClass('is-unknown');
        $('#defaultIcon').attr('class', 'fa-solid fa-circle-question');
        $('#defaultLabel').text('Daemon unreachable');
        $('#defaultHint').text('The DNS daemon is not answering on its control port.');
        $('#defaultPicker').empty();
    } else {
        var HINTS = {
            allowall:  'Every name resolves for these clients; both lists are ignored.',
            games:     'Whitelisted names and games names resolve.',
            whitelist: 'Only whitelisted names resolve.',
            blocked:   'Every query is refused, including listed names.'
        };
        $box.addClass('is-' + mode);
        $('#defaultIcon').attr('class', 'fa-solid ' + CLIENT_MODES[mode].icon);
        $('#defaultLabel').text('Default: ' + CLIENT_MODES[mode].label);
        $('#defaultHint').text(HINTS[mode]);
        $('#defaultPicker').html(policyGroup(DEFAULT_MODE_ORDER, mode, { large: true }));
    }

    /* Inheriting rows are drawn from the default, so they are stale the moment
       it moves. Only redrawn on an actual change, since this also runs on the
       poll timer. */
    if (changed && grid) { markClientRows(); }
}

function setDefaultPolicy(mode) {
    if (!IS_ADMIN || !CLIENT_MODES[mode] || mode === DEFAULT_POLICY) { return; }

    apiPost('control_default', { mode: mode }, function (res) {
        renderDefaultPolicy(res.mode);
        notify('Default policy set to ' + CLIENT_MODES[res.mode].label + '.',
               res.mode === 'blocked' ? 'danger' : 'success');
        /* Reloaded rather than left alone: the tooltips on every "Default"
           button name the policy that just changed. */
        if (grid) { grid.bootgrid('reload'); }
    });
}

/* Bootgrid's row handler calls stopPropagation, so these are bound directly to
   the buttons after each render rather than delegated on the table. */
function bindPolicyButtons() {
    grid.find('.policy-btn').off('click').on('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        var $group = $(this).closest('.policy-group');
        setClientMode($group, $group.data('ip'), $(this).data('mode'));
    });
}

/* Applied immediately on click: the buttons show the current state at all times
   and any change is one click to undo, so a confirmation step earns nothing. */
function setClientMode($group, ip, mode) {
    var prev = $group.data('mode') || 'default';
    if (!IS_ADMIN || mode === prev) { return; }

    apiPost('control_client', { ip: ip, mode: mode }, function (res) {
        var msg = res.mode === 'default'
            ? ip + ' now follows the default'
              + (DEFAULT_POLICY ? ' (' + CLIENT_MODES[DEFAULT_POLICY].label + ')' : '')
            : ip + ' set to ' + CLIENT_MODES[res.mode].label;
        notify(msg, res.mode === 'blocked' ? 'danger' : 'success');
        grid.bootgrid('reload');
    });
}

function openDetailForRow($el, dest) {
    var rows = grid.bootgrid('getCurrentRows');
    var idx  = $el.closest('tr').index();
    if (rows && rows[idx]) openDetail(rows[idx], dest);
}

/* Bootgrid owns the markup above the table, so the Add Domain button is
   injected into its action bar once the grid has rendered. */
function injectAddDomainButton() {
    if (!IS_ADMIN) return;
    var gridSel = PAGE === 'games' ? '#gamesGrid' : '#whitelistGrid';
    var $bar = $(gridSel).closest('.panel-body').find('.bootgrid-header .actionBar');
    if (!$bar.length || $bar.find('#addDomainBtn').length) return;
    $('<button/>', {
        id: 'addDomainBtn',
        'class': 'btn btn-primary bar-left',
        html: '<i class="fa-solid fa-plus"></i> Add Domain'
    }).on('click', function () { openEdit(''); }).prependTo($bar);
}

/* Segmented All / Blocked / Allowed filter, injected alongside the search box.
   Filtering runs server-side so paging and totals stay correct. */
var HISTORY_FILTERS = [
    { id: 'all',     label: 'All',     icon: 'fa-layer-group',  lastText: 'Last Seen' },
    { id: 'blocked', label: 'Blocked', icon: 'fa-ban',          lastText: 'Last Blocked' },
    { id: 'allowed', label: 'Allowed', icon: 'fa-circle-check', lastText: 'Last Allowed' }
];

/* The timestamp column reports a different event per filter, so its heading is
 * patched in place. Bootgrid builds the header from its own template and offers
 * no API to retitle a column, and destroying the grid to re-init would discard
 * the user's column and page choices. */
function applyHistoryHeadings() {
    var f = null;
    $.each(HISTORY_FILTERS, function (i, x) {
        if (x.id === historyFilter) { f = x; return false; }
    });
    if (!f) return;

    var $panel = $('#historyGrid').closest('.panel-body');
    $panel.find('th[data-column-id="last_any"] span.text').text(f.lastText);

    /* The column-selector entry is a bare text node next to its checkbox, so
     * only that node is swapped to leave the input and its handler intact. */
    var $label = $panel.find('.actionBar input[name="last_any"]').parent();
    $label.contents().filter(function () {
        return this.nodeType === 3;
    }).last().replaceWith(' ' + f.lastText);
}

function injectHistoryFilter() {
    var $bar = $('#historyGrid').closest('.panel-body').find('.bootgrid-header .actionBar');
    if (!$bar.length || $bar.find('#historyFilter').length) return;

    var $group = $('<div/>', {
        id: 'historyFilter',
        'class': 'btn-group bar-left filter-group',
        role: 'group'
    });

    $.each(HISTORY_FILTERS, function (i, f) {
        $('<button/>', {
            type: 'button',
            'class': 'btn btn-default' + (historyFilter === f.id ? ' active' : ''),
            'data-filter': f.id,
            html: '<i class="fa-solid ' + f.icon + '"></i> ' + f.label
        }).appendTo($group);
    });

    $group.on('click', 'button', function () {
        var value = $(this).data('filter');
        if (value === historyFilter) return;
        historyFilter = value;
        $group.find('button').removeClass('active');
        $(this).addClass('active');
        /* reload() also resets to page 1, which is what a filter change wants. */
        grid.bootgrid('reload');
    });

    $bar.prepend($group);
}

/* Immediately left of the search box. The action bar is right-aligned and the
 * search field is inline, so inserting the select just before it places the
 * control on its left. Hidden until the daemon has added client_ip. */
function injectHistoryClient() {
    var $bar = $('#historyGrid').closest('.panel-body').find('.bootgrid-header .actionBar');
    var $search = $bar.find('.search');
    if (!$bar.length || !$search.length) return;

    var $sel = $bar.find('#historyClient');
    if (!$sel.length) {
        $sel = $('<select/>', {
            id: 'historyClient',
            'class': 'form-control history-client',
            title: 'Show history for one client'
        });
        $search.before($sel);
        $sel.on('change', function () {
            var value = $(this).val() || '';
            if (value === historyClient) return;
            historyClient = value;
            grid.bootgrid('reload');
        });
    }

    $.post('index.php?api=history_clients', { csrf_token: CSRF }, null, 'json')
        .done(function (res) {
            if (!res || !res.ready) {
                $sel.remove();
                return;
            }
            var current = historyClient;
            $sel.empty().append($('<option/>', { value: '', text: 'All clients' }));
            $.each(res.clients || [], function (i, c) {
                var label = c.ip;
                if (c.hostname) {
                    var short = String(c.hostname).split('.')[0];
                    label = c.ip + ' (' + (short || c.hostname) + ')';
                }
                $sel.append($('<option/>', { value: c.ip, text: label }));
            });
            $sel.val(current);
            if ($sel.val() !== current) {
                $sel.val('');
                historyClient = '';
            }
        });
}

/* Auto refresh: green button while running, red while stopped. */
var AUTO_REFRESH_MS = 3000;
var autoTimer = null;

function setAutoRefresh(on) {
    if (on && !autoTimer) {
        autoTimer = setInterval(function () {
            /* Don't yank the grid out from under an open dialog. */
            if ($('.modal.in').length) return;
            if (!grid) return;
            /* bootgrid's reload() resets to page 1, so skip the tick while the
               user is reading a later page rather than dragging them back. */
            if (grid.bootgrid('getCurrentPage') > 1) return;
            grid.bootgrid('reload');
        }, AUTO_REFRESH_MS);
    } else if (!on && autoTimer) {
        clearInterval(autoTimer);
        autoTimer = null;
    }
    $('#autoRefreshBtn')
        .removeClass('btn-success btn-danger')
        .addClass(autoTimer ? 'btn-success' : 'btn-danger')
        .attr('title', autoTimer ? 'Auto refresh is running (every 3s)' : 'Auto refresh is stopped');
}

function toggleAutoRefresh() {
    setAutoRefresh(!autoTimer);
}

function openEdit(name) {
    if (!IS_ADMIN) return;
    editOriginal = name || '';
    editParsedHost = '';
    var adding = !editOriginal;
    var listTitle = PAGE === 'games' ? 'Games' : 'Whitelist';
    $('#editTitle').text(adding ? ('Add to ' + listTitle) : 'Edit Domain');
    $('#editSaveBtn').text(adding ? ('Add to ' + listTitle) : 'Save');
    $('#editNameLabel').text(adding ? 'Domain or URL' : 'Domain name');
    $('#editName').attr('placeholder', adding ? 'https://example.com/path?q=1' : 'example.com');
    $('#editHelp').text(adding
        ? 'Paste a domain or a full URL. A URL can be saved as its exact host, its base domain, or a name you type.'
        : 'Matches the domain and every subdomain of it. Must have at least two labels, using letters, digits, hyphen or underscore.');
    $('#editName').val(editOriginal);
    $('#editError').hide().text('');
    $('#editScope').hide();
    $('input[name="editScope"][value="exact"]').prop('checked', true);
    $('#editCustomText').val('').prop('disabled', true);
    $('#editModal .modal-dialog').toggleClass('modal-sm', !adding);
    $('#deleteBtn').toggle(!adding);
    $('#editModal').modal('show');
}

/* A pasted URL carries a scheme, a path, a query, or a hash. A bare domain
 * does not, and is saved as typed. */
function looksLikeUrl(text) {
    var t = $.trim(text || '');
    if (!t) return false;
    if (t.indexOf('://') !== -1 || t.indexOf('//') === 0) return true;
    return /[\/?#]/.test(t);
}

/* Hostname from a URL, or an error string when the text is URL-shaped but has
 * nothing the lists can store. Null means the text is not a URL. */
function hostFromInput(text) {
    var t = $.trim(text || '');
    if (!looksLikeUrl(t)) return null;
    var toParse = t;
    if (t.indexOf('://') === -1) {
        toParse = 'https://' + t.replace(/^\/\//, '');
    }
    var url;
    try {
        url = new URL(toParse);
    } catch (e) {
        return { error: 'That does not look like a URL.' };
    }
    var host = String(url.hostname || '').toLowerCase().replace(/\.$/, '');
    if (!host) return { error: 'That URL has no hostname.' };
    /* URL.hostname leaves IPv6 unbracketed, so a colon means an address. */
    if (host.indexOf(':') !== -1 || /^[0-9.]+$/.test(host)) {
        return { error: 'That address has no domain to add.' };
    }
    if (host.indexOf('.') === -1) {
        return { error: 'That name needs at least two labels, such as example.com.' };
    }
    return { host: host };
}

function refreshEditScope() {
    if (editOriginal) {
        $('#editScope').hide();
        return;
    }
    var raw = $('#editName').val();
    if (!looksLikeUrl(raw)) {
        $('#editScope').hide();
        $('#editError').hide().text('');
        editParsedHost = '';
        return;
    }
    var parsed = hostFromInput(raw);
    if (!parsed || parsed.error) {
        $('#editScope').hide();
        $('#editError').text(parsed && parsed.error ? parsed.error : 'That URL has no hostname.').show();
        editParsedHost = '';
        return;
    }
    $('#editError').hide().text('');
    var host = parsed.host;
    var base = baseDomain(host);
    $('#editExactText').text(host);
    $('#editBaseText').text(base);
    $('#editBaseRow').toggle(!!base && base !== host);
    var $custom = $('#editCustomText');
    if ($custom.prop('disabled') || $custom.val() === editParsedHost || !$custom.val()) {
        $custom.val(host);
    }
    editParsedHost = host;
    if (base === host && $('input[name="editScope"]:checked').val() === 'base') {
        $('input[name="editScope"][value="exact"]').prop('checked', true);
    }
    $custom.prop('disabled', $('input[name="editScope"]:checked').val() !== 'custom');
    $('#editScope').show();
}

/* The name that will be saved. A URL contributes the selected host, not the
 * raw text. A custom value that is itself a URL contributes its host. */
function chosenEditName() {
    var raw = $.trim($('#editName').val());
    if (editOriginal || !looksLikeUrl(raw) || !$('#editScope').is(':visible')) {
        return raw;
    }
    var scope = $('input[name="editScope"]:checked').val();
    if (scope === 'base') return $.trim($('#editBaseText').text());
    if (scope === 'custom') {
        var custom = $.trim($('#editCustomText').val());
        var parsed = hostFromInput(custom);
        return parsed && parsed.host ? parsed.host : custom;
    }
    return $.trim($('#editExactText').text());
}

function apiPost(action, data, onOk, onErr) {
    data.csrf_token = CSRF;
    $.post('index.php?api=' + action, data, null, 'json')
        .done(function (res) {
            if (res && res.success) { onOk(res); }
            else {
                var msg = (res && res.error) || 'Request failed.';
                if (onErr) { onErr(msg); } else { notify(msg, 'danger'); }
            }
        })
        .fail(function (xhr) {
            var msg = xhr.status === 403 ? 'Administrator access required.' : 'Request failed.';
            /* A caller that supplies onErr is responsible for reporting the
               failure itself, and often for undoing an optimistic UI change. */
            if (onErr) { onErr(msg); } else { notify(msg, 'danger'); }
        });
}

function listApi(action) {
    return (PAGE === 'games' ? 'games' : 'whitelist') + '_' + action;
}

function listNoun() {
    return PAGE === 'games' ? 'the games list' : 'the whitelist';
}

function saveEntry() {
    var name = chosenEditName();
    if (!name) { $('#editError').text('Please enter a domain name.').show(); return; }
    if (looksLikeUrl(name)) {
        $('#editError').text('Enter a domain, not a full URL.').show();
        return;
    }
    apiPost(listApi('save'), { original: editOriginal, name: name }, function (res) {
        $('#editModal').modal('hide');
        notify('Saved ' + res.name + (res.note ? ' \u2014 ' + res.note : ''), 'success');
        grid.bootgrid('reload');
    }, function (err) {
        /* Keep the dialog open so the rejected name can be corrected. */
        $('#editError').text(err).show();
    });
}

/* Bootstrap-styled replacement for window.confirm().
   cb receives true when confirmed, false when dismissed. */
var confirmCb = null;

function confirmDialog(opts, cb) {
    confirmCb = cb;
    $('#confirmTitle').text(opts.title || 'Confirm');
    $('#confirmBody').text(opts.body || 'Are you sure?');
    $('#confirmOk')
        .text(opts.okText || 'OK')
        .removeClass('btn-primary btn-danger')
        .addClass(opts.danger ? 'btn-danger' : 'btn-primary');
    $('#confirmModal').modal('show');
}

$(function () {
    $('#confirmOk').on('click', function () {
        var cb = confirmCb;
        confirmCb = null;
        $('#confirmModal').one('hidden.bs.modal', function () {
            if (cb) cb(true);
        }).modal('hide');
    });

    /* Fires for Cancel, the × button, Esc and backdrop clicks. */
    $('#confirmModal').on('hidden.bs.modal', function () {
        var cb = confirmCb;
        confirmCb = null;
        if (cb) cb(false);
    });

    $('#confirmModal').on('shown.bs.modal', function () {
        $('#confirmOk').focus();
    });

    /* Focus the field once the modal has finished animating in, so Enter
       lands on the input rather than the document. */
    $('#editModal').on('shown.bs.modal', function () {
        $('#editName').focus();
    });

    /* Enter = Save. Esc = Cancel is already handled by Bootstrap's own
       keyboard dismissal, which fires the same hidden.bs.modal path. */
    $('#editName').on('input', function () {
        if (!editOriginal) refreshEditScope();
    });
    $('#editName').on('keydown', function (e) {
        if (e.which === 13) {
            e.preventDefault();
            saveEntry();
        }
    });
    $('input[name="editScope"]').on('change', function () {
        var custom = $('input[name="editScope"]:checked').val() === 'custom';
        $('#editCustomText').prop('disabled', !custom);
        if (custom) $('#editCustomText').focus().select();
    });
    $('#editCustomText').on('keydown', function (e) {
        if (e.which === 13) {
            e.preventDefault();
            saveEntry();
        }
    });
});

/* Shared by the editor's Remove link and the grid's trash button. onCancel lets
   the editor reopen itself when the user backs out; the grid has nothing to
   restore and passes nothing. */
function removeDomain(name, onCancel) {
    confirmDialog({
        title: 'Remove domain',
        body: 'Remove "' + name + '" from ' + listNoun() + '?',
        okText: 'Remove',
        danger: true
    }, function (ok) {
        if (!ok) { if (onCancel) onCancel(); return; }
        apiPost(listApi('delete'), { name: name }, function (res) {
            notify('Removed ' + res.name + (res.note ? ' \u2014 ' + res.note : ''),
                   res.note ? 'danger' : 'success');
            grid.bootgrid('reload');
        });
    });
}

function moveDomain(name) {
    var toGames = PAGE === 'whitelist';
    confirmDialog({
        title: toGames ? 'Move to Games' : 'Move to Whitelist',
        body: 'Move "' + name + '" to ' + (toGames ? 'the games list' : 'the whitelist') + '?',
        okText: 'Move'
    }, function (ok) {
        if (!ok) return;
        apiPost(listApi('move'), { name: name }, function (res) {
            notify('Moved ' + res.name + (res.note ? ' \u2014 ' + res.note : ''),
                   res.note ? 'info' : 'success');
            grid.bootgrid('reload');
        });
    });
}

function deleteEntry() {
    if (!editOriginal) return;
    var name = editOriginal;
    /* Bootstrap 3 cannot stack modals cleanly, so close the editor,
       ask for confirmation, and reopen the editor if the user backs out. */
    $('#editModal').one('hidden.bs.modal', function () {
        removeDomain(name, function () { openEdit(name); });
    }).modal('hide');
}

/* Domain detail dialog. Cancel is the default action, and Bootstrap's own
   keyboard handling makes Escape dismiss without acting. */
var detailTarget = null;

/* Suffixes under which registrations happen, so the "base domain" of
   "a.b.example.co.uk" is "example.co.uk" rather than the shared "co.uk".
   Deliberately a short list of the common cases plus the dynamic-DNS provider
   in use here; the custom field is the escape hatch for anything else. */
var MULTI_PART_SUFFIXES = [
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'co.in', 'co.il',
    'co.jp', 'ne.jp', 'or.jp', 'co.kr', 'com.br', 'com.cn', 'com.mx',
    'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'sytes.net'
];

function baseDomain(name) {
    var parts = String(name || '').toLowerCase().split('.').filter(function (p) {
        return p.length > 0;
    });
    if (parts.length <= 2) return parts.join('.');
    var lastTwo = parts.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.indexOf(lastTwo) !== -1) {
        return parts.slice(-3).join('.');
    }
    return lastTwo;
}

function selectedScopeName(exact) {
    var scope = $('input[name="allowScope"]:checked').val();
    if (scope === 'base')   return $('#scopeBaseText').text();
    if (scope === 'custom') return $.trim($('#scopeCustomText').val());
    return exact;
}

function showAllowScope(row, verb) {
    $('.scope-verb').text(verb);
    var base = baseDomain(row.name);
    $('#scopeExactText').text(row.name);
    $('#scopeBaseText').text(base);
    $('#scopeCustomText').val(row.name).prop('disabled', true);
    /* With two labels the base is the name itself, so offering both would
       be two radios that do the same thing. */
    $('#scopeBaseRow').toggle(base !== '' && base !== row.name);
    $('input[name="allowScope"][value="exact"]').prop('checked', true);
    $('#detailScope').show();
}

function openDetail(row, dest) {
    if (!row || !row.name) return;
    dest = dest || 'whitelist';
    var $act   = $('#detailAction');
    var $note  = $('#detailNote');
    var $scope = $('#detailScope');

    $('#detailName').text(row.name);
    $note.hide().empty();
    $scope.hide();
    detailTarget = null;
    $('.scope-verb').text('Add');
    $('#detailTitle').text('Domain');

    if (dest === 'games') {
        if (row.local) {
            $('#detailTitle').text('Add to Games');
            $('#detailStatus').html('<i class="fa-solid fa-circle-check status-approved"></i>' +
                'Currently <strong>allowed</strong> as a local network name.');
            $note.html('Single-label names are always allowed and are not added to the games list.').show();
        } else if (row.on_games) {
            $('#detailTitle').text('Add to Games');
            var gvia = row.games_by && row.games_by !== row.name;
            $('#detailStatus').html('<i class="fa-solid fa-gamepad status-games"></i>' +
                'Already on the <strong>games list</strong>' +
                (gvia ? ' via <code>' + esc(row.games_by) + '</code>' : '') + '.');
        } else {
            $('#detailTitle').text('Add to Games');
            if (row.on_whitelist) {
                var wvia = row.covered_by && row.covered_by !== row.name;
                $('#detailStatus').html('<i class="fa-solid fa-circle-check status-approved"></i>' +
                    'Currently on the <strong>whitelist</strong>' +
                    (wvia ? ' via <code>' + esc(row.covered_by) + '</code>' : '') + '.');
                $note.html('This adds a games entry and leaves the whitelist row in place.').show();
            } else {
                $('#detailStatus').html('<i class="fa-solid fa-circle-minus status-unapproved"></i>' +
                    'Currently <strong>blocked</strong>.');
                $note.html('This adds the name to the games list only.').show();
            }
            showAllowScope(row, 'Add');
            detailTarget = { op: 'games', name: row.name };
            $act.text('Add to Games').removeClass('btn-danger').addClass('btn-success');
        }
    } else if (row.local) {
        /* Allowed as a class by the resolver, so there is no whitelist row to
           remove and the action button would have nothing to act on. */
        $('#detailTitle').text('Add to Whitelist');
        $('#detailStatus').html('<i class="fa-solid fa-circle-check status-approved"></i>' +
            'Currently <strong>allowed</strong> as a local network name.');
        $note.html('Single-label names are always allowed and have no whitelist ' +
                   'entry to remove.').show();
    } else if (row.on_whitelist) {
        $('#detailTitle').text('Remove from Whitelist');
        var via = row.covered_by && row.covered_by !== row.name;
        $('#detailStatus').html('<i class="fa-solid fa-circle-check status-approved"></i>' +
            'Currently <strong>allowed</strong>' +
            (via ? ' via <code>' + esc(row.covered_by) + '</code>' : '') + '.');
        /* Blocking has to remove whichever entry actually grants access, which
           for a subdomain match is the parent rather than this name. */
        detailTarget = { op: 'block', name: row.covered_by || row.name };
        $act.text('Block').removeClass('btn-success').addClass('btn-danger');
        var blockNote = '';
        if (via) {
            blockNote = 'Blocking removes <code>' + esc(row.covered_by) + '</code> from the ' +
                        'whitelist, which also blocks every other subdomain of it.';
        }
        if (row.on_games) {
            blockNote += (blockNote ? ' ' : '') + 'The games entry is left in place.';
        }
        if (blockNote) $note.html(blockNote).show();
    } else {
        $('#detailTitle').text('Add to Whitelist');
        if (row.on_games) {
            var viaGames = row.games_by && row.games_by !== row.name;
            $('#detailStatus').html('<i class="fa-solid fa-gamepad status-games"></i>' +
                'Currently on the <strong>games list</strong>' +
                (viaGames ? ' via <code>' + esc(row.games_by) + '</code>' : '') + '.');
            $note.html('Adding it to the whitelist leaves the games entry in place.').show();
        } else {
            $('#detailStatus').html('<i class="fa-solid fa-circle-minus status-unapproved"></i>' +
                'Currently <strong>blocked</strong>.');
        }
        showAllowScope(row, 'Add');
        detailTarget = { op: 'allow', name: row.name };
        $act.text('Add to Whitelist').removeClass('btn-danger').addClass('btn-success');
    }

    $act.toggle(!!detailTarget && IS_ADMIN);
    $('#detailModal').modal('show');
}

function applyDetailAction() {
    if (!detailTarget || !IS_ADMIN) return;
    var op   = detailTarget.op;
    var name = (op === 'allow' || op === 'games')
        ? selectedScopeName(detailTarget.name) : detailTarget.name;

    if (!name) {
        notify(op === 'games'
            ? 'Enter a domain to add to the games list.'
            : 'Enter a domain to add to the whitelist.', 'danger');
        return;
    }

    detailTarget = null;
    $('#detailModal').modal('hide');

    if (op === 'allow') {
        apiPost('history_approve', { name: name }, function (res) {
            notify('Added ' + res.name + ' to the whitelist' + (res.note ? ' \u2014 ' + res.note : ''), 'success');
            grid.bootgrid('reload');
        });
    } else if (op === 'games') {
        apiPost('history_games', { name: name }, function (res) {
            notify('Added ' + res.name + ' to games' + (res.note ? ' \u2014 ' + res.note : ''), 'success');
            grid.bootgrid('reload');
        });
    } else {
        apiPost('whitelist_delete', { name: name }, function (res) {
            notify('Blocked ' + res.name + (res.note ? ' \u2014 ' + res.note : ''),
                   res.note ? 'danger' : 'success');
            grid.bootgrid('reload');
        });
    }
}

/* Copies to the clipboard. The Clipboard API needs a secure context, which the
   site has over HTTPS, but the execCommand path keeps this working if that ever
   fails or the browser withholds permission. */
function copyToClipboard(text) {
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () {
            notify('Copied ' + text, 'success');
        }, function () { legacyCopy(text); });
        return;
    }
    legacyCopy(text);
}

function legacyCopy(text) {
    var $tmp = $('<textarea>').val(text)
        .css({ position: 'fixed', top: '-1000px', opacity: 0 })
        .appendTo('body');
    $tmp[0].select();
    var ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    $tmp.remove();
    notify(ok ? 'Copied ' + text : 'Could not copy to clipboard', ok ? 'success' : 'danger');
}
</script>
</body>
</html>
