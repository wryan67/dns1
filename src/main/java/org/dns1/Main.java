package org.dns1;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.*;
import org.xbill.DNS.Record;
import sun.misc.Signal;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicLong;

/******************************************************************************
 * DnsServiceApp Main Class
 ******************************************************************************/
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final int DNS_PORT = 53;

    private static final String ACTION_INSERT = "insert";
    private static final String ACTION_DELETE = "delete";

    /* A 512 byte buffer silently truncates EDNS0/DNSSEC queries, which then
     * fail to parse and are dropped without a reply. */
    private static final int UDP_RECEIVE_BUFFER_BYTES = 4096;

    /* Largest response we put on the wire for a client that did not advertise
     * EDNS0. Anything bigger gets the TC flag so the client retries on TCP. */
    private static final int PLAIN_UDP_RESPONSE_LIMIT = 512;

    /* Upper bound on what we honour from a client's EDNS0 advertisement,
     * to stay clear of IP fragmentation. */
    private static final int EDNS_UDP_RESPONSE_LIMIT = 4096;

    private static final int TCP_MESSAGE_LIMIT = 65535;
    private static final int TCP_BACKLOG = 128;
    private static final int TCP_IDLE_TIMEOUT_MS = 10000;

    private static final long DEFAULT_TTL_SECONDS = 60L;
    private static final Duration UPSTREAM_TIMEOUT = Duration.ofSeconds(5);

    /* The DNS cache is filled from untrusted input, so it must be bounded. */
    private static final int MAX_CACHE_ENTRIES = 10000;
    private static final long CACHE_SWEEP_INTERVAL_SECONDS = 30L;
    private static final int MAX_PENDING_DB_TASKS = 10000;

    /* Allowed queries are the hot path, so their hits are counted in memory and
     * written in one batched transaction on this interval. Writing per query
     * would put a SQLite round trip in front of every resolution. */
    private static final long ALLOWED_FLUSH_INTERVAL_SECONDS = 5L;

    /* History rows untouched for this long are discarded by the daily purge, so
     * the table does not grow without bound from one-off lookups. */
    private static final int HISTORY_RETENTION_MONTHS = 6;
    private static final LocalTime HISTORY_PURGE_TIME = LocalTime.of(5, 0);

    /* Guards against the scheduler waking marginally before the target instant.
     * Any value under a second is enough; the purge boundary is a month scale. */
    private static final long SCHEDULE_MARGIN_MILLIS = 500L;

    /* Control socket. Bound to loopback only, so it is reachable from processes
     * sharing this network namespace (the web UI's PHP, in the same container)
     * and from nowhere else. There is no authentication: anything able to
     * connect can already write the database directly, so the socket grants no
     * privilege that a local process did not already have. */
    private static final int CONTROL_PORT = 22700;
    private static final int CONTROL_BACKLOG = 16;
    private static final int CONTROL_IDLE_TIMEOUT_MS = 30000;
    private static final int CONTROL_WORKER_THREADS = 4;

    /* Commands arrive from another process, so the line length has to be capped:
     * an unbounded readLine on a client that never sends a newline would grow
     * until the heap is exhausted. No legitimate command approaches this. */
    private static final int CONTROL_MAX_LINE_CHARS = 512;

    /* Fields are separated by a lower-case thorn. A pipe is accepted as an alias
     * purely so the socket can be driven by hand from nc or telnet without
     * having to type a thorn; neither character is legal in a domain name, so
     * allowing both cannot make a valid name ambiguous. */
    private static final String CONTROL_FIELD_SPLIT = "[\u00FE|]";
    private static final char CONTROL_FIELD_SEPARATOR = '\u00FE';

    /* DNS wire-format limits: 253 characters for a presentation-format name and
     * 63 for a single label. */
    private static final int MAX_DOMAIN_LENGTH = 253;
    private static final int MAX_LABEL_LENGTH = 63;

    /* Master switch and per-client blocks. Both are persisted, so a restart
     * cannot silently re-open a network the administrator had closed. */
    private static final String SETTING_GLOBAL_ENABLED = "global_enabled";
    private static final String SETTING_DEFAULT_MODE = "default_mode";
    private static final long CLIENT_FLUSH_INTERVAL_SECONDS = 5L;

    /* DHCP names change, so hostnames are refreshed rather than resolved once.
     * The cap keeps a large or spoofed client table from turning each pass into
     * thousands of upstream PTR queries. */
    private static final long HOSTNAME_REFRESH_INTERVAL_MINUTES = 10L;
    private static final int HOSTNAME_REFRESH_MAX_ROWS = 256;
    private static final int MAX_TRACKED_CLIENTS = 4096;
    private static final int MAX_IP_LENGTH = 45;

    /* The three policies a query can be judged under. They apply both to a
     * single client and, as the default, to every client that has no policy of
     * its own. */
    private static final String MODE_ALLOW_ALL = "allowall";
    private static final String MODE_FILTERED  = "filtered";
    private static final String MODE_BLOCKED   = "blocked";

    /* Not a policy: the wire token asking that a client's own policy be cleared
     * so it follows the default again. Stored as NULL in clients.mode. */
    private static final String MODE_INHERIT = "default";

    private static String dbPath = "dns_service.db";
    private static String secondaryDns = "192.168.22.22";

    /* Single-label names such as "elrond" cannot resolve on the public internet,
     * because ICANN prohibits dotless domains, so they are necessarily names of
     * the local network. That makes them safe to allow as a class, without an
     * entry per host and without having to prove anything about the address
     * they resolve to.
     *
     * On by default: blocking LAN hostnames breaks local name resolution and is
     * never the point of a content filter. --no-allow-local turns it off, in
     * which case a local name must be whitelisted like any other. Mirrored by
     * ALLOW_LOCAL_NAMES in the web UI's lib.php. */
    private static boolean allowLocalNames = true;

    private static final Set<String> whitelistCache = ConcurrentHashMap.newKeySet();
    private static final ConcurrentHashMap<String, CachedDnsResponse> dnsMemoryCache = new ConcurrentHashMap<>();

    /* Allowed-query hits awaiting their next batched flush to the history table. */
    private static final ConcurrentHashMap<String, AllowedHit> pendingAllowedHits = new ConcurrentHashMap<>();

    /******************************************************************************
     * AllowedHit
     *
     * A per-domain tally. The count is drained with getAndSet(0) rather than by
     * removing the entry, so hits recorded during a flush are carried into the
     * next one instead of being lost.
     ******************************************************************************/
    private static final class AllowedHit {
        private final AtomicLong count = new AtomicLong();
        private volatile String lastSeen;
    }

    /* The policy applied to any client that has none of its own. Changing it
     * moves every such client at once, which is what makes it useful as a
     * whole-network control: "block all" is a kill switch, "allowall" suspends
     * filtering, "filtered" is the normal running state. */
    private static final AtomicReference<String> defaultMode = new AtomicReference<>(MODE_FILTERED);

    /* Client addresses that carry a policy of their own, mirrored from
     * clients.mode. Absent means the row's mode is NULL: follow the default. */
    private static final ConcurrentHashMap<String, String> clientModes = new ConcurrentHashMap<>();

    /* Per-client activity awaiting its next batched flush to the clients table. */
    private static final ConcurrentHashMap<String, ClientHit> pendingClientHits = new ConcurrentHashMap<>();

    /******************************************************************************
     * ClientHit
     *
     * A per-address tally, drained the same way AllowedHit is so that hits
     * arriving during a flush are carried forward instead of being lost.
     ******************************************************************************/
    private static final class ClientHit {
        private final AtomicLong count = new AtomicLong();
        private volatile String lastSeen;
    }

    private static final AtomicLong droppedDbTasks = new AtomicLong();

    private static final ExecutorService requestWorkerPool = Executors.newFixedThreadPool(
            Math.max(4, Runtime.getRuntime().availableProcessors() * 2),
            namedThreadFactory("dns-worker")
    );

    private static final ThreadPoolExecutor dbExecutorPool = new ThreadPoolExecutor(
            2, 2, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(MAX_PENDING_DB_TASKS),
            namedThreadFactory("dns-db"),
            new ThreadPoolExecutor.AbortPolicy()
    );

    private static final ScheduledExecutorService cacheMaintenancePool =
            Executors.newSingleThreadScheduledExecutor(namedThreadFactory("dns-cache-sweeper"));

    /* Kept off the cache-sweeper thread so a slow purge cannot delay the 30s
     * cache sweep or the 5s allowed-hit flush. */
    private static final ScheduledExecutorService historyRetentionPool =
            Executors.newSingleThreadScheduledExecutor(namedThreadFactory("dns-history-retention"));

    /* Control connections are brief and rare, so a small fixed pool is enough
     * and also caps how many a misbehaving client can tie up at once. */
    private static final ExecutorService controlWorkerPool = Executors.newFixedThreadPool(
            CONTROL_WORKER_THREADS, namedThreadFactory("dns-control"));


    private static Resolver upstreamResolver;

    /******************************************************************************
     * CachedDnsResponse Class
     ******************************************************************************/
    private static class CachedDnsResponse {
        final byte[] rawResponseBytes;
        final long expiresAtEpochMs;

        /**************************************************************************
         * Constructor
         **************************************************************************/
        CachedDnsResponse(byte[] rawResponseBytes, long ttlSeconds) {
            this.rawResponseBytes = rawResponseBytes;
            this.expiresAtEpochMs = System.currentTimeMillis() + (ttlSeconds * 1000L);
        }

        /**************************************************************************
         * isExpired
         **************************************************************************/
        boolean isExpired() {
            return System.currentTimeMillis() > this.expiresAtEpochMs;
        }
    }

    /******************************************************************************
     * namedThreadFactory
     ******************************************************************************/
    private static ThreadFactory namedThreadFactory(String prefix) {
        AtomicLong counter = new AtomicLong();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + "-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    /******************************************************************************
     * main
     ******************************************************************************/
    public static void main(String[] args) {
        parseCliOptions(args);
        initDatabase();
        loadWhitelistCache();
        loadControlState();
        warnIfObsoleteActionQueue();
        installReloadSignalHandler();
        startControlListener();

        try {
            SimpleResolver resolver = new SimpleResolver(secondaryDns);
            resolver.setTimeout(UPSTREAM_TIMEOUT);
            upstreamResolver = resolver;
        } catch (UnknownHostException e) {
            log.error("CRITICAL: Failed to initialize secondary DNS resolver '{}': {}", secondaryDns, e.getMessage());
            System.exit(2);
        }

        cacheMaintenancePool.scheduleWithFixedDelay(
                Main::purgeExpiredCacheEntries,
                CACHE_SWEEP_INTERVAL_SECONDS,
                CACHE_SWEEP_INTERVAL_SECONDS,
                TimeUnit.SECONDS
        );

        cacheMaintenancePool.scheduleWithFixedDelay(
                Main::flushAllowedHits,
                ALLOWED_FLUSH_INTERVAL_SECONDS,
                ALLOWED_FLUSH_INTERVAL_SECONDS,
                TimeUnit.SECONDS
        );

        cacheMaintenancePool.scheduleWithFixedDelay(
                Main::flushClientHits,
                CLIENT_FLUSH_INTERVAL_SECONDS,
                CLIENT_FLUSH_INTERVAL_SECONDS,
                TimeUnit.SECONDS
        );

        /* Shares the retention thread rather than the cache-maintenance one, so
         * a slow round of upstream PTR queries cannot delay the 30s cache sweep
         * or the 5s counter flushes. */
        historyRetentionPool.scheduleWithFixedDelay(
                Main::refreshClientHostnames,
                1,
                HOSTNAME_REFRESH_INTERVAL_MINUTES,
                TimeUnit.MINUTES
        );

        scheduleHistoryPurge();

        installShutdownHook();

        log.info("Starting DNS service: db={}, secondary={}, port={}, allowLocal={}",
                 dbPath, secondaryDns, DNS_PORT, allowLocalNames);
        startTcpListener();
        startDnsListener();
    }

    /******************************************************************************
     * scheduleHistoryPurge
     *
     * Queues the next purge for the coming 05:00 local time and re-arms itself
     * afterwards.
     *
     * A fixed 24-hour period would drift off 05:00 at every daylight-saving
     * change, because the day it crosses is 23 or 25 hours long. Recomputing the
     * delay from the calendar after each run keeps it on the wall clock instead.
     ******************************************************************************/
    private static void scheduleHistoryPurge() {
        ZonedDateTime now  = ZonedDateTime.now();
        ZonedDateTime next = now.with(HISTORY_PURGE_TIME);
        if (!next.isAfter(now)) {
            next = next.plusDays(1);
        }

        /* Re-resolving the time against the new date normalizes 05:00 on a day
         * where a DST jump means it does not exist or occurs twice. */
        next = next.toLocalDate().atTime(HISTORY_PURGE_TIME).atZone(now.getZone());

        /* Millisecond precision plus a margin, so the task never wakes a hair
         * before the target instant. Truncating to whole seconds fires early,
         * and the early wake still sees 05:00 as upcoming, which reschedules for
         * the same day and runs the purge a second time. */
        long delayMillis = Math.max(1000L,
                Duration.between(now, next).toMillis() + SCHEDULE_MARGIN_MILLIS);
        log.info("Next history purge scheduled for {} ({} hours from now)",
                 next, String.format(Locale.ROOT, "%.1f", delayMillis / 3600000.0));

        historyRetentionPool.schedule(() -> {
            try {
                purgeOldHistory();
            } catch (Exception e) {
                /* A failed purge must not cancel the schedule, which is what an
                 * escaping exception would do to a repeating task. */
                log.warn("History purge failed: {}", e.getMessage());
            } finally {
                scheduleHistoryPurge();
            }
        }, delayMillis, TimeUnit.MILLISECONDS);
    }

    /******************************************************************************
     * purgeOldHistory
     *
     * Deletes history rows whose most recent activity of any kind predates the
     * retention window.
     *
     * The cutoff is taken across both timestamps rather than last_seen alone. A
     * row carries a denied and an allowed timestamp independently, and either
     * may be NULL, so a domain that was denied once long ago but is allowed
     * daily still has an ancient last_seen. Judging that row on last_seen would
     * delete an actively used entry along with its accumulated counts.
     ******************************************************************************/
    private static void purgeOldHistory() {
        String cutoff = DateTimeFormatter.ISO_INSTANT.format(
                ZonedDateTime.now().minusMonths(HISTORY_RETENTION_MONTHS).toInstant());

        /* Timestamps are written as UTC ISO-8601, which orders correctly as
         * text, so the comparison needs no date parsing. Rows with neither
         * timestamp set are left alone: there is no evidence of their age. */
        String purgeSql = "DELETE FROM history " +
                "WHERE (last_seen IS NOT NULL OR allowed_last_seen IS NOT NULL) " +
                "AND MAX(COALESCE(last_seen, ''), COALESCE(allowed_last_seen, '')) < ?;";

        try (Connection conn = getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(purgeSql)) {
            stmt.setString(1, cutoff);
            int removed = stmt.executeUpdate();
            if (removed > 0) {
                log.info("History purge removed {} row(s) with no activity since {}", removed, cutoff);
            } else {
                log.info("History purge found no rows older than {}", cutoff);
            }
        } catch (SQLException e) {
            log.warn("History purge failed: {}", e.getMessage());
        }
    }

    /******************************************************************************
     * installShutdownHook
     ******************************************************************************/
    private static void installShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutting down; draining pending database writes");
            flushAllowedHits();
            flushClientHits();
            dbExecutorPool.shutdown();
            try {
                if (!dbExecutorPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    dbExecutorPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                dbExecutorPool.shutdownNow();
            }
            long dropped = droppedDbTasks.get();
            if (dropped > 0) {
                log.warn("Dropped {} denied-request log task(s) due to backlog", dropped);
            }
        }, "dns-shutdown"));
    }

    /******************************************************************************
     * parseCliOptions
     ******************************************************************************/
    private static void parseCliOptions(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if ("--db".equals(args[i]) && i + 1 < args.length) {
                dbPath = args[++i];
            } else if ("--2dns".equals(args[i]) && i + 1 < args.length) {
                secondaryDns = args[++i];
            } else if ("--allow-local".equals(args[i])) {
                allowLocalNames = true;
            } else if ("--no-allow-local".equals(args[i])) {
                allowLocalNames = false;
            }
        }
    }

    /******************************************************************************
     * installReloadSignalHandler
     *
     * SIGHUP is the long-standing convention for asking a daemon to re-read its
     * configuration, so it reloads the whitelist cache from the table. The
     * control socket's "whitelist reload" does the same work; this stays as the
     * out-of-band path for when the socket cannot be reached.
     *
     * Handling SIGHUP also overrides its default action, which is to terminate
     * the process.
     ******************************************************************************/
    private static void installReloadSignalHandler() {
        try {
            Signal.handle(new Signal("HUP"), sig -> {
                /* A signal handler must return promptly and cannot safely do
                 * database I/O, so the reload is handed to a worker. */
                controlWorkerPool.execute(() -> {
                    try {
                        int size = reloadWhitelistCache();
                        log.info("SIGHUP: whitelist cache reloaded, now {} entr(ies)", size);
                    } catch (SQLException e) {
                        log.error("SIGHUP: whitelist reload failed: {}", e.getMessage());
                    }
                });
            });
            log.info("Send SIGHUP to pid {} to reload the whitelist cache", ProcessHandle.current().pid());
        } catch (IllegalArgumentException | UnsupportedOperationException e) {
            log.error("Could not install SIGHUP handler; use the control socket to reload: {}", e.toString());
        }
    }

    /******************************************************************************
     * startControlListener
     *
     * Accepts plain-text commands on the loopback interface. The web UI writes
     * the whitelist table itself and then sends the matching command here, so
     * the daemon's in-memory cache changes at the same moment rather than after
     * a polling delay.
     *
     * Binding to the loopback address specifically, rather than to every
     * interface, is what keeps the port off the network: an unauthenticated
     * command channel reachable from the LAN would let any client edit the
     * whitelist.
     ******************************************************************************/
    private static void startControlListener() {
        Thread listener = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(
                    CONTROL_PORT, CONTROL_BACKLOG, InetAddress.getLoopbackAddress())) {

                log.info("Control socket listening on {}:{}",
                         serverSocket.getInetAddress().getHostAddress(), CONTROL_PORT);

                while (true) {
                    Socket client = serverSocket.accept();
                    try {
                        controlWorkerPool.execute(() -> handleControlConnection(client));
                    } catch (RejectedExecutionException e) {
                        /* Every worker is busy. Closing immediately is better
                         * than queueing without bound; the caller sees the
                         * connection drop and can retry. */
                        log.warn("Control socket busy; rejected a connection");
                        closeQuietly(client);
                    }
                }
            } catch (IOException e) {
                /* The DNS service itself is unaffected, so this is not fatal;
                 * the cache then syncs only on SIGHUP or restart. */
                log.error("Control socket failed on port {}: {}. Whitelist changes will not " +
                          "reach the cache until a reload or restart.", CONTROL_PORT, e.getMessage());
            }
        }, "control-listener");
        listener.setDaemon(true);
        listener.start();
    }

    /******************************************************************************
     * handleControlConnection
     *
     * Reads commands until the client disconnects, so one connection can carry a
     * batch. A read timeout applies to each line, which stops an idle or wedged
     * client from holding a worker thread indefinitely.
     ******************************************************************************/
    private static void handleControlConnection(Socket client) {
        try (Socket socket = client) {
            socket.setSoTimeout(CONTROL_IDLE_TIMEOUT_MS);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

            String line;
            while ((line = readBoundedLine(reader)) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                String response = executeControlCommand(line);
                writer.write(response);
                writer.write("\n");
                writer.flush();
            }
        } catch (SocketTimeoutException e) {
            log.debug("Control connection idle past {} ms; closing", CONTROL_IDLE_TIMEOUT_MS);
        } catch (IOException e) {
            log.debug("Control connection ended: {}", e.getMessage());
        }
    }

    /******************************************************************************
     * readBoundedLine
     *
     * BufferedReader.readLine has no length limit, so a client that never sends
     * a newline would grow the buffer until the heap is gone. This reads a
     * character at a time and gives up once the cap is passed.
     *
     * Returns null at end of stream, and throws when the cap is exceeded, since
     * the rest of that line cannot be trusted to be a command boundary.
     ******************************************************************************/
    private static String readBoundedLine(BufferedReader reader) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = reader.read()) != -1) {
            if (c == '\n') {
                /* Tolerates CRLF from clients such as telnet. */
                int end = sb.length();
                while (end > 0 && sb.charAt(end - 1) == '\r') {
                    end--;
                }
                return sb.substring(0, end);
            }
            if (sb.length() >= CONTROL_MAX_LINE_CHARS) {
                throw new IOException("Command exceeded " + CONTROL_MAX_LINE_CHARS + " characters");
            }
            sb.append((char) c);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    /******************************************************************************
     * executeControlCommand
     *
     * Field 1 is the command and the rest are its arguments. Replies are in the
     * same shape: "ok", "ok<sep>detail", or "error<sep>reason".
     *
     * Every reply is a single line, so a caller can read exactly one line per
     * command it sent without needing to know the command.
     ******************************************************************************/
    private static String executeControlCommand(String line) {
        String[] fields = line.trim().split(CONTROL_FIELD_SPLIT, -1);
        for (int i = 0; i < fields.length; i++) {
            fields[i] = fields[i].trim();
        }

        String command = fields[0].toLowerCase(Locale.ROOT);
        String subcommand = fields.length > 1 ? fields[1].toLowerCase(Locale.ROOT) : "";

        switch (command) {
            case "ping":
                return "ok" + CONTROL_FIELD_SEPARATOR + "pong";

            case "whitelist":
                return executeWhitelistCommand(subcommand, fields);

            case "stats":
                return "ok" + CONTROL_FIELD_SEPARATOR + "whitelist=" + whitelistCache.size()
                        + CONTROL_FIELD_SEPARATOR + "dnscache=" + dnsMemoryCache.size()
                        + CONTROL_FIELD_SEPARATOR + "allowlocal=" + allowLocalNames
                        + CONTROL_FIELD_SEPARATOR + "default=" + defaultMode.get()
                        + CONTROL_FIELD_SEPARATOR + "clientpolicies=" + clientModes.size();

            case "client":
                return executeClientCommand(subcommand, fields);

            case "default":
                return executeDefaultCommand(subcommand, fields);

            case "status":
                return "ok" + CONTROL_FIELD_SEPARATOR + defaultMode.get();

            case "enable":
                return executeSwitchCommand(subcommand, fields, true);

            case "disable":
                return executeSwitchCommand(subcommand, fields, false);

            default:
                /* The command is echoed back so a caller can tell a typo from a
                 * version mismatch, but it is capped: it is untrusted input and
                 * the reply must stay a single bounded line. */
                return controlError("unknown command '" + abbreviate(command) + "'");
        }
    }

    /******************************************************************************
     * executeWhitelistCommand
     ******************************************************************************/
    private static String executeWhitelistCommand(String subcommand, String[] fields) {
        if ("reload".equals(subcommand)) {
            try {
                int size = reloadWhitelistCache();
                return "ok" + CONTROL_FIELD_SEPARATOR + size;
            } catch (SQLException e) {
                return controlError("reload failed: " + e.getMessage());
            }
        }

        boolean isAdd = "add".equals(subcommand);
        if (!isAdd && !"remove".equals(subcommand)) {
            return controlError("whitelist takes 'add', 'remove' or 'reload', got '"
                    + abbreviate(subcommand) + "'");
        }
        if (fields.length < 3) {
            return controlError("whitelist " + subcommand + " requires a domain");
        }

        /* Normalized here rather than trusting the caller, so the cache key
         * matches what the resolver looks up regardless of how the name was
         * typed. Same validation the table load applies, so the socket cannot
         * introduce an entry that a reload would then reject. */
        String domain = normalizeDomain(fields[2]);
        if (!isValidWhitelistEntry(domain)) {
            return controlError("invalid domain '" + abbreviate(fields[2])
                    + "': must be a dotted name of letters, digits, hyphen or underscore"
                    + " (e.g. example.com)");
        }

        boolean changed = isAdd ? whitelistCache.add(domain) : whitelistCache.remove(domain);

        /* "already present" and "added" are both success: the caller asked for a
         * state, and that state now holds. Reporting the distinction is still
         * useful when tracing a UI and daemon that disagree. */
        log.info("Control: whitelist {} '{}' ({}); cache now holds {} entr(ies)",
                 subcommand, domain, changed ? "changed" : "no change", whitelistCache.size());

        return "ok" + CONTROL_FIELD_SEPARATOR + (changed ? "changed" : "unchanged")
                + CONTROL_FIELD_SEPARATOR + whitelistCache.size();
    }

    /******************************************************************************
     * executeSwitchCommand
     *
     * The on/off switch became the three-way default policy, so neither verb has
     * an unambiguous meaning any more and both are refused with a pointer to the
     * command that replaced them.
     ******************************************************************************/
    private static String executeSwitchCommand(String subcommand, String[] fields, boolean enable) {
        String verb = enable ? "enable" : "disable";

        if ("global".equals(subcommand)) {
            return controlError(verb + " global is no longer supported; use "
                    + "default" + CONTROL_FIELD_SEPARATOR + "set" + CONTROL_FIELD_SEPARATOR
                    + "<allowall|filtered|blocked>");
        }

        if ("ip".equals(subcommand)) {
            return controlError(verb + " ip is no longer supported; use "
                    + "client" + CONTROL_FIELD_SEPARATOR + "set" + CONTROL_FIELD_SEPARATOR
                    + "<ip>" + CONTROL_FIELD_SEPARATOR + "<allowall|filtered|blocked|default>");
        }

        return controlError(verb + " is no longer supported; use 'default|set' or 'client|set'");
    }

    /******************************************************************************
     * executeDefaultCommand
     *
     * Backs "default|set|<allowall|filtered|blocked>".
     *
     * The table is written before the in-memory state so that a failed write
     * leaves the two agreeing rather than running in a state that would vanish
     * at the next restart.
     ******************************************************************************/
    private static String executeDefaultCommand(String subcommand, String[] fields) {
        if (!"set".equals(subcommand)) {
            return controlError("default takes 'set', got '" + abbreviate(subcommand) + "'");
        }
        if (fields.length < 3) {
            return controlError("default set requires a policy");
        }

        String mode = normalizeMode(fields[2]);
        if (mode == null) {
            return controlError("invalid policy '" + abbreviate(fields[2])
                    + "': expected allowall, filtered or blocked");
        }

        try {
            persistSetting(SETTING_DEFAULT_MODE, mode);
        } catch (SQLException e) {
            return controlError("could not persist the default policy: " + e.getMessage());
        }

        boolean changed = !mode.equals(defaultMode.getAndSet(mode));
        log.warn("Control: default policy set to {}", mode);
        return "ok" + CONTROL_FIELD_SEPARATOR + mode
                + CONTROL_FIELD_SEPARATOR + (changed ? "changed" : "unchanged");
    }

    /******************************************************************************
     * executeClientCommand
     *
     * Backs "client|set|<ip>|<allowall|filtered|blocked|default>".
     *
     * "default" is not a policy but a request to clear this client's own, so it
     * stores NULL and drops the map entry, leaving the client to follow whatever
     * the default is now and whatever it becomes later.
     ******************************************************************************/
    private static String executeClientCommand(String subcommand, String[] fields) {
        if (!"set".equals(subcommand)) {
            return controlError("client takes 'set', got '" + abbreviate(subcommand) + "'");
        }
        if (fields.length < 4) {
            return controlError("client set requires an address and a policy");
        }

        String ip = normalizeIp(fields[2]);
        if (ip == null) {
            return controlError("invalid IP address '" + abbreviate(fields[2]) + "'");
        }

        boolean inherit = MODE_INHERIT.equalsIgnoreCase(fields[3].trim());
        String mode = inherit ? null : normalizeMode(fields[3]);
        if (mode == null && !inherit) {
            return controlError("invalid policy '" + abbreviate(fields[3])
                    + "': expected allowall, filtered, blocked or default");
        }

        try {
            persistClientMode(ip, mode);
        } catch (SQLException e) {
            return controlError("could not persist the client policy: " + e.getMessage());
        }

        String previous = inherit ? clientModes.remove(ip) : clientModes.put(ip, mode);
        boolean changed = !Objects.equals(mode, previous);

        log.warn("Control: client {} policy set to {}", ip, inherit ? "default (inherited)" : mode);
        return "ok" + CONTROL_FIELD_SEPARATOR + (inherit ? MODE_INHERIT : mode)
                + CONTROL_FIELD_SEPARATOR + (changed ? "changed" : "unchanged");
    }

    /******************************************************************************
     * controlError
     ******************************************************************************/
    private static String controlError(String reason) {
        return "error" + CONTROL_FIELD_SEPARATOR + reason.replace('\n', ' ').replace('\r', ' ');
    }

    /******************************************************************************
     * abbreviate
     *
     * Untrusted text is echoed in replies and log lines, so it is truncated and
     * stripped of the field separator and of anything that could forge a line
     * or field boundary in the reply.
     ******************************************************************************/
    private static String abbreviate(String value) {
        if (value == null) {
            return "";
        }
        String clean = value.replaceAll("[\\p{Cntrl}\u00FE|]", "");
        return clean.length() <= 40 ? clean : clean.substring(0, 40) + "...";
    }

    /******************************************************************************
     * closeQuietly
     ******************************************************************************/
    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            /* Already failing; nothing useful to do. */
        }
    }

    /******************************************************************************
     * warnIfObsoleteActionQueue
     *
     * The whitelist_actions table was the previous synchronisation channel and
     * is no longer read. Rows left in it are already reflected in the whitelist
     * table, because the web UI wrote both in one transaction and the cache load
     * above reads that table in full, so they are cleared rather than applied.
     ******************************************************************************/
    private static void warnIfObsoleteActionQueue() {
        String existsSql = "SELECT name FROM sqlite_master WHERE type='table' AND name='whitelist_actions';";
        try (Connection conn = getDbConnection();
             Statement stmt = conn.createStatement()) {

            try (ResultSet rs = stmt.executeQuery(existsSql)) {
                if (!rs.next()) {
                    return;
                }
            }

            int leftover;
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM whitelist_actions;")) {
                leftover = rs.next() ? rs.getInt(1) : 0;
            }

            if (leftover > 0) {
                stmt.executeUpdate("DELETE FROM whitelist_actions;");
                log.warn("Cleared {} row(s) from the obsolete whitelist_actions queue; its changes " +
                         "were already present in the whitelist table. Synchronisation now uses the " +
                         "control socket on port {}.", leftover, CONTROL_PORT);
            }
        } catch (SQLException e) {
            /* Purely cosmetic cleanup, so a failure must not stop startup. */
            log.debug("Could not inspect whitelist_actions: {}", e.getMessage());
        }
    }




    private static Connection getDbConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
    }

    /******************************************************************************
     * initDatabase
     ******************************************************************************/
    private static void initDatabase() {
        String createWhitelistSql = "CREATE TABLE IF NOT EXISTS whitelist (" +
                "name TEXT PRIMARY KEY, " +
                "date_approved DATETIME" +
                ");";

        String createDeniedSql = "CREATE TABLE IF NOT EXISTS history (" +
                "name TEXT PRIMARY KEY, " +
                "count INTEGER, " +
                "last_seen DATETIME, " +
                "allowed_count INTEGER NOT NULL DEFAULT 0, " +
                "allowed_last_seen DATETIME" +
                ");";

        /* Daemon-owned operational state. Unlike the whitelist, which the web UI
         * writes so it keeps working while the daemon is down, these are written
         * here: they describe the resolver's own runtime, and toggling them
         * means nothing when the resolver is not running. */
        String createSettingsSql = "CREATE TABLE IF NOT EXISTS settings (" +
                "key TEXT PRIMARY KEY, " +
                "value TEXT" +
                ");";

        /* mode is deliberately nullable: NULL means this client has no policy of
         * its own and follows the default. Auto-created rows start that way, so
         * a device appearing on the network inherits rather than being pinned. */
        String createClientsSql = "CREATE TABLE IF NOT EXISTS clients (" +
                "ip TEXT PRIMARY KEY, " +
                "hostname TEXT, " +
                "mode TEXT, " +
                "query_count INTEGER NOT NULL DEFAULT 0, " +
                "first_seen DATETIME, " +
                "last_seen DATETIME" +
                ");";

        try (Connection conn = getDbConnection();
             Statement stmt = conn.createStatement()) {
            stmt.execute(createWhitelistSql);
            stmt.execute(createDeniedSql);
            stmt.execute(createSettingsSql);
            stmt.execute(createClientsSql);

            /* Databases created before allowed-query tracking existed still have
             * the two-counter schema, so add the columns in place. */
            addColumnIfMissing(conn, "history", "allowed_count", "INTEGER NOT NULL DEFAULT 0");
            addColumnIfMissing(conn, "history", "allowed_last_seen", "DATETIME");

            /* Entries approved before this column existed keep a NULL here,
             * which is the honest answer: the date was never recorded. The
             * daemon only reads the whitelist, so the web UI writes this. */
            addColumnIfMissing(conn, "whitelist", "date_approved", "DATETIME");

            migrateClientEnabledToMode(conn);
            migrateClientModeNullable(conn);
            migrateGlobalEnabledToDefaultMode(conn);
        } catch (SQLException e) {
            log.error("CRITICAL: Database initialization failed for '{}': {}", dbPath, e.getMessage());
            System.exit(2);
        }
    }

    /******************************************************************************
     * migrateClientEnabledToMode
     *
     * The per-client switch started as a boolean and became a three-way policy.
     * The old column is carried across and then removed, so there is no second
     * column that still looks authoritative but is never read.
     ******************************************************************************/
    private static void migrateClientEnabledToMode(Connection conn) throws SQLException {
        if (!hasColumn(conn, "clients", "enabled")) {
            return;
        }
        addColumnIfMissing(conn, "clients", "mode",
                           "TEXT NOT NULL DEFAULT '" + MODE_FILTERED + "'");

        try (Statement stmt = conn.createStatement()) {
            int moved = stmt.executeUpdate(
                    "UPDATE clients SET mode = '" + MODE_BLOCKED + "' WHERE enabled = 0;");
            stmt.execute("ALTER TABLE clients DROP COLUMN enabled;");
            log.info("Migrated clients.enabled to clients.mode ({} blocked client(s) carried over)", moved);
        }
    }

    /******************************************************************************
     * migrateClientModeNullable
     *
     * clients.mode began as NOT NULL DEFAULT 'filtered', when "filtered" was the
     * hardcoded default and a row could not say "whatever the default is". Now
     * that the default is configurable, that distinction matters, so the column
     * is rebuilt as nullable.
     *
     * Rows reading 'filtered' become NULL. Nothing is lost: while the column was
     * NOT NULL there was no way to record an explicit choice of "filtered" as
     * distinct from the seeded value, and the default is 'filtered' on the first
     * run after this migration, so behaviour is unchanged either way. Rows that
     * were deliberately set to allowall or blocked keep their policy.
     *
     * SQLite cannot drop a NOT NULL constraint in place, so the table is rebuilt.
     ******************************************************************************/
    private static void migrateClientModeNullable(Connection conn) throws SQLException {
        if (!isColumnNotNull(conn, "clients", "mode")) {
            return;
        }

        boolean autoCommit = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE clients_migrate (" +
                    "ip TEXT PRIMARY KEY, " +
                    "hostname TEXT, " +
                    "mode TEXT, " +
                    "query_count INTEGER NOT NULL DEFAULT 0, " +
                    "first_seen DATETIME, " +
                    "last_seen DATETIME" +
                    ");");
            int inherited = stmt.executeUpdate(
                    "INSERT INTO clients_migrate (ip, hostname, mode, query_count, first_seen, last_seen) " +
                    "SELECT ip, hostname, NULLIF(mode, '" + MODE_FILTERED + "'), " +
                    "query_count, first_seen, last_seen FROM clients;");
            stmt.execute("DROP TABLE clients;");
            stmt.execute("ALTER TABLE clients_migrate RENAME TO clients;");
            conn.commit();
            log.info("Rebuilt clients.mode as nullable; {} row(s) carried over, "
                     + "'filtered' rows now follow the default", inherited);
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(autoCommit);
        }
    }

    /******************************************************************************
     * migrateGlobalEnabledToDefaultMode
     *
     * The master on/off switch became the three-way default policy. "Off" was a
     * kill switch that refused everything, which is exactly "blocked"; "on" was
     * ordinary whitelist filtering. The old row is removed so there is no second
     * setting that still looks authoritative but is never read.
     ******************************************************************************/
    private static void migrateGlobalEnabledToDefaultMode(Connection conn) throws SQLException {
        String legacy = null;
        try (PreparedStatement stmt =
                     conn.prepareStatement("SELECT value FROM settings WHERE key = ?;")) {
            stmt.setString(1, SETTING_GLOBAL_ENABLED);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    legacy = rs.getString(1);
                }
            }
        }
        if (legacy == null) {
            return;
        }

        String mode = "0".equals(legacy) ? MODE_BLOCKED : MODE_FILTERED;

        /* Only seeds the new setting; an explicit default already chosen wins. */
        try (PreparedStatement stmt = conn.prepareStatement(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING;")) {
            stmt.setString(1, SETTING_DEFAULT_MODE);
            stmt.setString(2, mode);
            stmt.executeUpdate();
        }
        try (PreparedStatement stmt =
                     conn.prepareStatement("DELETE FROM settings WHERE key = ?;")) {
            stmt.setString(1, SETTING_GLOBAL_ENABLED);
            stmt.executeUpdate();
        }
        log.info("Migrated settings.global_enabled ({}) to default policy '{}'", legacy, mode);
    }

    /******************************************************************************
     * hasColumn
     ******************************************************************************/
    private static boolean hasColumn(Connection conn, String table, String column) throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + table + ");")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /******************************************************************************
     * isColumnNotNull
     *
     * False when the column does not exist, so a caller can use this to decide
     * whether a rebuild is needed without first proving the column is there.
     ******************************************************************************/
    private static boolean isColumnNotNull(Connection conn, String table, String column)
            throws SQLException {
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + table + ");")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) {
                    return rs.getInt("notnull") != 0;
                }
            }
        }
        return false;
    }

    /******************************************************************************
     * normalizeMode
     *
     * Returns the canonical policy name, or null when the value is not one.
     ******************************************************************************/
    private static String normalizeMode(String value) {
        String candidate = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (MODE_ALLOW_ALL.equals(candidate) || MODE_FILTERED.equals(candidate)
                || MODE_BLOCKED.equals(candidate)) {
            return candidate;
        }
        return null;
    }

    /******************************************************************************
     * clientMode
     *
     * The policy this address is judged under: its own if it has one, otherwise
     * whatever the default currently is.
     ******************************************************************************/
    private static String clientMode(String ip) {
        String mode = clientModes.get(ip);
        return mode == null ? defaultMode.get() : mode;
    }

    /******************************************************************************
     * loadControlState
     *
     * Reads the default policy and the per-client policies into memory. Called at
     * startup so a restart resumes the state the administrator left set, rather
     * than defaulting to open.
     ******************************************************************************/
    private static void loadControlState() {
        try (Connection conn = getDbConnection()) {
            String mode = MODE_FILTERED;
            try (PreparedStatement stmt =
                         conn.prepareStatement("SELECT value FROM settings WHERE key = ?;")) {
                stmt.setString(1, SETTING_DEFAULT_MODE);
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        String stored = normalizeMode(rs.getString(1));
                        if (stored != null) {
                            mode = stored;
                        }
                    }
                }
            }
            defaultMode.set(mode);

            clientModes.clear();
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery(
                         "SELECT ip, mode FROM clients WHERE mode IS NOT NULL;")) {
                while (rs.next()) {
                    String clientPolicy = normalizeMode(rs.getString("mode"));
                    if (clientPolicy != null) {
                        clientModes.put(rs.getString("ip"), clientPolicy);
                    }
                }
            }

            log.info("Default policy is '{}'; {} client(s) carry a policy of their own",
                     mode, clientModes.size());
        } catch (SQLException e) {
            /* Left at 'filtered': refusing every query because a settings row
             * could not be read would be a worse failure. */
            log.error("Failed to load control state, defaulting to '{}': {}",
                      MODE_FILTERED, e.getMessage());
        }
    }

    /******************************************************************************
     * persistSetting
     ******************************************************************************/
    private static void persistSetting(String key, String value) throws SQLException {
        String sql = "INSERT INTO settings (key, value) VALUES (?, ?) " +
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
        try (Connection conn = getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, key);
            stmt.setString(2, value);
            stmt.executeUpdate();
        }
    }

    /******************************************************************************
     * persistClientMode
     *
     * Inserts the row when the address has never been seen, so a policy can be
     * set for a client before it has ever sent a query. A null mode clears the
     * client's own policy, leaving it to follow the default.
     ******************************************************************************/
    private static void persistClientMode(String ip, String mode) throws SQLException {
        String sql = "INSERT INTO clients (ip, hostname, mode, query_count, first_seen, last_seen) " +
                "VALUES (?, NULL, ?, 0, NULL, NULL) " +
                "ON CONFLICT(ip) DO UPDATE SET mode = excluded.mode;";
        try (Connection conn = getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, ip);
            if (mode == null) {
                stmt.setNull(2, Types.VARCHAR);
            } else {
                stmt.setString(2, mode);
            }
            stmt.executeUpdate();
        }
    }

    /******************************************************************************
     * recordClientHit
     *
     * Counts a query against its source address in memory. On the request path,
     * so it must not touch the database.
     *
     * The map is capped because the source address of a UDP query is unverified
     * and a spoofed flood would otherwise grow it without limit.
     ******************************************************************************/
    private static void recordClientHit(String ip) {
        ClientHit hit = pendingClientHits.get(ip);
        if (hit == null) {
            if (pendingClientHits.size() >= MAX_TRACKED_CLIENTS) {
                return;
            }
            hit = pendingClientHits.computeIfAbsent(ip, key -> new ClientHit());
        }
        hit.count.incrementAndGet();
        hit.lastSeen = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    }

    /******************************************************************************
     * flushClientHits
     *
     * Writes every pending tally in one transaction. The upsert deliberately
     * leaves "mode" and "first_seen" alone, so flushing activity can never
     * change a client's policy or move the date it was first seen.
     *
     * New rows are seeded with a NULL mode, meaning the client follows the
     * default policy: a device appearing on the network is judged by whatever
     * the default is at the time it queries, and keeps following the default if
     * that is later changed.
     ******************************************************************************/
    private static void flushClientHits() {
        if (pendingClientHits.isEmpty()) {
            return;
        }

        String sql = "INSERT INTO clients (ip, hostname, mode, query_count, first_seen, last_seen) " +
                "VALUES (?, NULL, NULL, ?, ?, ?) " +
                "ON CONFLICT(ip) DO UPDATE SET " +
                "query_count = clients.query_count + excluded.query_count, " +
                "last_seen = excluded.last_seen;";

        try (Connection conn = getDbConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                for (Map.Entry<String, ClientHit> entry : pendingClientHits.entrySet()) {
                    ClientHit hit = entry.getValue();
                    long delta = hit.count.getAndSet(0);
                    if (delta == 0) {
                        pendingClientHits.remove(entry.getKey(), hit);
                        continue;
                    }
                    stmt.setString(1, entry.getKey());
                    stmt.setLong(2, delta);
                    stmt.setString(3, hit.lastSeen);
                    stmt.setString(4, hit.lastSeen);
                    stmt.addBatch();
                }
                stmt.executeBatch();
            }
            conn.commit();
        } catch (SQLException e) {
            log.warn("Failed to flush client counters: {}", e.getMessage());
        }
    }

    /******************************************************************************
     * refreshClientHostnames
     *
     * Resolves client addresses to names with PTR queries against the secondary
     * DNS server, which on a home network is the router that issued the DHCP
     * leases and therefore knows the machine names.
     *
     * Runs off the request path on a timer. A name that fails to resolve leaves
     * the stored one untouched, so a device that is merely switched off keeps
     * its last known name instead of reverting to a bare address.
     ******************************************************************************/
    private static void refreshClientHostnames() {
        List<String> targets = new ArrayList<>();
        String selectSql = "SELECT ip FROM clients ORDER BY last_seen DESC LIMIT " + HOSTNAME_REFRESH_MAX_ROWS + ";";
        try (Connection conn = getDbConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSql)) {
            while (rs.next()) {
                targets.add(rs.getString(1));
            }
        } catch (SQLException e) {
            log.warn("Could not list clients for hostname refresh: {}", e.getMessage());
            return;
        }

        String updateSql = "UPDATE clients SET hostname = ? WHERE ip = ?;";
        int resolved = 0;
        try (Connection conn = getDbConnection();
             PreparedStatement stmt = conn.prepareStatement(updateSql)) {
            for (String ip : targets) {
                String hostname = reverseLookup(ip);
                if (hostname == null) {
                    continue;
                }
                stmt.setString(1, hostname);
                stmt.setString(2, ip);
                stmt.executeUpdate();
                resolved++;
            }
        } catch (SQLException e) {
            log.warn("Could not store resolved hostnames: {}", e.getMessage());
            return;
        }

        if (resolved > 0) {
            log.debug("Refreshed {} of {} client hostname(s)", resolved, targets.size());
        }
    }

    /******************************************************************************
     * reverseLookup
     *
     * The shared resolver cache is bypassed so a renamed or re-leased address is
     * picked up on the next pass rather than being pinned for the record's TTL.
     ******************************************************************************/
    private static String reverseLookup(String ip) {
        try {
            Lookup lookup = new Lookup(ReverseMap.fromAddress(ip), Type.PTR);
            lookup.setResolver(upstreamResolver);
            lookup.setCache(null);

            Record[] answers = lookup.run();
            if (answers == null) {
                return null;
            }
            for (Record answer : answers) {
                if (answer instanceof PTRRecord) {
                    String name = normalizeDomain(((PTRRecord) answer).getTarget().toString(true));
                    if (!name.isEmpty()) {
                        return name;
                    }
                }
            }
        } catch (Exception e) {
            /* An unresolvable address is the normal case for anything the
             * router has no lease for, so this is not worth a warning. */
            log.debug("Reverse lookup failed for {}: {}", ip, e.toString());
        }
        return null;
    }

    /******************************************************************************
     * normalizeIp
     *
     * Returns the canonical form of a literal address, or null if the value is
     * not one.
     *
     * The character check comes first so that getByName() cannot be handed a
     * hostname and made to perform a DNS lookup on untrusted input.
     ******************************************************************************/
    private static String normalizeIp(String value) {
        String candidate = value == null ? "" : value.trim();
        if (candidate.isEmpty() || candidate.length() > MAX_IP_LENGTH) {
            return null;
        }
        boolean hasSeparator = false;
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (c == '.' || c == ':') {
                hasSeparator = true;
            } else if (!isHex && c != '%') {
                return null;
            }
        }
        /* Without a separator the value is a bare number, which getByName()
         * would happily reinterpret as a packed address. */
        if (!hasSeparator) {
            return null;
        }
        try {
            return InetAddress.getByName(candidate).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /******************************************************************************
     * addColumnIfMissing
     *
     * SQLite has no "ADD COLUMN IF NOT EXISTS", so the current columns are read
     * back from PRAGMA table_info first.
     ******************************************************************************/
    private static void addColumnIfMissing(Connection conn, String table, String column, String ddl)
            throws SQLException {
        boolean present = false;
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + table + ");")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) {
                    present = true;
                    break;
                }
            }
        }
        if (present) {
            return;
        }
        try (Statement stmt = conn.createStatement()) {
            stmt.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl + ";");
            log.info("Added column {}.{} to existing database", table, column);
        }
    }

    /******************************************************************************
     * loadWhitelistCache
     ******************************************************************************/
    private static void loadWhitelistCache() {
        try {
            whitelistCache.addAll(readWhitelistTable());
        } catch (SQLException e) {
            log.error("CRITICAL: Failed to load whitelist table: {}", e.getMessage());
            System.exit(2);
        }
        log.info("Loaded {} whitelist entr(ies) into memory cache", whitelistCache.size());
    }

    /******************************************************************************
     * reloadWhitelistCache
     *
     * Re-reads the whitelist table and converges the cache on it, which is how a
     * change made outside the control socket (a direct sqlite3 edit, or a change
     * made while the daemon was down) reaches the resolver.
     *
     * Adds before removing, so a name present both before and after is never
     * momentarily absent; clearing first would deny live queries for the length
     * of the reload.
     ******************************************************************************/
    private static int reloadWhitelistCache() throws SQLException {
        Set<String> loaded = readWhitelistTable();
        whitelistCache.addAll(loaded);
        whitelistCache.retainAll(loaded);
        return whitelistCache.size();
    }

    /******************************************************************************
     * readWhitelistTable
     ******************************************************************************/
    private static Set<String> readWhitelistTable() throws SQLException {
        String selectSql = "SELECT name FROM whitelist;";
        Set<String> loaded = new HashSet<>();
        try (Connection conn = getDbConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(selectSql)) {
            int rejected = 0;
            while (rs.next()) {
                String domain = normalizeDomain(rs.getString("name"));
                if (isValidWhitelistEntry(domain)) {
                    loaded.add(domain);
                } else if (!domain.isEmpty()) {
                    rejected++;
                    log.warn("Ignoring invalid whitelist entry '{}': entries must have at least " +
                            "two labels (e.g. example.com)", domain);
                }
            }
            if (rejected > 0) {
                log.warn("Ignored {} invalid whitelist entr(ies)", rejected);
            }
        }
        return loaded;
    }

    /******************************************************************************
     * startDnsListener
     ******************************************************************************/
    private static void startDnsListener() {
        try (DatagramSocket socket = new DatagramSocket(DNS_PORT, InetAddress.getByName("0.0.0.0"))) {
            log.info("Listening for UDP DNS queries on 0.0.0.0:{}", DNS_PORT);
            while (true) {
                byte[] buffer = new byte[UDP_RECEIVE_BUFFER_BYTES];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                byte[] requestData = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), 0, requestData, 0, packet.getLength());
                InetAddress clientAddr = packet.getAddress();
                int clientPort = packet.getPort();

                requestWorkerPool.submit(() -> processUdpRequest(socket, requestData, clientAddr, clientPort));
            }
        } catch (IOException e) {
            log.error("CRITICAL: UDP port {} listener crashed: {}", DNS_PORT, e.getMessage(), e);
            System.exit(2);
        }
    }

    /******************************************************************************
     * startTcpListener
     *
     * RFC 7766 requires DNS servers to accept queries over TCP; it is also the
     * fallback path clients use when a UDP response comes back truncated.
     ******************************************************************************/
    private static void startTcpListener() {
        Thread listenerThread = new Thread(() -> {
            try (ServerSocket serverSocket =
                         new ServerSocket(DNS_PORT, TCP_BACKLOG, InetAddress.getByName("0.0.0.0"))) {
                log.info("Listening for TCP DNS queries on 0.0.0.0:{}", DNS_PORT);
                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    requestWorkerPool.submit(() -> processTcpConnection(clientSocket));
                }
            } catch (IOException e) {
                log.error("CRITICAL: TCP port {} listener crashed: {}", DNS_PORT, e.getMessage(), e);
                System.exit(2);
            }
        }, "dns-tcp-listener");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    /******************************************************************************
     * processUdpRequest
     ******************************************************************************/
    private static void processUdpRequest(DatagramSocket socket, byte[] data,
                                          InetAddress clientAddr, int clientPort) {
        byte[] responseData = buildResponse(data, false, clientAddr);
        if (responseData != null) {
            sendResponse(socket, responseData, clientAddr, clientPort);
        }
    }

    /******************************************************************************
     * processTcpConnection
     *
     * TCP DNS frames each message with a two byte big-endian length prefix.
     ******************************************************************************/
    private static void processTcpConnection(Socket clientSocket) {
        InetAddress clientAddr = clientSocket.getInetAddress();
        try (Socket socket = clientSocket) {
            socket.setSoTimeout(TCP_IDLE_TIMEOUT_MS);
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());

            while (true) {
                int messageLength;
                try {
                    messageLength = in.readUnsignedShort();
                } catch (IOException e) {
                    return;
                }
                if (messageLength <= 0) {
                    return;
                }

                byte[] requestData = new byte[messageLength];
                in.readFully(requestData);

                byte[] responseData = buildResponse(requestData, true, clientAddr);
                if (responseData == null) {
                    return;
                }
                out.writeShort(responseData.length);
                out.write(responseData);
                out.flush();
            }
        } catch (SocketTimeoutException e) {
            log.debug("TCP connection from {} idled out", clientAddr);
        } catch (IOException e) {
            log.debug("TCP connection from {} failed: {}", clientAddr, e.getMessage());
        }
    }

    /******************************************************************************
     * buildResponse
     *
     * Returns the wire bytes to send back, or null when the request is too
     * malformed to answer at all.
     ******************************************************************************/
    private static byte[] buildResponse(byte[] requestData, boolean viaTcp, InetAddress clientAddr) {
        Message request;
        try {
            request = new Message(requestData);
        } catch (IOException e) {
            log.debug("Unparseable query from {}: {}", clientAddr, e.getMessage());
            return buildRawFormErr(requestData);
        }

        Record question = request.getQuestion();
        if (question == null) {
            log.debug("Query without question section from {}", clientAddr);
            return serialize(errorResponse(request, Rcode.FORMERR, null), request, viaTcp);
        }

        String domain = normalizeDomain(question.getName().toString(true));
        String clientIp = clientAddr.getHostAddress();
        recordClientHit(clientIp);

        try {
            /* One decision covers every query: the client's own policy if it has
             * one, otherwise the default. A blocked client is refused ahead of
             * the whitelist, so "block all" means all, including approved names.
             *
             * Refusals here are NXDOMAIN, the same answer the whitelist gives, so
             * a client sees one consistent behaviour rather than two failure
             * modes. They are deliberately not written to the history table:
             * those counters exist to show what the whitelist is blocking, and
             * folding a policy block into them would distort the very numbers
             * used to decide what to approve. The clients table records the
             * activity instead. */
            String mode = clientMode(clientIp);
            if (MODE_BLOCKED.equals(mode)) {
                log.info("BLOCK {} from {} (policy: block all)", domain, clientIp);
                return serialize(errorResponse(request, Rcode.NXDOMAIN, question), request, viaTcp);
            }

            /* An unfiltered client is treated exactly as though every name were
             * approved, so it takes the same resolve-and-cache path and its
             * traffic is counted the same way. */
            if (MODE_ALLOW_ALL.equals(mode)
                    || isWhitelisted(domain) || (allowLocalNames && isLocalName(domain))) {
                recordAllowedHit(domain);
                return serialize(resolveWhitelisted(request, question, domain), request, viaTcp);
            }

            log.info("DENY {} (type {}) from {}", domain, Type.string(question.getType()), clientAddr);
            submitDbTask(() -> handleDeniedBackgroundLookup(domain));
            return serialize(errorResponse(request, Rcode.NXDOMAIN, question), request, viaTcp);
        } catch (Exception e) {
            log.warn("Failed to answer {} for {}: {}", domain, clientAddr, e.toString());
            return serialize(errorResponse(request, Rcode.SERVFAIL, question), request, viaTcp);
        }
    }

    /******************************************************************************
     * resolveWhitelisted
     ******************************************************************************/
    private static Message resolveWhitelisted(Message request, Record question, String domain)
            throws IOException {
        String cacheKey = buildCacheKey(request, question, domain);

        CachedDnsResponse cached = dnsMemoryCache.get(cacheKey);
        if (cached != null && !cached.isExpired()) {
            Message cachedResponse = new Message(cached.rawResponseBytes);
            cachedResponse.getHeader().setID(request.getHeader().getID());
            log.debug("CACHE HIT {}", cacheKey);
            return cachedResponse;
        }

        Message upstreamResponse;
        try {
            upstreamResponse = upstreamResolver.send(request);
        } catch (IOException e) {
            /* Without this the client gets nothing at all and hangs until its
             * own timeout expires. */
            log.warn("Upstream {} failed for {}: {}", secondaryDns, domain, e.toString());
            return errorResponse(request, Rcode.SERVFAIL, question);
        }

        int rcode = upstreamResponse.getHeader().getRcode();
        if (rcode == Rcode.NOERROR || rcode == Rcode.NXDOMAIN) {
            long ttlSeconds = extractTtlSeconds(upstreamResponse);
            cachePut(cacheKey, new CachedDnsResponse(upstreamResponse.toWire(), ttlSeconds));
            log.debug("CACHE STORE {} ttl={}s", cacheKey, ttlSeconds);
        }

        return upstreamResponse;
    }

    /******************************************************************************
     * buildCacheKey
     *
     * The DNSSEC OK bit is part of the key because it changes what the upstream
     * server returns.
     ******************************************************************************/
    private static String buildCacheKey(Message request, Record question, String domain) {
        OPTRecord opt = request.getOPT();
        boolean dnssecOk = opt != null && (opt.getFlags() & ExtendedFlags.DO) != 0;
        return domain + "#" + question.getType() + "#" + question.getDClass() + "#" + (dnssecOk ? "do" : "nodo");
    }

    /******************************************************************************
     * extractTtlSeconds
     *
     * Uses the smallest TTL in the answer section so nothing is served past its
     * intended lifetime. Falls back to 60 seconds when no TTL is available.
     ******************************************************************************/
    private static long extractTtlSeconds(Message response) {
        long minimumTtl = Long.MAX_VALUE;
        for (Record record : response.getSection(Section.ANSWER)) {
            long ttl = record.getTTL();
            if (ttl > 0 && ttl < minimumTtl) {
                minimumTtl = ttl;
            }
        }
        if (minimumTtl == Long.MAX_VALUE) {
            return DEFAULT_TTL_SECONDS;
        }
        return minimumTtl;
    }

    /******************************************************************************
     * errorResponse
     ******************************************************************************/
    private static Message errorResponse(Message request, int rcode, Record question) {
        Message response = new Message(request.getHeader().getID());
        response.getHeader().setOpcode(request.getHeader().getOpcode());
        response.getHeader().setFlag(Flags.QR);
        if (request.getHeader().getFlag(Flags.RD)) {
            response.getHeader().setFlag(Flags.RD);
            response.getHeader().setFlag(Flags.RA);
        }
        response.getHeader().setRcode(rcode);
        if (question != null) {
            response.addRecord(question, Section.QUESTION);
        }
        return response;
    }

    /******************************************************************************
     * buildRawFormErr
     *
     * Best effort reply for a message we could not parse: echo the transaction
     * id with FORMERR rather than leaving the client waiting.
     ******************************************************************************/
    private static byte[] buildRawFormErr(byte[] requestData) {
        if (requestData.length < 12) {
            return null;
        }
        byte[] response = new byte[12];
        response[0] = requestData[0];
        response[1] = requestData[1];
        response[2] = (byte) 0x80;
        response[3] = (byte) Rcode.FORMERR;
        return response;
    }

    /******************************************************************************
     * serialize
     *
     * Applies the size limit that matches how the client reached us. Oversized
     * UDP answers come back with the TC flag set so the client retries on TCP.
     ******************************************************************************/
    private static byte[] serialize(Message response, Message request, boolean viaTcp) {
        if (viaTcp) {
            return response.toWire(TCP_MESSAGE_LIMIT);
        }

        OPTRecord clientOpt = request.getOPT();
        if (clientOpt == null) {
            /* A client that did not use EDNS0 must not receive an OPT record,
             * and cannot be assumed to handle more than 512 bytes. */
            OPTRecord responseOpt = response.getOPT();
            if (responseOpt != null) {
                response.removeRecord(responseOpt, Section.ADDITIONAL);
            }
            return response.toWire(PLAIN_UDP_RESPONSE_LIMIT);
        }

        int advertised = clientOpt.getPayloadSize();
        int limit = Math.max(PLAIN_UDP_RESPONSE_LIMIT, Math.min(advertised, EDNS_UDP_RESPONSE_LIMIT));
        return response.toWire(limit);
    }

    /******************************************************************************
     * cachePut
     ******************************************************************************/
    private static void cachePut(String cacheKey, CachedDnsResponse entry) {
        if (dnsMemoryCache.size() >= MAX_CACHE_ENTRIES) {
            purgeExpiredCacheEntries();
            if (dnsMemoryCache.size() >= MAX_CACHE_ENTRIES) {
                evictEntries(dnsMemoryCache.size() - (MAX_CACHE_ENTRIES * 9 / 10));
            }
        }
        dnsMemoryCache.put(cacheKey, entry);
    }

    /******************************************************************************
     * purgeExpiredCacheEntries
     ******************************************************************************/
    private static void purgeExpiredCacheEntries() {
        try {
            int removed = 0;
            Iterator<Map.Entry<String, CachedDnsResponse>> it = dnsMemoryCache.entrySet().iterator();
            while (it.hasNext()) {
                if (it.next().getValue().isExpired()) {
                    it.remove();
                    removed++;
                }
            }
            if (removed > 0) {
                log.debug("Cache sweep removed {} expired entr(ies); {} remain", removed, dnsMemoryCache.size());
            }
        } catch (RuntimeException e) {
            log.warn("Cache sweep failed: {}", e.toString());
        }
    }

    /******************************************************************************
     * evictEntries
     ******************************************************************************/
    private static void evictEntries(int howMany) {
        if (howMany <= 0) {
            return;
        }
        int removed = 0;
        Iterator<String> it = dnsMemoryCache.keySet().iterator();
        while (it.hasNext() && removed < howMany) {
            it.next();
            it.remove();
            removed++;
        }
        log.warn("DNS cache reached {} entries; evicted {} to stay bounded", MAX_CACHE_ENTRIES, removed);
    }

    /******************************************************************************
     * submitDbTask
     *
     * The queue is bounded so that a flood of denied requests cannot grow it
     * without limit. Overflow is dropped and counted rather than answered late.
     ******************************************************************************/
    private static void submitDbTask(Runnable task) {
        try {
            dbExecutorPool.execute(task);
        } catch (RejectedExecutionException e) {
            long dropped = droppedDbTasks.incrementAndGet();
            if (dropped == 1 || dropped % 1000 == 0) {
                log.warn("Database task backlog full; dropped {} denied-request log task(s)", dropped);
            }
        }
    }

    /******************************************************************************
     * recordAllowedHit
     *
     * Counts an allowed query in memory. Called on every whitelisted request,
     * including local cache hits, so it must stay allocation-light and must not
     * touch the database.
     ******************************************************************************/
    private static void recordAllowedHit(String domain) {
        AllowedHit hit = pendingAllowedHits.computeIfAbsent(domain, key -> new AllowedHit());
        hit.count.incrementAndGet();
        hit.lastSeen = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    }

    /******************************************************************************
     * flushAllowedHits
     *
     * Writes every pending tally in a single transaction. A row may not exist
     * yet when a domain was whitelisted before it was ever denied, so this is an
     * upsert that leaves the denial counters untouched.
     ******************************************************************************/
    private static void flushAllowedHits() {
        if (pendingAllowedHits.isEmpty()) {
            return;
        }

        String upsertAllowedSql = "INSERT INTO history (name, count, last_seen, allowed_count, allowed_last_seen) " +
                "VALUES (?, 0, NULL, ?, ?) " +
                "ON CONFLICT(name) DO UPDATE SET " +
                "allowed_count = history.allowed_count + excluded.allowed_count, " +
                "allowed_last_seen = excluded.allowed_last_seen;";

        try (Connection conn = getDbConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement stmt = conn.prepareStatement(upsertAllowedSql)) {
                for (Map.Entry<String, AllowedHit> entry : pendingAllowedHits.entrySet()) {
                    AllowedHit hit = entry.getValue();
                    long delta = hit.count.getAndSet(0);
                    if (delta == 0) {
                        /* Idle since the last flush, so stop tracking it. */
                        pendingAllowedHits.remove(entry.getKey(), hit);
                        continue;
                    }
                    stmt.setString(1, entry.getKey());
                    stmt.setLong(2, delta);
                    stmt.setString(3, hit.lastSeen);
                    stmt.addBatch();
                }
                stmt.executeBatch();
            }
            conn.commit();
        } catch (SQLException e) {
            log.warn("Failed to flush allowed-query counters: {}", e.getMessage());
        }
    }

    /******************************************************************************
     * handleDeniedBackgroundLookup
     ******************************************************************************/
    private static void handleDeniedBackgroundLookup(String domain) {
        String nowIso = DateTimeFormatter.ISO_INSTANT.format(Instant.now());
        String upsertDeniedSql = "INSERT INTO history (name, count, last_seen) " +
                "VALUES (?, 1, ?) " +
                "ON CONFLICT(name) DO UPDATE SET " +
                "count = history.count + 1, " +
                "last_seen = excluded.last_seen;";

        List<String> candidates = candidateSuffixes(domain);

        try (Connection conn = getDbConnection()) {
            try (PreparedStatement deniedStmt = conn.prepareStatement(upsertDeniedSql)) {
                deniedStmt.setString(1, domain);
                deniedStmt.setString(2, nowIso);
                deniedStmt.executeUpdate();
            }

            if (candidates.isEmpty()) {
                return;
            }

            /* The entry that covers this name may be any of its parent domains,
             * so every candidate suffix has to be checked, not just the exact
             * name that was queried.
             *
             * COLLATE must sit on the column here; "name IN (...) COLLATE
             * NOCASE" parses but silently matches nothing. */
            StringBuilder sql = new StringBuilder(
                    "SELECT name FROM whitelist WHERE name COLLATE NOCASE IN (");
            for (int i = 0; i < candidates.size(); i++) {
                sql.append(i == 0 ? "?" : ",?");
            }
            sql.append(");");

            try (PreparedStatement checkStmt = conn.prepareStatement(sql.toString())) {
                for (int i = 0; i < candidates.size(); i++) {
                    checkStmt.setString(i + 1, candidates.get(i));
                }
                try (ResultSet rs = checkStmt.executeQuery()) {
                    while (rs.next()) {
                        String allowed = normalizeDomain(rs.getString("name"));
                        if (isValidWhitelistEntry(allowed) && whitelistCache.add(allowed)) {
                            log.info("Whitelist cache updated from database: {} (covers {})", allowed, domain);
                        }
                    }
                }
            }
        } catch (SQLException e) {
            log.warn("Failed to record denied request for {}: {}", domain, e.getMessage());
        }
    }

    /******************************************************************************
     * sendResponse
     ******************************************************************************/
    private static void sendResponse(DatagramSocket socket, byte[] responseData,
                                     InetAddress clientAddr, int clientPort) {
        try {
            DatagramPacket outPacket = new DatagramPacket(responseData, responseData.length, clientAddr, clientPort);
            socket.send(outPacket);
        } catch (IOException e) {
            log.debug("Failed to send response to {}:{}: {}", clientAddr, clientPort, e.getMessage());
        }
    }

    /******************************************************************************
     * isWhitelisted
     *
     * A whitelist entry covers the domain itself and every subdomain of it, so
     * "microsoft.com" permits both "microsoft.com" and "whatever.microsoft.com".
     *
     * Rather than scanning every whitelist entry, this walks the query name up
     * to the root, which is a handful of hash lookups regardless of how large
     * the whitelist is.
     ******************************************************************************/
    private static boolean isWhitelisted(String domain) {
        for (String candidate : candidateSuffixes(domain)) {
            if (whitelistCache.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    /******************************************************************************
     * candidateSuffixes
     *
     * Returns the name itself plus each parent domain, cut only at label
     * boundaries. For "a.b.microsoft.com" that is:
     *   a.b.microsoft.com, b.microsoft.com, microsoft.com
     *
     * Cutting only at dots is what keeps "notmicrosoft.com" from matching a
     * "microsoft.com" entry, which a plain string-suffix test would allow.
     *
     * The bare TLD ("com") is deliberately never produced, so a stray
     * single-label row could not whitelist an entire top-level domain.
     ******************************************************************************/
    private static List<String> candidateSuffixes(String domain) {
        List<String> candidates = new ArrayList<>();
        if (domain == null || domain.isEmpty()) {
            return candidates;
        }
        String candidate = domain;
        while (candidate.indexOf('.') >= 0) {
            candidates.add(candidate);
            int dot = candidate.indexOf('.');
            if (dot + 1 >= candidate.length()) {
                break;
            }
            candidate = candidate.substring(dot + 1);
        }
        return candidates;
    }

    /******************************************************************************
     * isLocalName
     *
     * True for a single-label name such as "elrond". ICANN prohibits dotless
     * domains, so a name with no dot can only ever be answered by the local
     * network. Locality is therefore guaranteed by the shape of the name, which
     * is why no address check is needed to treat it as local.
     ******************************************************************************/
    private static boolean isLocalName(String domain) {
        return domain != null && !domain.isEmpty() && domain.indexOf('.') < 0;
    }

    /******************************************************************************
     * isValidWhitelistEntry
     *
     * Entries must have at least two labels. A single-label entry such as "com"
     * would otherwise permit every domain beneath that top-level domain.
     ******************************************************************************/
    /******************************************************************************
     * isValidWhitelistEntry
     *
     * Checks the shape of a name before it can enter the whitelist or the cache.
     *
     * The control socket accepts commands from another process, so this is an
     * input boundary and not merely a convenience check: without the per-label
     * rules, arbitrary text would be accepted and held in the cache, where it
     * could never match a real query but would still be reported by "stats" and
     * survive until a reload.
     *
     * Mirrored by isValidWhitelistEntry() in the web UI's lib.php; the two must
     * agree or an entry accepted by one is silently dropped by the other.
     ******************************************************************************/
    private static boolean isValidWhitelistEntry(String domain) {
        if (domain == null || domain.isEmpty() || domain.length() > MAX_DOMAIN_LENGTH) {
            return false;
        }
        /* A leading or trailing dot would produce an empty label, and requiring
         * an interior dot is what keeps single-label names out: those are
         * handled as local names, which are a separate class. */
        if (domain.charAt(0) == '.' || domain.endsWith(".") || domain.indexOf('.') <= 0) {
            return false;
        }
        for (String label : domain.split("\\.", -1)) {
            if (!isValidDomainLabel(label)) {
                return false;
            }
        }
        return true;
    }

    /******************************************************************************
     * isValidDomainLabel
     *
     * Letters, digits, hyphen, and underscore. Underscore is not in RFC 1035 but
     * is what service names such as _dmarc use in practice, and rejecting it
     * would make those impossible to whitelist.
     *
     * The input has already been lower-cased by normalizeDomain, so upper case
     * here means the caller skipped normalization and the entry would not match
     * a lookup anyway.
     ******************************************************************************/
    private static boolean isValidDomainLabel(String label) {
        if (label.isEmpty() || label.length() > MAX_LABEL_LENGTH) {
            return false;
        }
        if (label.charAt(0) == '-' || label.charAt(label.length() - 1) == '-') {
            return false;
        }
        for (int i = 0; i < label.length(); i++) {
            char c = label.charAt(i);
            boolean allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_';
            if (!allowed) {
                return false;
            }
        }
        return true;
    }

    /******************************************************************************
     * normalizeDomain
     ******************************************************************************/
    private static String normalizeDomain(String rawDomain) {
        if (rawDomain == null) return "";
        String trimmed = rawDomain.trim().toLowerCase(Locale.ROOT);
        while (trimmed.endsWith(".")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        /* Tolerate entries written as ".microsoft.com", which would otherwise
         * never match anything. */
        while (trimmed.startsWith(".")) {
            trimmed = trimmed.substring(1);
        }
        return trimmed;
    }
}