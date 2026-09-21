package dpi;

import java.time.Instant;
import java.util.Objects;

public class Types {

    public enum ConnectionState {
        NEW, ESTABLISHED, CLASSIFIED, CLOSED
    }

    public enum AppType {
        UNKNOWN, HTTP, HTTPS, DNS, SSH, TLS, STREAMING
    }

    /**
     * Immutable FiveTuple used as a map key.
     * Overrides equals and hashCode for bidirectional consistency if needed.
     */
    public record FiveTuple(
        String srcIp,
        int srcPort,
        String dstIp,
        int dstPort,
        int protocol
    ) {
        // Automatically generates equals(), hashCode(), and getters in Java 16+
    }

    /**
     * Represents an active connection flow.
     */
    public static class Connection {
        private final FiveTuple tuple;
        private ConnectionState state = ConnectionState.NEW;
        private AppType appType = AppType.UNKNOWN;
        private String sni = "";
        private boolean blocked = false;
        private long bytesIn = 0;
        private long bytesOut = 0;
        private Instant lastSeen = Instant.now();

        public Connection(FiveTuple tuple) {
            this.tuple = tuple;
        }

        // Copy constructor (to emulate returning vector of copies)
        public Connection(Connection other) {
            this.tuple = other.tuple;
            this.state = other.state;
            this.appType = other.appType;
            this.sni = other.sni;
            this.blocked = other.blocked;
            this.bytesIn = other.bytesIn;
            this.bytesOut = other.bytesOut;
            this.lastSeen = other.lastSeen;
        }

        // Getters and setters
        public FiveTuple getTuple() { return tuple; }
        public ConnectionState getState() { return state; }
        public void setState(ConnectionState state) { this.state = state; }
        public AppType getAppType() { return appType; }
        public void setAppType(AppType appType) { this.appType = appType; }
        public String getSni() { return sni; }
        public void setSni(String sni) { this.sni = sni; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public Instant getLastSeen() { return lastSeen; }
        public void updateLastSeen() { this.lastSeen = Instant.now(); }
        public void addBytes(long size, boolean isOutbound) {
            if (isOutbound) bytesOut += size;
            else bytesIn += size;
            updateLastSeen();
        }
    }
}

// ============================================================================
// Connection Tracker - Maintains flow table for all active connections
// ============================================================================
//
// Each FP thread has its own ConnectionTracker instance (no sharing needed
// since connections are consistently hashed to the same FP).
//
// Features:
// - Track connection state (NEW -> ESTABLISHED -> CLASSIFIED -> CLOSED)
// - Store classification results (app type, SNI)
// - Maintain per-flow statistics
// - Timeout inactive connections
// ============================================================================

package dpi;

import dpi.Types.*;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Consumer;

/**
 * Maintains flow table for all active connections for a single FP thread.
 */
public class ConnectionTracker {

    public record TrackerStats(
        long activeConnections,
        long totalConnectionsSeen,
        long classifiedConnections,
        long blockedConnections
    ) {}

    private final int fpId;
    private final int maxConnections;

    // Using LinkedHashMap with accessOrder=true simplifies LRU tracking and eviction
    private final Map<FiveTuple, Connection> connections;

    private long totalSeen = 0;
    private long classifiedCount = 0;
    private long blockedCount = 0;

    public ConnectionTracker(int fpId) {
        this(fpId, 100_000);
    }

    public ConnectionTracker(int fpId, int maxConnections) {
        this.fpId = fpId;
        this.maxConnections = maxConnections;
        // LinkedHashMap configured for LRU access ordering
        this.connections = new LinkedHashMap<>(16, 0.75f, true);
    }

    /**
     * Get or create connection entry.
     */
    public Connection getOrCreateConnection(FiveTuple tuple) {
        Connection conn = connections.get(tuple);
        if (conn == null) {
            if (connections.size() >= maxConnections) {
                evictOldest();
            }
            conn = new Connection(tuple);
            connections.put(tuple, conn);
            totalSeen++;
        }
        return conn;
    }

    /**
     * Get existing connection (returns null if not found).
     */
    public Connection getConnection(FiveTuple tuple) {
        return connections.get(tuple);
    }

    /**
     * Update connection with new packet.
     */
    public void updateConnection(Connection conn, long packetSize, boolean isOutbound) {
        if (conn != null) {
            conn.addBytes(packetSize, isOutbound);
            if (conn.getState() == ConnectionState.NEW) {
                conn.setState(ConnectionState.ESTABLISHED);
            }
        }
    }

    /**
     * Mark connection as classified.
     */
    public void classifyConnection(Connection conn, AppType app, String sni) {
        if (conn != null) {
            conn.setAppType(app);
            conn.setSni(sni != null ? sni : "");
            conn.setState(ConnectionState.CLASSIFIED);
            classifiedCount++;
        }
    }

    /**
     * Mark connection as blocked.
     */
    public void blockConnection(Connection conn) {
        if (conn != null) {
            conn.setBlocked(true);
            blockedCount++;
        }
    }

    /**
     * Mark connection as closed and remove it.
     */
    public void closeConnection(FiveTuple tuple) {
        Connection conn = connections.remove(tuple);
        if (conn != null) {
            conn.setState(ConnectionState.CLOSED);
        }
    }

    /**
     * Remove timed-out connections.
     *
     * @param timeout duration threshold (default: 300 seconds)
     * @return number of connections removed
     */
    public int cleanupStale(Duration timeout) {
        Instant cutoff = Instant.now().minus(timeout);
        int removedCount = 0;

        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<FiveTuple, Connection> entry = it.next();
            if (entry.getValue().getLastSeen().isBefore(cutoff)) {
                it.remove();
                removedCount++;
            }
        }
        return removedCount;
    }

    public int cleanupStale() {
        return cleanupStale(Duration.ofSeconds(300));
    }

    /**
     * Get snapshot copy of all connections.
     */
    public List<Connection> getAllConnections() {
        List<Connection> list = new ArrayList<>(connections.size());
        for (Connection conn : connections.values()) {
            list.add(new Connection(conn)); // Defensive copy
        }
        return list;
    }

    public int getActiveCount() {
        return connections.size();
    }

    public TrackerStats getStats() {
        return new TrackerStats(connections.size(), totalSeen, classifiedCount, blockedCount);
    }

    public void clear() {
        connections.clear();
    }

    /**
     * Iteration callback across all connections.
     */
    public void forEach(Consumer<Connection> callback) {
        connections.values().forEach(callback);
    }

    /**
     * Evicts the eldest entry based on LRU order.
     */
    private void evictOldest() {
        Iterator<Map.Entry<FiveTuple, Connection>> it = connections.entrySet().iterator();
        if (it.hasNext()) {
            it.next();
            it.remove();
        }
    }

    public int getFpId() {
        return fpId;
    }
}
// ============================================================================
// Global Connection Table - Aggregates stats from all FP trackers
// ============================================================================
package dpi;

import dpi.Types.*;

import java.util.*;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Aggregates statistics across all worker FP trackers.
 * Corresponds to GlobalConnectionTable with std::shared_mutex synchronization.
 */
public class GlobalConnectionTable {

    public record DomainCount(String domain, long count) {}

    public record GlobalStats(
        long totalActiveConnections,
        long totalConnectionsSeen,
        Map<AppType, Long> appDistribution,
        List<DomainCount> topDomains
    ) {}

    private final List<ConnectionTracker> trackers;
    // std::shared_mutex translates to ReentrantReadWriteLock in Java
    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock();

    public GlobalConnectionTable(int numFps) {
        this.trackers = new ArrayList<>(Collections.nCopies(numFps, null));
    }

    /**
     * Register a tracker instance for an FP thread.
     */
    public void registerTracker(int fpId, ConnectionTracker tracker) {
        rwLock.writeLock().lock();
        try {
            if (fpId >= trackers.size()) {
                while (trackers.size() <= fpId) {
                    trackers.add(null);
                }
            }
            trackers.set(fpId, tracker);
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * Aggregate statistics across all registered trackers.
     */
    public GlobalStats getGlobalStats() {
        rwLock.readLock().lock();
        try {
            long totalActive = 0;
            long totalSeen = 0;
            Map<AppType, Long> appDistribution = new EnumMap<>(AppType.class);
            Map<String, Long> domainCounts = new HashMap<>();

            for (ConnectionTracker tracker : trackers) {
                if (tracker == null) continue;

                ConnectionTracker.TrackerStats stats = tracker.getStats();
                totalActive += stats.activeConnections();
                totalSeen += stats.totalConnectionsSeen();

                tracker.forEach(conn -> {
                    // Count application distribution
                    appDistribution.merge(conn.getAppType(), 1L, Long::sum);

                    // Count domain names (SNI)
                    String sni = conn.getSni();
                    if (sni != null && !sni.isBlank()) {
                        domainCounts.merge(sni, 1L, Long::sum);
                    }
                });
            }

            // Sort top domains by occurrence (descending)
            List<DomainCount> topDomains = domainCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue(), a.getValue()))
                .limit(10)
                .map(e -> new DomainCount(e.getKey(), e.getValue()))
                .collect(Collectors.toList());

            return new GlobalStats(totalActive, totalSeen, appDistribution, topDomains);
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /**
     * Generates a string report of the global table state.
     */
    public String generateReport() {
        GlobalStats stats = getGlobalStats();
        StringBuilder sb = new StringBuilder();

        sb.append("=== Global Connection Report ===\n");
        sb.append(String.format("Active Connections: %d\n", stats.totalActiveConnections()));
        sb.append(String.format("Total Connections Seen: %d\n", stats.totalConnectionsSeen()));
        sb.append("\nApplication Distribution:\n");
        stats.appDistribution().forEach((app, count) ->
            sb.append(String.format("  %-15s: %d\n", app, count))
        );
        sb.append("\nTop Domains:\n");
        for (DomainCount entry : stats.topDomains()) {
            sb.append(String.format("  %-25s: %d\n", entry.domain(), entry.count()));
        }
        sb.append("================================\n");

        return sb.toString();
    }
}