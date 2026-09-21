package dpi;

import dpi.Types.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fast Path Processor Thread.
 *
 * Responsibilities:
 * 1. Receive packets from input queue.
 * 2. Maintain flow state via ConnectionTracker.
 * 3. Deep Packet Inspection (SNI extraction, protocol detection).
 * 4. Rule matching (blocking decisions).
 * 5. Forward or drop packets.
 */
public class FastPathProcessor {

    public record FPStats(
        long packetsProcessed,
        long packetsForwarded,
        long packetsDropped,
        long connectionsTracked,
        long sniExtractions,
        long classificationHits
    ) {}

    private final int fpId;
    private final BlockingQueue<PacketJob> inputQueue;
    private final ConnectionTracker connTracker;
    private final RuleManager ruleManager;
    private final PacketOutputCallback outputCallback;

    // Statistics
    private final AtomicLong packetsProcessed = new AtomicLong(0);
    private final AtomicLong packetsForwarded = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);
    private final AtomicLong sniExtractions = new AtomicLong(0);
    private final AtomicLong classificationHits = new AtomicLong(0);

    // Thread control
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread workerThread;

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this(fpId, ruleManager, outputCallback, 10_000);
    }

    public FastPathProcessor(int fpId, RuleManager ruleManager, PacketOutputCallback outputCallback, int queueCapacity) {
        this.fpId = fpId;
        this.ruleManager = ruleManager;
        this.outputCallback = outputCallback;
        this.inputQueue = new ArrayBlockingQueue<>(queueCapacity);
        this.connTracker = new ConnectionTracker(fpId);
    }

    /**
     * Start the FP worker thread.
     */
    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            workerThread = new Thread(this::run, "DPI-FP-" + fpId);
            workerThread.start();
        }
    }

    /**
     * Stop the FP worker thread.
     */
    public synchronized void stop() {
        if (running.compareAndSet(true, false)) {
            if (workerThread != null && workerThread.isAlive()) {
                workerThread.interrupt();
            }
        }
    }

    public BlockingQueue<PacketJob> getInputQueue() {
        return inputQueue;
    }

    public ConnectionTracker getConnectionTracker() {
        return connTracker;
    }

    public int getId() {
        return fpId;
    }

    public boolean isRunning() {
        return running.get();
    }

    public FPStats getStats() {
        return new FPStats(
            packetsProcessed.get(),
            packetsForwarded.get(),
            packetsDropped.get(),
            connTracker.getActiveCount(),
            sniExtractions.get(),
            classificationHits.get()
        );
    }

    /**
     * Main consumer loop.
     */
    private void run() {
        while (running.get() || !inputQueue.isEmpty()) {
            try {
                PacketJob job = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job == null) {
                    continue;
                }

                packetsProcessed.incrementAndGet();
                PacketAction action = processPacket(job);
                job.setAction(action);

                if (action == PacketAction.FORWARD) {
                    packetsForwarded.incrementAndGet();
                } else if (action == PacketAction.DROP) {
                    packetsDropped.incrementAndGet();
                }

                if (outputCallback != null) {
                    outputCallback.onPacketOutput(job, action);
                }

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    /**
     * Process a single packet through tracking, inspection, and rules.
     */
    private PacketAction processPacket(PacketJob job) {
        ParsedPacket parsed = job.getParsed();
        if (parsed == null) {
            return PacketAction.FORWARD;
        }

        FiveTuple tuple = parsed.getFiveTuple();
        Connection conn = connTracker.getOrCreateConnection(tuple);

        // Update traffic statistics and connection freshness
        connTracker.updateConnection(conn, parsed.getPayloadLength(), parsed.isOutbound());

        if (parsed.isTcp()) {
            updateTCPState(conn, parsed.getTcpFlags());
        }

        // Deep Packet Inspection if not classified yet
        if (conn.getState() != ConnectionState.CLASSIFIED) {
            inspectPayload(job, conn);
        }

        // Apply filtering policies
        return checkRules(job, conn);
    }

    /**
     * Inspect packet payload for classification (TLS SNI or HTTP Host).
     */
    private void inspectPayload(PacketJob job, Connection conn) {
        if (tryExtractSNI(job, conn)) {
            classificationHits.incrementAndGet();
            return;
        }

        if (tryExtractHTTPHost(job, conn)) {
            classificationHits.incrementAndGet();
        }
    }

    /**
     * Extract SNI from TLS Client Hello.
     */
    private boolean tryExtractSNI(PacketJob job, Connection conn) {
        byte[] payload = job.getParsed().getPayload();
        if (payload == null || payload.length == 0) {
            return false;
        }

        String sni = SniExtractor.extractTlsSni(payload);
        if (sni != null && !sni.isBlank()) {
            sniExtractions.incrementAndGet();
            connTracker.classifyConnection(conn, AppType.HTTPS, sni);
            return true;
        }
        return false;
    }

    /**
     * Extract Host header from HTTP request.
     */
    private boolean tryExtractHTTPHost(PacketJob job, Connection conn) {
        byte[] payload = job.getParsed().getPayload();
        if (payload == null || payload.length == 0) {
            return false;
        }

        String host = SniExtractor.extractHttpHost(payload);
        if (host != null && !host.isBlank()) {
            connTracker.classifyConnection(conn, AppType.HTTP, host);
            return true;
        }
        return false;
    }

    /**
     * Check if packet or flow matches any blocking rules.
     */
    private PacketAction checkRules(PacketJob job, Connection conn) {
        if (ruleManager == null) {
            return PacketAction.FORWARD;
        }

        FiveTuple tuple = job.getParsed().getFiveTuple();

        // 1. IP rule check
        if (ruleManager.isIpBlocked(tuple.srcIp()) || ruleManager.isIpBlocked(tuple.dstIp())) {
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        // 2. Application type rule check
        if (conn.getAppType() != AppType.UNKNOWN && ruleManager.isAppBlocked(conn.getAppType())) {
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        // 3. Domain rule check
        if (!conn.getSni().isBlank() && ruleManager.isDomainBlocked(conn.getSni())) {
            connTracker.blockConnection(conn);
            return PacketAction.DROP;
        }

        return conn.isBlocked() ? PacketAction.DROP : PacketAction.FORWARD;
    }

    /**
     * Track connection state transitions based on TCP flags (SYN, FIN, RST).
     */
    private void updateTCPState(Connection conn, int tcpFlags) {
        final int SYN = 0x02;
        final int RST = 0x04;
        final int FIN = 0x01;

        if ((tcpFlags & RST) != 0 || (tcpFlags & FIN) != 0) {
            conn.setState(ConnectionState.CLOSED);
        } else if ((tcpFlags & SYN) != 0 && conn.getState() == ConnectionState.NEW) {
            conn.setState(ConnectionState.ESTABLISHED);
        }
    }
}
// ============================================================================
// FP Manager - Creates and manages multiple FP threads
// ============================================================================
package dpi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;

/**
 * Manages the lifecycle and distribution across all FastPathProcessor threads.
 */
public class FpManager {

    public record AggregatedStats(
        long totalProcessed,
        long totalForwarded,
        long totalDropped,
        long totalConnections
    ) {}

    private final List<FastPathProcessor> fps;

    public FpManager(int numFps, RuleManager ruleManager, PacketOutputCallback outputCallback) {
        this.fps = new ArrayList<>(numFps);
        for (int i = 0; i < numFps; i++) {
            this.fps.add(new FastPathProcessor(i, ruleManager, outputCallback));
        }
    }

    /**
     * Start all FP threads.
     */
    public void startAll() {
        for (FastPathProcessor fp : fps) {
            fp.start();
        }
    }

    /**
     * Stop all FP threads.
     */
    public void stopAll() {
        for (FastPathProcessor fp : fps) {
            fp.stop();
        }
    }

    public FastPathProcessor getFP(int id) {
        return fps.get(id);
    }

    public BlockingQueue<PacketJob> getFPQueue(int id) {
        return fps.get(id).getInputQueue();
    }

    /**
     * Retrieve references to all FP input queues for Load Balancers.
     */
    public List<BlockingQueue<PacketJob>> getQueuePtrs() {
        List<BlockingQueue<PacketJob>> queues = new ArrayList<>(fps.size());
        for (FastPathProcessor fp : fps) {
            queues.add(fp.getInputQueue());
        }
        return Collections.unmodifiableList(queues);
    }

    public int getNumFPs() {
        return fps.size();
    }

    /**
     * Aggregate statistics across all managed FP threads.
     */
    public AggregatedStats getAggregatedStats() {
        long totalProcessed = 0;
        long totalForwarded = 0;
        long totalDropped = 0;
        long totalConnections = 0;

        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats s = fp.getStats();
            totalProcessed += s.packetsProcessed();
            totalForwarded += s.packetsForwarded();
            totalDropped += s.packetsDropped();
            totalConnections += s.connectionsTracked();
        }

        return new AggregatedStats(totalProcessed, totalForwarded, totalDropped, totalConnections);
    }

    /**
     * Generate summary report across all FP workers.
     */
    public String generateClassificationReport() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Fast Path Processor Aggregate Report ===\n");
        AggregatedStats agg = getAggregatedStats();
        sb.append(String.format("Total Packets Processed: %d\n", agg.totalProcessed()));
        sb.append(String.format("Total Packets Forwarded: %d\n", agg.totalForwarded()));
        sb.append(String.format("Total Packets Dropped:   %d\n", agg.totalDropped()));
        sb.append(String.format("Total Active Flows:      %d\n", agg.totalConnections()));
        sb.append("--------------------------------------------\n");

        for (FastPathProcessor fp : fps) {
            FastPathProcessor.FPStats s = fp.getStats();
            sb.append(String.format("  [FP-%d] Processed: %d | Fwd: %d | Drop: %d | Hits: %d\n",
                fp.getId(), s.packetsProcessed(), s.packetsForwarded(), s.packetsDropped(), s.classificationHits()));
        }
        sb.append("============================================\n");
        return sb.toString();
    }
}