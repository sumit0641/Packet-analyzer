package dpi;

import dpi.Types.*;
import java.io.*;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DPI Engine - Main orchestrator.
 *
 * Architecture Overview:
 * PCAP Reader -> Load Balancers (LB) -> Fast Path Processors (FP) -> Output Queue -> Output Writer
 */
public class DpiEngine implements AutoCloseable {

    // ========================================================================
    // Configuration
    // ========================================================================
    public static class Config {
        private int numLoadBalancers = 2;
        private int fpsPerLb = 2;
        private int queueSize = 10_000;
        private String rulesFile = "";
        private boolean verbose = false;

        public Config() {}

        public Config(int numLoadBalancers, int fpsPerLb, int queueSize, String rulesFile, boolean verbose) {
            this.numLoadBalancers = numLoadBalancers;
            this.fpsPerLb = fpsPerLb;
            this.queueSize = queueSize;
            this.rulesFile = rulesFile;
            this.verbose = verbose;
        }

        public int getNumLoadBalancers() { return numLoadBalancers; }
        public void setNumLoadBalancers(int numLoadBalancers) { this.numLoadBalancers = numLoadBalancers; }

        public int getFpsPerLb() { return fpsPerLb; }
        public void setFpsPerLb(int fpsPerLb) { this.fpsPerLb = fpsPerLb; }

        public int getQueueSize() { return queueSize; }
        public void setQueueSize(int queueSize) { this.queueSize = queueSize; }

        public String getRulesFile() { return rulesFile; }
        public void setRulesFile(String rulesFile) { this.rulesFile = rulesFile; }

        public boolean isVerbose() { return verbose; }
        public void setVerbose(boolean verbose) { this.verbose = verbose; }
    }

    // ========================================================================
    // Fields
    // ========================================================================
    private final Config config;

    // Shared components
    private final RuleManager ruleManager;
    private final GlobalConnectionTable globalConnTable;

    // Subsystem Managers
    private LbManager lbManager;
    private FpManager fpManager;

    // Output Handling
    private final BlockingQueue<PacketJob> outputQueue;
    private Thread outputThread;
    private OutputStream outputStream;
    private final Object outputLock = new Object();

    // Stats
    private final DpiStats stats = new DpiStats();

    // State control
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean processingComplete = new AtomicBoolean(false);

    // Reader thread
    private Thread readerThread;

    // ========================================================================
    // Constructor & Lifecycle
    // ========================================================================
    public DpiEngine(Config config) {
        this.config = Objects.requireNonNull(config, "Config cannot be null");
        this.ruleManager = new RuleManager();
        int totalFps = config.getNumLoadBalancers() * config.getFpsPerLb();
        this.globalConnTable = new GlobalConnectionTable(totalFps);
        this.outputQueue = new ArrayBlockingQueue<>(config.getQueueSize());
    }

    /**
     * Initialize the engine (pools, queues, rule loading).
     */
    public synchronized boolean initialize() {
        try {
            if (config.getRulesFile() != null && !config.getRulesFile().isBlank()) {
                loadRules(config.getRulesFile());
            }

            this.fpManager = new FpManager(config.getNumLoadBalancers() * config.getFpsPerLb(), globalConnTable, outputQueue);
            this.lbManager = new LbManager(config.getNumLoadBalancers(), config.getFpsPerLb(), fpManager);

            return true;
        } catch (Exception e) {
            System.err.println("Initialization failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Start worker threads and output consumer.
     */
    public synchronized void start() {
        if (running.compareAndSet(false, true)) {
            processingComplete.set(false);

            if (fpManager != null) fpManager.start();
            if (lbManager != null) lbManager.start();

            outputThread = new Thread(this::outputThreadFunc, "DPI-OutputWriter");
            outputThread.start();
        }
    }

    /**
     * Process a PCAP file and forward allowed packets to the output file.
     */
    public boolean processFile(String inputFile, String outputFile) {
        if (!running.get()) {
            start();
        }

        try {
            synchronized (outputLock) {
                this.outputStream = new BufferedOutputStream(new FileOutputStream(outputFile));
            }
        } catch (FileNotFoundException e) {
            System.err.println("Could not open output file: " + e.getMessage());
            return false;
        }

        readerThread = new Thread(() -> readerThreadFunc(inputFile), "DPI-PcapReader");
        readerThread.start();

        return true;
    }

    /**
     * Stop all processing and background threads.
     */
    public synchronized void stop() {
        if (running.compareAndSet(true, false)) {
            if (readerThread != null && readerThread.isAlive()) {
                readerThread.interrupt();
            }

            if (lbManager != null) lbManager.stop();
            if (fpManager != null) fpManager.stop();

            if (outputThread != null && outputThread.isAlive()) {
                outputThread.interrupt();
            }

            synchronized (outputLock) {
                if (outputStream != null) {
                    try {
                        outputStream.flush();
                        outputStream.close();
                    } catch (IOException ignored) {}
                }
            }
        }
    }

    /**
     * Block until the reader completes and remaining packets are flushed.
     */
    public void waitForCompletion() {
        try {
            if (readerThread != null) {
                readerThread.join();
            }
            while (!outputQueue.isEmpty() && running.get()) {
                Thread.sleep(10);
            }
            processingComplete.set(true);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public void close() {
        stop();
    }

    // ========================================================================
    // Rule Management Delegations
    // ========================================================================
    public void blockIP(String ip) { ruleManager.blockIP(ip); }
    public void unblockIP(String ip) { ruleManager.unblockIP(ip); }

    public void blockApp(AppType app) { ruleManager.blockApp(app); }
    public void blockApp(String appName) { ruleManager.blockApp(appName); }

    public void unblockApp(AppType app) { ruleManager.unblockApp(app); }
    public void unblockApp(String appName) { ruleManager.unblockApp(appName); }

    public void blockDomain(String domain) { ruleManager.blockDomain(domain); }
    public void unblockDomain(String domain) { ruleManager.unblockDomain(domain); }

    public boolean loadRules(String filename) { return ruleManager.loadFromFile(filename); }
    public boolean saveRules(String filename) { return ruleManager.saveToFile(filename); }

    // ========================================================================
    // Reporting & Statistics
    // ========================================================================
    public String generateReport() {
        return globalConnTable.generateReport();
    }

    public String generateClassificationReport() {
        GlobalConnectionTable.GlobalStats gStats = globalConnTable.getGlobalStats();
        StringBuilder sb = new StringBuilder();
        sb.append("--- App Distribution ---\n");
        gStats.appDistribution().forEach((k, v) -> sb.append(k).append(": ").append(v).append("\n"));
        return sb.toString();
    }

    public DpiStats getStats() { return stats; }

    public void printStatus() {
        System.out.printf("Active: %d | Total Seen: %d | Queued Outputs: %d%n",
                globalConnTable.getGlobalStats().totalActiveConnections(),
                globalConnTable.getGlobalStats().totalConnectionsSeen(),
                outputQueue.size());
    }

    // ========================================================================
    // Accessors
    // ========================================================================
    public RuleManager getRuleManager() { return ruleManager; }
    public Config getConfig() { return config; }
    public boolean isRunning() { return running.get(); }
    public boolean isProcessingComplete() { return processingComplete.get(); }

    // ========================================================================
    // Internal Workers & Pipeline Logic
    // ========================================================================
    private void readerThreadFunc(String inputFile) {
        try (PcapReader reader = new PcapReader(inputFile)) {
            PcapGlobalHeader header = reader.readHeader();
            synchronized (outputLock) {
                writeOutputHeader(header);
            }

            long packetId = 0;
            RawPacket raw;
            while (running.get() && (raw = reader.readNextPacket()) != null) {
                ParsedPacket parsed = PacketParser.parse(raw);
                PacketJob job = createPacketJob(raw, parsed, packetId++);
                lbManager.dispatch(job);
            }
        } catch (Exception e) {
            if (running.get()) {
                System.err.println("Error reading PCAP: " + e.getMessage());
            }
        }
    }

    private void outputThreadFunc() {
        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketJob job = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (job != null) {
                    handleOutput(job, job.getAction());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void handleOutput(PacketJob job, PacketAction action) {
        if (action == PacketAction.FORWARD) {
            synchronized (outputLock) {
                writeOutputPacket(job);
            }
            stats.incrementForwarded();
        } else if (action == PacketAction.DROP) {
            stats.incrementDropped();
        }
    }

    private boolean writeOutputHeader(PcapGlobalHeader header) {
        if (outputStream == null) return false;
        try {
            header.writeTo(outputStream);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private void writeOutputPacket(PacketJob job) {
        if (outputStream == null) return;
        try {
            job.writeRawPacket(outputStream);
        } catch (IOException e) {
            System.err.println("Error writing packet: " + e.getMessage());
        }
    }

    private PacketJob createPacketJob(RawPacket raw, ParsedPacket parsed, long packetId) {
        return new PacketJob(packetId, raw, parsed);
    }
}