package org.eclipse.edc.connector.cocos.spi.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ComputationJob {

    public enum Status {
        PENDING, STARTING_AGENTS, UPLOADING, RUNNING, COLLECTING_RESULTS, COMPLETED, FAILED
    }

    private final String jobId;
    private final String towerCallbackUrl;
    private final List<ComputationUnit> units;
    private volatile Status status;
    private final Map<String, byte[]> results = new HashMap<>();
    private volatile String errorMessage;

    public ComputationJob(String jobId, String towerCallbackUrl, List<ComputationUnit> units) {
        this.jobId = jobId;
        this.towerCallbackUrl = towerCallbackUrl;
        this.units = new ArrayList<>(units);
        this.status = Status.PENDING;
    }

    public String getJobId() { return jobId; }

    public String getTowerCallbackUrl() { return towerCallbackUrl; }

    public List<ComputationUnit> getUnits() { return units; }

    public Status getStatus() { return status; }

    public Map<String, byte[]> getResults() { return results; }

    public String getErrorMessage() { return errorMessage; }

    public void setStatus(Status status) { this.status = status; }

    public void setResult(String vmIp, byte[] result) { results.put(vmIp, result); }

    public void setErrorMessage(String message) { this.errorMessage = message; }
}
