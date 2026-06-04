package org.eclipse.edc.connector.cocos.orchestrator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.edc.connector.cocos.spi.model.ComputationJob;
import org.eclipse.edc.http.spi.EdcHttpClient;
import org.eclipse.edc.spi.monitor.Monitor;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

public class TowerCallbackClient {

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private final EdcHttpClient httpClient;
    private final ObjectMapper mapper;
    private final Monitor monitor;

    public TowerCallbackClient(EdcHttpClient httpClient, ObjectMapper mapper, Monitor monitor) {
        this.httpClient = httpClient;
        this.mapper = mapper;
        this.monitor = monitor;
    }

    public void reportSuccess(ComputationJob job) {
        var encoded = job.getResults().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> Base64.getEncoder().encodeToString(e.getValue())));
        post(job.getTowerCallbackUrl(), Map.of(
                "jobId", job.getJobId(),
                "status", "COMPLETED",
                "results", encoded));
    }

    public void reportFailure(ComputationJob job) {
        post(job.getTowerCallbackUrl(), Map.of(
                "jobId", job.getJobId(),
                "status", "FAILED",
                "error", job.getErrorMessage() != null ? job.getErrorMessage() : "Unknown error"));
    }

    private void post(String url, Object body) {
        try {
            var json = mapper.writeValueAsString(body);
            var request = new Request.Builder()
                    .url(url)
                    .post(RequestBody.create(json, JSON))
                    .build();
            try (var response = httpClient.execute(request)) {
                if (!response.isSuccessful()) {
                    monitor.warning("Tower callback returned non-success status: " + response.code());
                }
            }
        } catch (JsonProcessingException e) {
            monitor.severe("Failed to serialise Tower callback body", e);
        } catch (IOException e) {
            monitor.severe("Failed to call Tower callback at " + url, e);
        }
    }
}
