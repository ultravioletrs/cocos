package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.util.ArrayList;
import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ComputationRequest {

    private String jobId;
    private String towerCallbackUrl;
    private List<ComputationUnit> units = new ArrayList<>();

    private ComputationRequest() {}

    public String getJobId() { return jobId; }

    public String getTowerCallbackUrl() { return towerCallbackUrl; }

    public List<ComputationUnit> getUnits() { return units; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final ComputationRequest instance = new ComputationRequest();

        public Builder jobId(String jobId) { instance.jobId = jobId; return this; }

        public Builder towerCallbackUrl(String url) { instance.towerCallbackUrl = url; return this; }

        public Builder units(List<ComputationUnit> units) { instance.units = units; return this; }

        public ComputationRequest build() { return instance; }
    }
}
