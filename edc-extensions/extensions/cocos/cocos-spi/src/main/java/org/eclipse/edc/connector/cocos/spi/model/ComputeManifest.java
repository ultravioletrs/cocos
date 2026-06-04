package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.util.ArrayList;
import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ComputeManifest {

    private String id;
    private String name;
    private String description;
    private List<DatasetSpec> datasets = new ArrayList<>();
    private AlgorithmSpec algorithm;
    private AgentConfig agentConfig;

    private ComputeManifest() {}

    public String getId() { return id; }

    public String getName() { return name; }

    public String getDescription() { return description; }

    public List<DatasetSpec> getDatasets() { return datasets; }

    public AlgorithmSpec getAlgorithm() { return algorithm; }

    public AgentConfig getAgentConfig() { return agentConfig; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final ComputeManifest instance = new ComputeManifest();

        public Builder id(String id) { instance.id = id; return this; }

        public Builder name(String name) { instance.name = name; return this; }

        public Builder description(String description) { instance.description = description; return this; }

        public Builder datasets(List<DatasetSpec> datasets) { instance.datasets = datasets; return this; }

        public Builder algorithm(AlgorithmSpec algorithm) { instance.algorithm = algorithm; return this; }

        public Builder agentConfig(AgentConfig agentConfig) { instance.agentConfig = agentConfig; return this; }

        public ComputeManifest build() { return instance; }
    }
}
