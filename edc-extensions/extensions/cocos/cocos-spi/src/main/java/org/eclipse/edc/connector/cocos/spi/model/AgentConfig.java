package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AgentConfig {

    private int port;
    private String logLevel = "INFO";
    private boolean enableAttestation = true;

    private AgentConfig() {}

    public int getPort() { return port; }

    public String getLogLevel() { return logLevel; }

    public boolean isEnableAttestation() { return enableAttestation; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final AgentConfig instance = new AgentConfig();

        public Builder port(int port) { instance.port = port; return this; }

        public Builder logLevel(String logLevel) { instance.logLevel = logLevel; return this; }

        public Builder enableAttestation(boolean enable) { instance.enableAttestation = enable; return this; }

        public AgentConfig build() { return instance; }
    }
}
