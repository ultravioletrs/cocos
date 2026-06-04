package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AlgorithmSpec {

    private String filename;
    private AssetSource source;
    private String providerConnectorUrl;

    private AlgorithmSpec() {}

    public String getFilename() { return filename; }

    public AssetSource getSource() { return source; }

    public String getProviderConnectorUrl() { return providerConnectorUrl; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final AlgorithmSpec instance = new AlgorithmSpec();

        public Builder filename(String filename) { instance.filename = filename; return this; }

        public Builder source(AssetSource source) { instance.source = source; return this; }

        public Builder providerConnectorUrl(String url) { instance.providerConnectorUrl = url; return this; }

        public AlgorithmSpec build() { return instance; }
    }
}
