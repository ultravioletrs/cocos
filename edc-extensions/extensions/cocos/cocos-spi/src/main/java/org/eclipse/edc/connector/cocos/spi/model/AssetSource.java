package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AssetSource {

    public enum Type { FILE, URL }

    private Type type;
    private String url;
    private byte[] content;

    private AssetSource() {}

    public Type getType() { return type; }

    public String getUrl() { return url; }

    public byte[] getContent() { return content; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final AssetSource instance = new AssetSource();

        public Builder type(Type type) { instance.type = type; return this; }

        public Builder url(String url) { instance.url = url; return this; }

        public Builder content(byte[] content) { instance.content = content; return this; }

        public AssetSource build() { return instance; }
    }
}
