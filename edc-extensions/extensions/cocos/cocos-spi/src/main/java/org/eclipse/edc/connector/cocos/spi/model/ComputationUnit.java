package org.eclipse.edc.connector.cocos.spi.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class ComputationUnit {

    private String vmIp;
    private ComputeManifest manifest;

    private ComputationUnit() {}

    public String getVmIp() { return vmIp; }

    public ComputeManifest getManifest() { return manifest; }

    public static Builder newInstance() { return new Builder(); }

    public static class Builder {
        private final ComputationUnit instance = new ComputationUnit();

        public Builder vmIp(String vmIp) { instance.vmIp = vmIp; return this; }

        public Builder manifest(ComputeManifest manifest) { instance.manifest = manifest; return this; }

        public ComputationUnit build() { return instance; }
    }
}
