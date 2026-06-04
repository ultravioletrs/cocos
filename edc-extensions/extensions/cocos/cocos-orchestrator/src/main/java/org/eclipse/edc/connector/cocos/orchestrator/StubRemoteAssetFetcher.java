package org.eclipse.edc.connector.cocos.orchestrator;

import org.eclipse.edc.connector.cocos.spi.RemoteAssetFetcher;

import java.util.concurrent.CompletableFuture;

public class StubRemoteAssetFetcher implements RemoteAssetFetcher {

    @Override
    public CompletableFuture<byte[]> fetch(String providerConnectorUrl, String assetUrl) {
        // TODO: implement full DSP consumer flow:
        //  1. GET catalog from providerConnectorUrl
        //  2. POST contractrequest for the matching offer
        //  3. Initiate transfer process
        //  4. Receive data and return bytes
        //
        // The active CVM IP is available via CocosContextHolder.getActiveVmIp()
        // for wiring into the attestation VP during the DSP credential exchange.
        return CompletableFuture.failedFuture(
                new UnsupportedOperationException("DSP consumer flow not yet implemented"));
    }
}
