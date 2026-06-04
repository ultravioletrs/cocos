package org.eclipse.edc.connector.cocos.spi;

import java.util.concurrent.CompletableFuture;

public interface RemoteAssetFetcher {

    CompletableFuture<byte[]> fetch(String providerConnectorUrl, String assetUrl);
}
