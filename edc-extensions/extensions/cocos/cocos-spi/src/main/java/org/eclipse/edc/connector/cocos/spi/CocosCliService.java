package org.eclipse.edc.connector.cocos.spi;

import org.eclipse.edc.connector.cocos.spi.model.ComputeManifest;
import org.eclipse.edc.spi.result.Result;

public interface CocosCliService {

    Result<Void> startAgent(String vmIp, ComputeManifest manifest);

    Result<Void> uploadDataset(String vmIp, String filename, byte[] data);

    Result<Void> uploadAlgorithm(String vmIp, String filename, byte[] data);

    Result<byte[]> requestAttestation(String vmIp, String nonce);

    Result<byte[]> fetchResult(String vmIp);
}
