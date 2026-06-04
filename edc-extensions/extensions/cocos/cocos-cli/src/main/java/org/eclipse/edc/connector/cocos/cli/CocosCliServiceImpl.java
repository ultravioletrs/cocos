package org.eclipse.edc.connector.cocos.cli;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.cocos.spi.model.ComputeManifest;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;

public class CocosCliServiceImpl implements CocosCliService {

    private final String cliBinaryPath;
    private final Monitor monitor;

    public CocosCliServiceImpl(String cliBinaryPath, Monitor monitor) {
        this.cliBinaryPath = cliBinaryPath;
        this.monitor = monitor;
    }

    @Override
    public Result<Void> startAgent(String vmIp, ComputeManifest manifest) {
        // TODO: implement using ProcessBuilder when CLI command is finalised
        throw new UnsupportedOperationException("startAgent CLI command not yet defined");
    }

    @Override
    public Result<Void> uploadDataset(String vmIp, String filename, byte[] data) {
        // TODO: implement using ProcessBuilder when CLI command is finalised
        throw new UnsupportedOperationException("uploadDataset CLI command not yet defined");
    }

    @Override
    public Result<Void> uploadAlgorithm(String vmIp, String filename, byte[] data) {
        // TODO: implement using ProcessBuilder when CLI command is finalised
        throw new UnsupportedOperationException("uploadAlgorithm CLI command not yet defined");
    }

    @Override
    public Result<byte[]> requestAttestation(String vmIp, String nonce) {
        // TODO: implement using ProcessBuilder when CLI command is finalised
        throw new UnsupportedOperationException("requestAttestation CLI command not yet defined");
    }

    @Override
    public Result<byte[]> fetchResult(String vmIp) {
        // TODO: implement using ProcessBuilder when CLI command is finalised
        throw new UnsupportedOperationException("fetchResult CLI command not yet defined");
    }
}
