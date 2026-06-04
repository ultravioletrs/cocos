package org.eclipse.edc.connector.cocos.datasink;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.dataplane.spi.pipeline.DataSink;
import org.eclipse.edc.connector.dataplane.spi.pipeline.DataSource;
import org.eclipse.edc.connector.dataplane.spi.pipeline.StreamResult;
import org.eclipse.edc.spi.monitor.Monitor;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

public class CocosVmDataSink implements DataSink {

    public enum AssetKind { DATASET, ALGORITHM }

    private final String vmIp;
    private final String filename;
    private final AssetKind assetKind;
    private final CocosCliService cliService;
    private final ExecutorService executorService;
    private final Monitor monitor;

    public CocosVmDataSink(String vmIp, String filename, AssetKind assetKind,
                            CocosCliService cliService, ExecutorService executorService, Monitor monitor) {
        this.vmIp = vmIp;
        this.filename = filename;
        this.assetKind = assetKind;
        this.cliService = cliService;
        this.executorService = executorService;
        this.monitor = monitor;
    }

    @Override
    public CompletableFuture<StreamResult<Object>> transfer(DataSource source) {
        return CompletableFuture.supplyAsync(() -> {
            var partsResult = source.openPartStream();
            if (partsResult.failed()) {
                return StreamResult.error("Failed to open data source: " + String.join(", ", partsResult.getFailureMessages()));
            }

            try (var parts = partsResult.getContent()) {
                var part = parts.findFirst().orElse(null);
                if (part == null) {
                    return StreamResult.error("Data source contained no parts");
                }

                byte[] data;
                try {
                    data = part.openStream().readAllBytes();
                } catch (IOException e) {
                    return StreamResult.error("Failed to read data part: " + e.getMessage());
                }

                var result = assetKind == AssetKind.DATASET
                        ? cliService.uploadDataset(vmIp, filename, data)
                        : cliService.uploadAlgorithm(vmIp, filename, data);

                if (result.failed()) {
                    return StreamResult.error("CLI upload to " + vmIp + " failed: " + result.getFailureDetail());
                }

                monitor.debug("Uploaded " + filename + " to CocosAI VM " + vmIp);
                return StreamResult.success();
            }
        }, executorService);
    }
}
