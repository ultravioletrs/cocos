package org.eclipse.edc.connector.cocos.datasink;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.dataplane.spi.pipeline.DataSink;
import org.eclipse.edc.connector.dataplane.spi.pipeline.DataSinkFactory;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;
import org.eclipse.edc.spi.types.domain.transfer.DataFlowStartMessage;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.ExecutorService;

public class CocosVmDataSinkFactory implements DataSinkFactory {

    public static final String COCOS_VM_TYPE = "CocosVm";
    public static final String PROP_VM_IP = "cocos.vm.ip";
    public static final String PROP_FILENAME = "cocos.filename";
    public static final String PROP_ASSET_KIND = "cocos.asset.kind";

    private final CocosCliService cliService;
    private final ExecutorService executorService;
    private final Monitor monitor;

    public CocosVmDataSinkFactory(CocosCliService cliService, ExecutorService executorService, Monitor monitor) {
        this.cliService = cliService;
        this.executorService = executorService;
        this.monitor = monitor;
    }

    @Override
    public String supportedType() {
        return COCOS_VM_TYPE;
    }

    @Override
    public @NotNull Result<Void> validateRequest(DataFlowStartMessage request) {
        var address = request.getDestinationDataAddress();
        if (address.getStringProperty(PROP_VM_IP) == null) {
            return Result.failure("Missing required destination property: " + PROP_VM_IP);
        }
        if (address.getStringProperty(PROP_FILENAME) == null) {
            return Result.failure("Missing required destination property: " + PROP_FILENAME);
        }
        return Result.success();
    }

    @Override
    public DataSink createSink(DataFlowStartMessage request) {
        var address = request.getDestinationDataAddress();
        var vmIp = address.getStringProperty(PROP_VM_IP);
        var filename = address.getStringProperty(PROP_FILENAME);
        var kindStr = address.getStringProperty(PROP_ASSET_KIND, CocosVmDataSink.AssetKind.DATASET.name());
        var assetKind = CocosVmDataSink.AssetKind.valueOf(kindStr);
        return new CocosVmDataSink(vmIp, filename, assetKind, cliService, executorService, monitor);
    }
}
