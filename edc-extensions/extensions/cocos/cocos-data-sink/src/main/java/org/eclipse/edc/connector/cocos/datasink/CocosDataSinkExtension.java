package org.eclipse.edc.connector.cocos.datasink;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.dataplane.spi.pipeline.DataTransferExecutorServiceContainer;
import org.eclipse.edc.connector.dataplane.spi.pipeline.PipelineService;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

@Extension(CocosDataSinkExtension.NAME)
public class CocosDataSinkExtension implements ServiceExtension {

    public static final String NAME = "CocosAI VM Data Sink";

    @Inject
    private PipelineService pipelineService;

    @Inject
    private DataTransferExecutorServiceContainer executorContainer;

    @Inject
    private CocosCliService cliService;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        var factory = new CocosVmDataSinkFactory(cliService, executorContainer.getExecutorService(), context.getMonitor());
        pipelineService.registerFactory(factory);
    }
}
