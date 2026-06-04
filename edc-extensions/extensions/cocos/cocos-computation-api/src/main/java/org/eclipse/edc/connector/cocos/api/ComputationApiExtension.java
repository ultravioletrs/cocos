package org.eclipse.edc.connector.cocos.api;

import org.eclipse.edc.connector.cocos.spi.ComputationOrchestrator;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;
import org.eclipse.edc.web.spi.WebService;

@Extension(ComputationApiExtension.NAME)
public class ComputationApiExtension implements ServiceExtension {

    public static final String NAME = "CocosAI Computation API";

    @Inject
    private WebService webService;

    @Inject
    private ComputationOrchestrator orchestrator;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        webService.registerResource("management", new ComputationApiController(orchestrator));
    }
}
