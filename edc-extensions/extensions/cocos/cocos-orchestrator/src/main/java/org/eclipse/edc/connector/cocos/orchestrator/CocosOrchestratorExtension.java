package org.eclipse.edc.connector.cocos.orchestrator;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.cocos.spi.ComputationJobStore;
import org.eclipse.edc.connector.cocos.spi.ComputationOrchestrator;
import org.eclipse.edc.connector.cocos.spi.RemoteAssetFetcher;
import org.eclipse.edc.http.spi.EdcHttpClient;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provider;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

import java.util.concurrent.Executors;

@Extension(CocosOrchestratorExtension.NAME)
public class CocosOrchestratorExtension implements ServiceExtension {

    public static final String NAME = "CocosAI Orchestrator";

    @Inject
    private CocosCliService cliService;

    @Inject
    private EdcHttpClient httpClient;

    private InMemoryComputationJobStore jobStore;

    @Override
    public String name() {
        return NAME;
    }

    @Override
    public void initialize(ServiceExtensionContext context) {
        jobStore = new InMemoryComputationJobStore();
    }

    @Provider
    public ComputationJobStore computationJobStore() {
        return jobStore;
    }

    @Provider
    public ComputationOrchestrator computationOrchestrator(ServiceExtensionContext context) {
        var mapper = new ObjectMapper();
        var monitor = context.getMonitor();
        var callbackClient = new TowerCallbackClient(httpClient, mapper, monitor);
        var executor = Executors.newCachedThreadPool();
        var remoteAssetFetcher = new StubRemoteAssetFetcher();
        return new ComputationOrchestratorImpl(cliService, jobStore, remoteAssetFetcher, callbackClient, executor, monitor);
    }
}
