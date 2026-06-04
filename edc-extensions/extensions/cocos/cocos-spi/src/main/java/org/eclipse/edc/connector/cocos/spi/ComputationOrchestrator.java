package org.eclipse.edc.connector.cocos.spi;

import org.eclipse.edc.connector.cocos.spi.model.ComputationJob;
import org.eclipse.edc.connector.cocos.spi.model.ComputationRequest;

import java.util.Optional;

public interface ComputationOrchestrator {

    String start(ComputationRequest request);

    Optional<ComputationJob> getJob(String jobId);
}
