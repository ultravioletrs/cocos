package org.eclipse.edc.connector.cocos.spi;

import org.eclipse.edc.connector.cocos.spi.model.ComputationJob;

import java.util.Optional;

public interface ComputationJobStore {

    void save(ComputationJob job);

    Optional<ComputationJob> findById(String jobId);

    Optional<ComputationJob> findActiveJobForVm(String vmIp);
}
