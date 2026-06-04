package org.eclipse.edc.connector.cocos.orchestrator;

import org.eclipse.edc.connector.cocos.spi.ComputationJobStore;
import org.eclipse.edc.connector.cocos.spi.model.ComputationJob;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryComputationJobStore implements ComputationJobStore {

    private final ConcurrentHashMap<String, ComputationJob> store = new ConcurrentHashMap<>();

    @Override
    public void save(ComputationJob job) {
        store.put(job.getJobId(), job);
    }

    @Override
    public Optional<ComputationJob> findById(String jobId) {
        return Optional.ofNullable(store.get(jobId));
    }

    @Override
    public Optional<ComputationJob> findActiveJobForVm(String vmIp) {
        return store.values().stream()
                .filter(job -> job.getStatus() != ComputationJob.Status.COMPLETED
                        && job.getStatus() != ComputationJob.Status.FAILED)
                .filter(job -> job.getUnits().stream().anyMatch(u -> u.getVmIp().equals(vmIp)))
                .findFirst();
    }
}
