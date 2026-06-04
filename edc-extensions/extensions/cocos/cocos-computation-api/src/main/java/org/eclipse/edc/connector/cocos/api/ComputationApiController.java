package org.eclipse.edc.connector.cocos.api;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.edc.connector.cocos.spi.ComputationOrchestrator;
import org.eclipse.edc.connector.cocos.spi.model.ComputationRequest;

import java.util.Map;

@Consumes({MediaType.APPLICATION_JSON})
@Produces({MediaType.APPLICATION_JSON})
@Path("/cocos")
public class ComputationApiController {

    private final ComputationOrchestrator orchestrator;

    public ComputationApiController(ComputationOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @POST
    @Path("/computations")
    public Response startComputation(ComputationRequest request) {
        var jobId = orchestrator.start(request);
        return Response.accepted(Map.of("jobId", jobId)).build();
    }

    @GET
    @Path("/computations/{jobId}")
    public Response getComputation(@PathParam("jobId") String jobId) {
        return orchestrator.getJob(jobId)
                .map(job -> Response.ok(Map.of(
                        "jobId", job.getJobId(),
                        "status", job.getStatus().name()
                )).build())
                .orElse(Response.status(Response.Status.NOT_FOUND).build());
    }
}
