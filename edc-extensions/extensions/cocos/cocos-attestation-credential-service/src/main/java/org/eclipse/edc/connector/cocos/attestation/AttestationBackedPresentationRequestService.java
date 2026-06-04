package org.eclipse.edc.connector.cocos.attestation;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.connector.cocos.spi.CocosContextHolder;
import org.eclipse.edc.iam.decentralizedclaims.spi.PresentationRequestService;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiablePresentationContainer;
import org.eclipse.edc.spi.monitor.Monitor;
import org.eclipse.edc.spi.result.Result;

import java.util.List;

public class AttestationBackedPresentationRequestService implements PresentationRequestService {

    private final CocosCliService cliService;
    private final IdentityHubClient identityHubClient;
    private final Monitor monitor;

    public AttestationBackedPresentationRequestService(CocosCliService cliService,
                                                       IdentityHubClient identityHubClient,
                                                       Monitor monitor) {
        this.cliService = cliService;
        this.identityHubClient = identityHubClient;
        this.monitor = monitor;
    }

    @Override
    public Result<List<VerifiablePresentationContainer>> requestPresentation(
            String participantContextId,
            String ownDid,
            String counterPartyDid,
            String counterPartyToken,
            List<String> scopes) {

        var nonceResult = identityHubClient.requestNonce();
        if (nonceResult.failed()) {
            return Result.failure("Failed to obtain nonce from Identity Hub: " + nonceResult.getFailureDetail());
        }

        var vmIp = CocosContextHolder.getActiveVmIp().orElse(null);
        if (vmIp == null) {
            return Result.failure("No active CocosAI VM in context — attestation cannot proceed");
        }

        var attestationResult = cliService.requestAttestation(vmIp, nonceResult.getContent());
        if (attestationResult.failed()) {
            return Result.failure("Failed to obtain attestation report from VM " + vmIp
                    + ": " + attestationResult.getFailureDetail());
        }

        monitor.debug("Obtained attestation report from " + vmIp + ", requesting VP from Identity Hub");

        return identityHubClient.requestPresentation(
                participantContextId,
                ownDid,
                counterPartyDid,
                counterPartyToken,
                scopes,
                attestationResult.getContent());
    }
}
