package org.eclipse.edc.connector.cocos.attestation;

import org.eclipse.edc.http.spi.EdcHttpClient;
import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiablePresentationContainer;
import org.eclipse.edc.spi.result.Result;

import java.util.List;

public class IdentityHubClientImpl implements IdentityHubClient {

    private final EdcHttpClient httpClient;
    private final String identityHubBaseUrl;

    public IdentityHubClientImpl(EdcHttpClient httpClient, String identityHubBaseUrl) {
        this.httpClient = httpClient;
        this.identityHubBaseUrl = identityHubBaseUrl;
    }

    @Override
    public Result<String> requestNonce() {
        // TODO: implement GET {identityHubBaseUrl}/nonce when CW API is finalised
        return Result.failure("Identity Hub nonce API not yet implemented — pending CW API finalisation");
    }

    @Override
    public Result<List<VerifiablePresentationContainer>> requestPresentation(
            String participantContextId,
            String ownDid,
            String counterPartyDid,
            String counterPartyToken,
            List<String> scopes,
            byte[] attestationReport) {
        // TODO: implement POST {identityHubBaseUrl}/presentations with attestation report when CW API is finalised
        return Result.failure("Identity Hub presentation API not yet implemented — pending CW API finalisation");
    }
}
