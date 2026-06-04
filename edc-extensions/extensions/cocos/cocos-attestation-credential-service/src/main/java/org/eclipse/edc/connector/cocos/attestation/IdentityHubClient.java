package org.eclipse.edc.connector.cocos.attestation;

import org.eclipse.edc.iam.verifiablecredentials.spi.model.VerifiablePresentationContainer;
import org.eclipse.edc.spi.result.Result;

import java.util.List;

public interface IdentityHubClient {

    Result<String> requestNonce();

    // TODO: replace parameter list when CW API is finalised next week
    Result<List<VerifiablePresentationContainer>> requestPresentation(
            String participantContextId,
            String ownDid,
            String counterPartyDid,
            String counterPartyToken,
            List<String> scopes,
            byte[] attestationReport);
}
