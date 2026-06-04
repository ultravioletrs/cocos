package org.eclipse.edc.connector.cocos.attestation;

import org.eclipse.edc.connector.cocos.spi.CocosCliService;
import org.eclipse.edc.http.spi.EdcHttpClient;
import org.eclipse.edc.iam.decentralizedclaims.spi.PresentationRequestService;
import org.eclipse.edc.runtime.metamodel.annotation.Extension;
import org.eclipse.edc.runtime.metamodel.annotation.Inject;
import org.eclipse.edc.runtime.metamodel.annotation.Provider;
import org.eclipse.edc.runtime.metamodel.annotation.Setting;
import org.eclipse.edc.spi.system.ServiceExtension;
import org.eclipse.edc.spi.system.ServiceExtensionContext;

@Extension(CocosAttestationExtension.NAME)
public class CocosAttestationExtension implements ServiceExtension {

    public static final String NAME = "CocosAI Attestation Credential Service";

    @Setting(description = "Base URL of the CocosAI Identity Hub (CW)", key = "cocos.identity.hub.url", required = true)
    private String identityHubUrl;

    @Inject
    private CocosCliService cliService;

    @Inject
    private EdcHttpClient httpClient;

    @Override
    public String name() {
        return NAME;
    }

    @Provider
    public PresentationRequestService presentationRequestService(ServiceExtensionContext context) {
        var identityHubClient = new IdentityHubClientImpl(httpClient, identityHubUrl);
        return new AttestationBackedPresentationRequestService(cliService, identityHubClient, context.getMonitor());
    }
}
