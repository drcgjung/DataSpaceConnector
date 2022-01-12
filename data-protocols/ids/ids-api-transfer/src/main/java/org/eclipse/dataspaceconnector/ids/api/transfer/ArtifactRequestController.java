/*
 *  Copyright (c) 2020, 2021 Microsoft Corporation
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Microsoft Corporation - initial API and implementation
 *
 */

package org.eclipse.dataspaceconnector.ids.api.transfer;

import de.fraunhofer.iais.eis.ArtifactRequestMessage;
import de.fraunhofer.iais.eis.ArtifactResponseMessageBuilder;
import de.fraunhofer.iais.eis.RejectionMessageBuilder;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.dataspaceconnector.ids.spi.daps.DapsService;
import org.eclipse.dataspaceconnector.spi.iam.VerificationResult;
import org.eclipse.dataspaceconnector.ids.spi.policy.IdsPolicyService;
import org.eclipse.dataspaceconnector.policy.model.Policy;
import org.eclipse.dataspaceconnector.spi.asset.AssetIndex;
import org.eclipse.dataspaceconnector.spi.types.domain.asset.Asset;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.policy.PolicyRegistry;
import org.eclipse.dataspaceconnector.policy.engine.PolicyEvaluationResult;
import org.eclipse.dataspaceconnector.spi.security.Vault;
import org.eclipse.dataspaceconnector.spi.transfer.TransferProcessManager;
import org.eclipse.dataspaceconnector.spi.types.domain.transfer.DataAddress;
import org.eclipse.dataspaceconnector.spi.types.domain.transfer.DataRequest;

import java.util.AbstractMap;
import java.util.Map;

import static de.fraunhofer.iais.eis.RejectionReason.BAD_PARAMETERS;
import static de.fraunhofer.iais.eis.RejectionReason.NOT_AUTHENTICATED;
import static de.fraunhofer.iais.eis.RejectionReason.NOT_AUTHORIZED;
import static de.fraunhofer.iais.eis.RejectionReason.NOT_FOUND;
import static de.fraunhofer.iais.eis.RejectionReason.TEMPORARILY_NOT_AVAILABLE;
import static java.util.UUID.randomUUID;
import static org.eclipse.dataspaceconnector.ids.spi.Protocols.IDS_REST;

/**
 * Receives incoming data transfer requests and processes them.
 */
@Consumes({ MediaType.APPLICATION_JSON })
@Produces({ MediaType.APPLICATION_JSON })
@Path("/ids")
public class ArtifactRequestController {
    private static final String TOKEN_KEY = "dataspaceconnector-destination-token";
    private static final String DESTINATION_KEY = "dataspaceconnector-data-destination";

    private final DapsService dapsService;
    private final AssetIndex assetIndex;
    private final TransferProcessManager processManager;
    private final IdsPolicyService policyService;
    private final PolicyRegistry policyRegistry;
    private final Vault vault;
    private final Monitor monitor;

    public ArtifactRequestController(DapsService dapsService,
                                     AssetIndex assetIndex,
                                     TransferProcessManager processManager,
                                     IdsPolicyService policyService,
                                     PolicyRegistry policyRegistry,
                                     Vault vault,
                                     Monitor monitor) {
        this.dapsService = dapsService;
        this.assetIndex = assetIndex;
        this.processManager = processManager;
        this.policyService = policyService;
        this.policyRegistry = policyRegistry;
        this.vault = vault;
        this.monitor = monitor;
    }

    /**
     * a dedicated exception which carries an http response with it
     */
    public static class ResponseException extends Exception {
        Response response;

        public ResponseException(Response response) {
            this.response=response;
        }

        public Response getResponse() {
            return response;
        }
    }

    /**
     * refactored token verification
     * @param message request message
     * @return successful verification result
     * @throws ResponseException in case verification failed
     */
    protected VerificationResult verifyMessage(ArtifactRequestMessage message) throws ResponseException {
        var verificationResult = dapsService.verifyAndConvertToken(message.getSecurityToken().getTokenValue());
        if (!verificationResult.valid()) {
            monitor.info(() -> "verification failed for request " + message.getId());
            throw new ResponseException(Response.status(Response.Status.FORBIDDEN).entity(new RejectionMessageBuilder()._rejectionReason_(NOT_AUTHENTICATED).build()).build());
        }
        return verificationResult;
    }

    /**
     * refactored method to resolve the given asset and a policy
     * @param dataUrn
     * @return associated asset
     */
    protected Asset resolveAsset(String dataUrn) {
        return assetIndex.findById(dataUrn);
    }

    /**
     * resolve policy for asset
     * @param asset
     * @return policy associated to asset
     */
    protected Policy resolvePolicy(Asset asset) {
        if (asset != null) {
            return policyRegistry.resolvePolicy(asset.getPolicyId());
        }
        return null;
    }

    /**
     * evaluates the policy
     * @param policy
     * @param consumerConnectorId
     * @param correlationId
     * @param verificationResult
     * @return policy evaluation result (success and failure)
     */
    protected PolicyEvaluationResult evaluatePolicy(ArtifactRequestMessage message, Policy policy, String consumerConnectorId, String correlationId, VerificationResult verificationResult) {
        return policyService.evaluateRequest(consumerConnectorId, correlationId, verificationResult.token(), policy);
    }

    /**
     * refactored asset resolution and policy verification
     * @param message request message
     * @return a pair of the resolved asset and an optional failure response
     */
    protected Asset resolveAndVerifyAsset(ArtifactRequestMessage message, VerificationResult verificationResult) throws ResponseException {
        var dataUrn = message.getRequestedArtifact().toString();
        monitor.debug(() -> "Received artifact request for: " + dataUrn);

        var asset= resolveAsset(dataUrn);
        if (asset == null) {
            throw new ResponseException(Response.status(Response.Status.BAD_REQUEST).entity(new RejectionMessageBuilder()._rejectionReason_(NOT_FOUND).build()).build());
        }
        var policy = resolvePolicy(asset);

        if (policy == null) {
            monitor.severe("Policy not found for artifact: " + dataUrn);
            throw new ResponseException(Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new RejectionMessageBuilder()._rejectionReason_(TEMPORARILY_NOT_AVAILABLE).build()).build());
        }

        var consumerConnectorId = message.getIssuerConnector().toString();
        var correlationId = message.getId().toString();
        var policyResult =  evaluatePolicy(message, policy,consumerConnectorId,correlationId,verificationResult);

        if (!policyResult.valid()) {
            monitor.info("Policy evaluation failed");
            throw new ResponseException(Response.status(Response.Status.FORBIDDEN).entity(new RejectionMessageBuilder()._rejectionReason_(NOT_AUTHORIZED).build()).build());
        }

        return asset;
    }

    /**
     * refactored the construction of the internal data request
     * @param message incoming request message
     * @param asset resolved asset
     * @return the completed data request
     */
    protected DataRequest buildDataRequest(ArtifactRequestMessage message, Asset asset) {
        // TODO this needs to be deserialized from the artifact request message
        var destinationMap = (Map<String, Object>) message.getProperties().get(ArtifactRequestController.DESTINATION_KEY);
        var type = (String) destinationMap.get("type");

        Map<String, String> properties = (Map<String, String>) destinationMap.get("properties");
        var secretName = (String) destinationMap.get("keyName");

        var destinationToken = (String) message.getProperties().get(ArtifactRequestController.TOKEN_KEY);

        if (destinationToken != null) {
            vault.storeSecret(secretName, destinationToken);
        }

        var dataDestination = DataAddress.Builder.newInstance().type(type).properties(properties).keyName(secretName).build();

        var dataRequest = DataRequest.Builder.newInstance().id(randomUUID().toString()).assetId(asset.getId()).dataDestination(dataDestination).protocol(IDS_REST).build();
        return dataRequest;
    }

    /**
     * refactored the internal submission of a data request
     * @param dataRequest
     * @return response
     */
    protected Response performDataRequest(DataRequest dataRequest) {
        var response = processManager.initiateProviderRequest(dataRequest);

        switch (response.getStatus()) {
            case OK:
                monitor.info("Data transfer request initiated");
                ArtifactResponseMessageBuilder messageBuilder = new ArtifactResponseMessageBuilder();
                return Response.ok().entity(messageBuilder.build()).build();
            case FATAL_ERROR:
                return Response.status(Response.Status.BAD_REQUEST).entity(new RejectionMessageBuilder()._rejectionReason_(BAD_PARAMETERS).build()).build();
            default:
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(new RejectionMessageBuilder()._rejectionReason_(TEMPORARILY_NOT_AVAILABLE).build()).build();
        }
    }

    /**
     * receives a remote request
     * @param message as a payload
     * @return response indicating the processing status
     */
    @POST
    @Path("request")
    public Response request(ArtifactRequestMessage message) {
        try {
            var verificationResult=verifyMessage(message);
            var asset = resolveAndVerifyAsset(message,verificationResult);
            var dataRequest = buildDataRequest(message,asset);

            return performDataRequest(dataRequest);
        } catch(ResponseException re) {
            return re.getResponse();
        }
    }

}
