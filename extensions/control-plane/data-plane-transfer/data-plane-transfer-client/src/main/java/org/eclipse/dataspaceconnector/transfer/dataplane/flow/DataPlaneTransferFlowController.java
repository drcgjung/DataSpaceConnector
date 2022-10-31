/*
 *  Copyright (c) 2022 Amadeus
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Amadeus - initial API and implementation
 *
 */

package org.eclipse.dataspaceconnector.transfer.dataplane.flow;

import org.eclipse.dataspaceconnector.common.string.StringUtils;
import org.eclipse.dataspaceconnector.policy.model.Policy;
import org.eclipse.dataspaceconnector.spi.response.ResponseStatus;
import org.eclipse.dataspaceconnector.spi.response.StatusResult;
import org.eclipse.dataspaceconnector.spi.transfer.callback.ControlPlaneApiUrl;
import org.eclipse.dataspaceconnector.spi.transfer.flow.DataFlowController;
import org.eclipse.dataspaceconnector.spi.types.domain.DataAddress;
import org.eclipse.dataspaceconnector.spi.types.domain.transfer.DataFlowRequest;
import org.eclipse.dataspaceconnector.spi.types.domain.transfer.DataRequest;
import org.eclipse.dataspaceconnector.transfer.dataplane.spi.DataPlaneTransferConstants;
import org.eclipse.dataspaceconnector.transfer.dataplane.spi.client.DataPlaneTransferClient;
import org.jetbrains.annotations.NotNull;

import java.util.UUID;

import static org.eclipse.dataspaceconnector.transfer.dataplane.spi.DataPlaneTransferConstants.HTTP_PROXY;

/**
 * Implementation of {@link DataFlowController} that delegates data transfer to Data Plane instance.
 * Note that Data Plane can be embedded in current runtime (test, samples...) or accessed remotely.
 * The present {@link DataFlowController} is triggered when destination type in the {@link DataRequest} is different from
 * {@link DataPlaneTransferConstants#HTTP_PROXY}, as this one is reserved for synchronous data transfers.
 */
public class DataPlaneTransferFlowController implements DataFlowController {
    private final DataPlaneTransferClient client;
    private final ControlPlaneApiUrl callbackUrl;

    public DataPlaneTransferFlowController(DataPlaneTransferClient client, ControlPlaneApiUrl callbackUrl) {
        this.client = client;
        this.callbackUrl = callbackUrl;
    }

    @Override
    public boolean canHandle(DataRequest dataRequest, DataAddress contentAddress) {
        var type = dataRequest.getDestinationType();
        if (!StringUtils.isNullOrBlank(type)) {
            return !HTTP_PROXY.equals(dataRequest.getDestinationType());
        }
        return false;
    }

    @Override
    public @NotNull StatusResult<Void> initiateFlow(DataRequest dataRequest, DataAddress contentAddress, Policy policy) {
        var dataFlowRequest = createRequest(dataRequest, contentAddress);
        var result = client.transfer(dataFlowRequest);
        if (result.failed()) {
            return StatusResult.failure(ResponseStatus.FATAL_ERROR,
                    "Failed to delegate data transfer to Data Plane: " + String.join(", ", result.getFailureMessages()));
        }
        return StatusResult.success();
    }

    private DataFlowRequest createRequest(DataRequest dataRequest, DataAddress sourceAddress) {
        return DataFlowRequest.Builder.newInstance()
                .id(UUID.randomUUID().toString())
                .processId(dataRequest.getProcessId())
                .trackable(true)
                .sourceDataAddress(sourceAddress)
                .destinationType(dataRequest.getDestinationType())
                .destinationDataAddress(dataRequest.getDataDestination())
                .callbackAddress(callbackUrl != null ? callbackUrl.get() : null)
                .properties(dataRequest.getProperties())
                .build();
    }
}
