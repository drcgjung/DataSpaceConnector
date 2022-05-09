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

package org.eclipse.dataspaceconnector.receiver.http;

import net.jodah.failsafe.RetryPolicy;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.eclipse.dataspaceconnector.spi.EdcException;
import org.eclipse.dataspaceconnector.spi.monitor.Monitor;
import org.eclipse.dataspaceconnector.spi.result.Result;
import org.eclipse.dataspaceconnector.spi.transfer.edr.EndpointDataReferenceReceiver;
import org.eclipse.dataspaceconnector.spi.types.TypeManager;
import org.eclipse.dataspaceconnector.spi.types.domain.edr.EndpointDataReference;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import static net.jodah.failsafe.Failsafe.with;
import static org.eclipse.dataspaceconnector.common.string.StringUtils.isNullOrBlank;

/**
 * Implementation of a {@link org.eclipse.dataspaceconnector.spi.transfer.edr.EndpointDataReferenceReceiver} that posts
 * the {@link org.eclipse.dataspaceconnector.spi.types.domain.edr.EndpointDataReference} to an existing http endpoint.
 */
public class HttpEndpointDataReferenceReceiver implements EndpointDataReferenceReceiver {

    private static final MediaType JSON = MediaType.get("application/json");

    private Monitor monitor;
    private OkHttpClient httpClient;
    private TypeManager typeManager;
    private RetryPolicy<Object> retryPolicy;
    private String endpoint;
    private String authKey;
    private String authToken;

    private HttpEndpointDataReferenceReceiver() {
    }

    @Override
    public CompletableFuture<Result<Void>> send(@NotNull EndpointDataReference edr) {
        String payload = typeManager.writeValueAsString(edr);
        monitor.debug(String.format("About to send endpoint data reference to %s (%s,%s) - %s", endpoint, authKey, authToken, payload));
        var requestBody = RequestBody.create(payload, JSON);
        String[] endpoints = endpoint.split(",");
        boolean success = false;
        String reason = "Endpoint could not be contacted.";
        for (String endpoint : endpoints) {
            var requestBuilder = new Request.Builder().url(endpoint).post(requestBody);
            if (!isNullOrBlank(authKey) && !isNullOrBlank(authToken)) {
                requestBuilder.header(authKey, authToken);
            }
            try (var response = with(retryPolicy).get(() -> httpClient.newCall(requestBuilder.build()).execute())) {
                if (response.isSuccessful()) {
                    var body = response.body();
                    if (body == null) {
                        reason = String.format("Received empty response body when receiving endpoint data reference with id: %s", edr.getCorrelationId());
                        monitor.warning(reason);
                    } else {
                        monitor.info(String.format("Successfully contacted endpoint %s", endpoint));
                        success = true;
                    }
                } else {
                    reason = String.format("Received error code %s when transferring endpoint data reference with id: %s", response.code(), edr.getCorrelationId());
                    monitor.warning(reason);
                }
            }
        }
        if (success) {
            return CompletableFuture.completedFuture(Result.success());
        } else {
            throw new EdcException(reason);
        }
    }

    public static class Builder {
        private final HttpEndpointDataReferenceReceiver receiver;

        public static Builder newInstance() {
            return new Builder();
        }

        public Builder monitor(Monitor monitor) {
            receiver.monitor = monitor;
            return this;
        }

        public Builder httpClient(OkHttpClient httpClient) {
            receiver.httpClient = httpClient;
            return this;
        }

        public Builder typeManager(TypeManager typeManager) {
            receiver.typeManager = typeManager;
            return this;
        }

        public Builder retryPolicy(RetryPolicy<Object> retryPolicy) {
            receiver.retryPolicy = retryPolicy;
            return this;
        }

        public Builder endpoint(String endpoint) {
            receiver.endpoint = endpoint;
            return this;
        }

        public Builder authHeader(String key, String code) {
            receiver.authKey = key;
            receiver.authToken = code;
            return this;
        }

        public HttpEndpointDataReferenceReceiver build() {
            Objects.requireNonNull(receiver.monitor, "monitor");
            Objects.requireNonNull(receiver.endpoint, "endpoint");
            Objects.requireNonNull(receiver.httpClient, "httpClient");
            Objects.requireNonNull(receiver.typeManager, "typeManager");
            Objects.requireNonNull(receiver.retryPolicy, "retryPolicy");
            return receiver;
        }

        private Builder() {
            receiver = new HttpEndpointDataReferenceReceiver();
        }
    }
}
