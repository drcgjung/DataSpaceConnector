/*
 *  Copyright (c) 2022 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Bayerische Motoren Werke Aktiengesellschaft (BMW AG) - initial API and implementation
 *       Fraunhofer Institute for Software and Systems Engineering - expending Event classes
 *
 */

package org.eclipse.edc.spi.event.contractnegotiation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

/**
 * This event is raised when the ContractNegotiation has been confirmed.
 *
 * @deprecated please use {@link ContractNegotiationAgreed}
 */
@Deprecated(since = "milestone9")
@JsonDeserialize(builder = ContractNegotiationConfirmed.Builder.class)
public class ContractNegotiationConfirmed extends ContractNegotiationEvent {

    private ContractNegotiationConfirmed() {
    }

    @Override
    public String name() {
        return "contract.negotiation.confirmed";
    }

    @JsonPOJOBuilder(withPrefix = "")
    public static class Builder extends ContractNegotiationEvent.Builder<ContractNegotiationConfirmed, Builder> {

        @JsonCreator
        private Builder() {
            super(new ContractNegotiationConfirmed());
        }

        public static Builder newInstance() {
            return new Builder();
        }

        @Override
        public Builder self() {
            return this;
        }
    }
}
