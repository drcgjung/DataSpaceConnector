/*
 *  Copyright (c) 2021 Daimler TSS GmbH
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Daimler TSS GmbH - Initial API and Implementation
 *
 */

package org.eclipse.dataspaceconnector.spi.contract;

import org.eclipse.dataspaceconnector.spi.participant.ParticipantAgent;

import java.util.stream.Stream;

/**
 * Returns {@link ContractDefinition} for a given participant agent.
 *
 * A runtime extension may implement custom logic to determine which contract definitions are returned.
 */
public interface ContractOfferFramework {

    /**
     * Returns the definitions for the given participant agent.
     */
    Stream<ContractDefinition> definitionsFor(ParticipantAgent agent);


}
