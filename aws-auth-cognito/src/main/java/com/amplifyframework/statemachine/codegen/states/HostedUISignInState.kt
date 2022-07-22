/*
 * Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amplifyframework.statemachine.codegen.states

import com.amplifyframework.statemachine.State
import com.amplifyframework.statemachine.StateMachineEvent
import com.amplifyframework.statemachine.StateMachineResolver
import com.amplifyframework.statemachine.StateResolution

sealed class HostedUISignInState : State {
    data class NotStarted(val id: String = "") : HostedUISignInState()
    data class ShowingUI(val id: String = "") : HostedUISignInState()
    data class FetchingToken(val id: String = "") : HostedUISignInState()
    data class Done(val id: String = "") : HostedUISignInState()
    data class Error(val exception: Exception) : HostedUISignInState()

    class Resolver() : StateMachineResolver<HostedUISignInState> {
        override val defaultState = NotStarted()

        // TODO Implement Resolver
        override fun resolve(
            oldState: HostedUISignInState,
            event: StateMachineEvent
        ): StateResolution<HostedUISignInState> {
            return StateResolution(oldState)
        }
    }
}
