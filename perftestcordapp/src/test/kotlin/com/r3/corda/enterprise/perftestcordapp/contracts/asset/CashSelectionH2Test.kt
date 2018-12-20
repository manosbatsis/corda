package com.r3.corda.enterprise.perftestcordapp.contracts.asset

import com.r3.corda.enterprise.perftestcordapp.DOLLARS
import com.r3.corda.enterprise.perftestcordapp.POUNDS
import com.r3.corda.enterprise.perftestcordapp.flows.CashException
import com.r3.corda.enterprise.perftestcordapp.flows.CashIssueFlow
import com.r3.corda.enterprise.perftestcordapp.flows.CashPaymentFlow
import net.corda.core.internal.concurrent.transpose
import net.corda.core.utilities.OpaqueBytes
import net.corda.core.utilities.getOrThrow
import net.corda.testing.node.MockNetwork
import net.corda.testing.node.MockNodeConfigOverrides
import net.corda.testing.node.MockNodeParameters
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.After
import org.junit.Test
import java.util.Collections.nCopies

class CashSelectionH2Test {
    private val mockNet = MockNetwork(
            threadPerNode = true,
            cordappPackages = listOf("com.r3.corda.enterprise.perftestcordapp")
    )

    @After
    fun cleanUp() {
        mockNet.stopNodes()
    }

    @Test
    fun `selecting pennies amount larger than max int, which is split across multiple cash states`() {
        val node = mockNet.createNode()
        // The amount has to split across at least two states, probably to trigger the H2 accumulator variable during the
        // spend operation below.
        // Issuing Integer.MAX_VALUE will not cause an exception since PersistentCashState.pennies is a long
        nCopies(2, Integer.MAX_VALUE).map { issueAmount ->
            node.startFlow(CashIssueFlow(issueAmount.POUNDS, OpaqueBytes.of(1), mockNet.defaultNotaryIdentity))
        }.transpose().getOrThrow()
        // The spend must be more than the size of a single cash state to force the accumulator onto the second state.
        node.startFlow(CashPaymentFlow((Integer.MAX_VALUE + 1L).POUNDS, node.info.legalIdentities[0])).getOrThrow()
    }

    @Test
    fun `check does not hold connection over retries`() {
        val bankA = mockNet.createNode(MockNodeParameters(configOverrides = MockNodeConfigOverrides(
            // Tweak connections to be minimal to make this easier (1 results in a hung node during start up, so use 2 connections).
                extraDataSourceProperties = mapOf("maximumPoolSize" to "2"))))
        val notary = mockNet.defaultNotaryIdentity

        // Start more cash spends than we have connections.  If spend leaks a connection on retry, we will run out of connections.
        val flow1 = bankA.startFlow(CashPaymentFlow(amount = 100.DOLLARS, anonymous = false, recipient = notary))
        val flow2 = bankA.startFlow(CashPaymentFlow(amount = 100.DOLLARS, anonymous = false, recipient = notary))
        val flow3 = bankA.startFlow(CashPaymentFlow(amount = 100.DOLLARS, anonymous = false, recipient = notary))

        assertThatThrownBy { flow1.getOrThrow() }.isInstanceOf(CashException::class.java)
        assertThatThrownBy { flow2.getOrThrow() }.isInstanceOf(CashException::class.java)
        assertThatThrownBy { flow3.getOrThrow() }.isInstanceOf(CashException::class.java)
    }
}