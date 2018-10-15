package net.corda.node.flows

import net.corda.core.internal.concurrent.transpose
import net.corda.core.internal.div
import net.corda.core.internal.list
import net.corda.core.internal.moveTo
import net.corda.core.internal.readLines
import net.corda.core.messaging.startTrackedFlow
import net.corda.core.utilities.getOrThrow
import net.corda.node.internal.CheckpointIncompatibleException
import net.corda.node.internal.NodeStartup
import net.corda.node.services.Permissions.Companion.invokeRpc
import net.corda.node.services.Permissions.Companion.startFlow
import net.corda.testMessage.Message
import net.corda.testMessage.MessageState
import net.corda.testing.core.*
import net.corda.testMessage.*
import net.corda.testing.core.ALICE_NAME
import net.corda.testing.core.BOB_NAME
import net.corda.testing.core.singleIdentity
import net.corda.testing.driver.DriverDSL
import net.corda.testing.driver.DriverParameters
import net.corda.testing.driver.driver
import net.corda.testing.internal.IntegrationTest
import net.corda.testing.internal.IntegrationTestSchemas
import net.corda.testing.internal.toDatabaseSchemaName
import net.corda.testing.node.TestCordapp
import net.corda.testing.node.internal.ListenProcessDeathException
import net.corda.testing.node.internal.TestCordappDirectories
import net.corda.testing.node.internal.cordappForClasses
import net.test.cordapp.v1.Record
import net.test.cordapp.v1.SendMessageFlow
import org.junit.ClassRule
import org.junit.Test
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.*
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

class FlowCheckpointVersionNodeStartupCheckTest: IntegrationTest() {
    companion object {
        @ClassRule
        @JvmField
        val databaseSchemas = IntegrationTestSchemas(ALICE_NAME.toDatabaseSchemaName(), BOB_NAME.toDatabaseSchemaName(), DUMMY_NOTARY_NAME.toDatabaseSchemaName())

        val message = Message("Hello world!")
        val defaultCordapp = cordappForClasses(
                MessageState::class.java,
                MessageContract::class.java,
                SendMessageFlow::class.java,
                MessageSchema::class.java,
                MessageSchemaV1::class.java,
                Record::class.java
        )
    }

    @Test
    fun `restart node successfully with suspended flow`() {
        return driver(parametersForRestartingNodes(listOf(defaultCordapp))) {
            createSuspendedFlowInBob(cordapps = emptySet())
            // Bob will resume the flow
            val alice = startNode(providedName = ALICE_NAME).getOrThrow()
            startNode(providedName = BOB_NAME).getOrThrow()
            val page = alice.rpc.vaultTrack(MessageState::class.java)
            val result = if (page.snapshot.states.isNotEmpty()) {
                page.snapshot.states.first()
            } else {
                val r = page.updates.timeout(5, TimeUnit.SECONDS).take(1).toBlocking().single()
                if (r.consumed.isNotEmpty()) r.consumed.first() else r.produced.first()
            }
            assertNotNull(result)
            assertEquals(message, result.state.data.message)
        }
    }

    @Test
    fun `restart node with incompatible version of suspended flow due to different jar name`() {
        driver(parametersForRestartingNodes()) {
            val cordapp = defaultCordapp.withName("different-jar-name-test-${UUID.randomUUID()}")
            // Create the CorDapp jar file manually first to get hold of the directory that will contain it so that we can
            // rename the filename later. The cordappDir, which acts as pointer to the jar file, does not get renamed.
            val cordappDir = TestCordappDirectories.getJarDirectory(cordapp)
            val cordappJar = cordappDir.list().single()

            createSuspendedFlowInBob(setOf(cordapp))

            // Rename the jar file. TestCordappDirectories caches the location of the jar file but the use of the random
            // UUID in the name means there's zero chance of contaminating another test.
            cordappJar.moveTo(cordappDir / "renamed-${cordappJar.fileName}")

            assertBobFailsToStartWithLogMessage(
                    setOf(cordapp),
                    CheckpointIncompatibleException.FlowNotInstalledException(SendMessageFlow::class.java).message
            )
        }
    }

    @Test
    fun `restart node with incompatible version of suspended flow due to different jar hash`() {
        driver(parametersForRestartingNodes()) {
            val originalCordapp = defaultCordapp.withName("different-jar-hash-test-${UUID.randomUUID()}")
            val originalCordappJar = TestCordappDirectories.getJarDirectory(originalCordapp).list().single()

            createSuspendedFlowInBob(setOf(originalCordapp))

            // The vendor is part of the MANIFEST so changing it is sufficient to change the jar hash
            val modifiedCordapp = originalCordapp.withVendor("${originalCordapp.vendor}-modified")
            val modifiedCordappJar = TestCordappDirectories.getJarDirectory(modifiedCordapp).list().single()
            modifiedCordappJar.moveTo(originalCordappJar, REPLACE_EXISTING)

            assertBobFailsToStartWithLogMessage(
                    setOf(originalCordapp),
                    // The part of the log message generated by CheckpointIncompatibleException.FlowVersionIncompatibleException
                    "that is incompatible with the current installed version of"
            )
        }
    }

    private fun DriverDSL.createSuspendedFlowInBob(cordapps: Set<TestCordapp>) {
        val (alice, bob) = listOf(ALICE_NAME, BOB_NAME)
                .map { startNode(providedName = it, additionalCordapps = cordapps) }
                .transpose()
                .getOrThrow()
        alice.stop()
        val flowTracker = bob.rpc.startTrackedFlow(::SendMessageFlow, message, defaultNotaryIdentity, alice.nodeInfo.singleIdentity()).progress
        // Wait until Bob progresses as far as possible because Alice node is offline
        flowTracker.takeFirst { it == SendMessageFlow.Companion.FINALISING_TRANSACTION.label }.toBlocking().single()
        bob.stop()
    }

    private fun DriverDSL.assertBobFailsToStartWithLogMessage(cordapps: Collection<TestCordapp>, logMessage: String) {
        assertFailsWith(ListenProcessDeathException::class) {
            startNode(
                    providedName = BOB_NAME,
                    customOverrides = mapOf("devMode" to false),
                    additionalCordapps = cordapps,
                    regenerateCordappsOnStart = true
            ).getOrThrow()
        }

        val logDir = baseDirectory(BOB_NAME) / NodeStartup.LOGS_DIRECTORY_NAME
        val logFile = logDir.list { it.filter { it.fileName.toString().endsWith(".log") }.findAny().get() }
        val matchingLineCount = logFile.readLines { it.filter { line -> logMessage in line }.count() }
        assertEquals(1, matchingLineCount)
    }

    private fun parametersForRestartingNodes(cordappsForAllNodes: List<TestCordapp> = emptyList()): DriverParameters {
        return DriverParameters(
                startNodesInProcess = false, // Start nodes in separate processes to ensure CordappLoader is not shared between restarts
                inMemoryDB = false, // Ensure database is persisted between node restarts so we can keep suspended flows
                cordappsForAllNodes = cordappsForAllNodes
        )
    }
}
