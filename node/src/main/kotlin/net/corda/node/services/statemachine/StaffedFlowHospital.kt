package net.corda.node.services.statemachine

import net.corda.core.crypto.newSecureRandom
import net.corda.core.flows.FlowException
import net.corda.core.flows.HospitalizeFlowException
import net.corda.core.flows.NotaryError
import net.corda.core.flows.NotaryException
import net.corda.core.flows.ReceiveFinalityFlow
import net.corda.core.flows.ReceiveTransactionFlow
import net.corda.core.flows.StateMachineRunId
import net.corda.core.flows.UnexpectedFlowEndException
import net.corda.core.identity.Party
import net.corda.core.internal.DeclaredField
import net.corda.core.internal.ThreadBox
import net.corda.core.internal.TimedFlow
import net.corda.core.internal.VisibleForTesting
import net.corda.core.internal.bufferUntilSubscribed
import net.corda.core.messaging.DataFeed
import net.corda.core.utilities.contextLogger
import net.corda.core.utilities.debug
import net.corda.core.utilities.minutes
import net.corda.core.utilities.seconds
import net.corda.node.services.FinalityHandler
import org.hibernate.exception.ConstraintViolationException
import rx.subjects.PublishSubject
import java.io.Closeable
import java.sql.SQLException
import java.sql.SQLTransientConnectionException
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.persistence.PersistenceException
import kotlin.concurrent.timerTask
import kotlin.math.pow

/**
 * This hospital consults "staff" to see if they can automatically diagnose and treat flows.
 */
class StaffedFlowHospital(private val flowMessaging: FlowMessaging,
                          private val clock: Clock,
                          private val ourSenderUUID: String) : Closeable {
    companion object {
        private val log = contextLogger()
        private val staff = listOf(
            DeadlockNurse,
            DuplicateInsertSpecialist,
            DoctorTimeout,
            FinalityDoctor,
            TransientConnectionCardiologist,
            DatabaseEndocrinologist,
            TransitionErrorGeneralPractitioner,
            SedationNurse,
            NotaryDoctor
        )

        @VisibleForTesting
        val onFlowKeptForOvernightObservation = mutableListOf<(id: StateMachineRunId, by: List<String>) -> Unit>()

        @VisibleForTesting
        val onFlowDischarged = mutableListOf<(id: StateMachineRunId, by: List<String>) -> Unit>()

        @VisibleForTesting
        val onFlowAdmitted = mutableListOf<(id: StateMachineRunId) -> Unit>()
    }

    private val hospitalJobTimer = Timer("FlowHospitalJobTimer", true)

    init {
        // Register a task to log (at intervals) flows that are kept in hospital for overnight observation.
        hospitalJobTimer.scheduleAtFixedRate(timerTask {
            mutex.locked {
                if (flowsInHospital.isNotEmpty()) {
                    // Get patients whose last record in their medical records is Outcome.OVERNIGHT_OBSERVATION.
                    val patientsUnderOvernightObservation =
                            flowsInHospital.filter { flowPatients[it.key]?.records?.last()?.outcome == Outcome.OVERNIGHT_OBSERVATION }
                    if (patientsUnderOvernightObservation.isNotEmpty())
                        log.warn("There are ${patientsUnderOvernightObservation.count()} flows kept for overnight observation. " +
                                "Affected flow ids: ${patientsUnderOvernightObservation.map { it.key.uuid.toString() }.joinToString()}")
                }
                if (treatableSessionInits.isNotEmpty()) {
                    log.warn("There are ${treatableSessionInits.count()} erroneous session initiations kept for overnight observation. " +
                            "Erroneous session initiation ids: ${treatableSessionInits.map { it.key.toString() }.joinToString()}")
                }
            }
        }, 1.minutes.toMillis(), 1.minutes.toMillis())
    }

    /**
     * Represents the flows that have been admitted to the hospital for treatment.
     * Flows should be removed from [flowsInHospital] when they have completed a successful transition.
     */
    private val flowsInHospital = ConcurrentHashMap<StateMachineRunId, FlowFiber>()

    private val mutex = ThreadBox(object {
        /**
         * Contains medical history of every flow (a patient) that has entered the hospital. A flow can leave the hospital,
         * but their medical history will be retained.
         *
         * Flows should be removed from [flowPatients] when they have completed successfully. Upon successful completion,
         * the medical history of a flow is no longer relevant as that flow has been completely removed from the
         * statemachine.
         */
        val flowPatients = HashMap<StateMachineRunId, FlowMedicalHistory>()
        val treatableSessionInits = HashMap<StateMachineRunId, InternalSessionInitRecord>()
        val recordsPublisher = PublishSubject.create<MedicalRecord>()
    })
    private val secureRandom = newSecureRandom()

    /**
     * The node was unable to initiate the [InitialSessionMessage] from [sender].
     */
    fun sessionInitErrored(sessionMessage: InitialSessionMessage, sender: Party, event: ExternalEvent.ExternalMessageEvent, error: Throwable) {
        val id = event.flowId
        val time = clock.instant()
        val outcome = if (error is SessionRejectException.UnknownClass) {
            // We probably don't have the CorDapp installed so let's pause the message in the hopes that the CorDapp is
            // installed on restart, at which point the message will be able proceed as normal. If not then it will need
            // to be dropped manually.
            Outcome.OVERNIGHT_OBSERVATION
        } else {
            Outcome.UNTREATABLE
        }

        val record = sessionMessage.run { MedicalRecord.SessionInit(id, time, outcome, initiatorFlowClassName, flowVersion, appName, sender, error) }
        mutex.locked {
            if (outcome != Outcome.UNTREATABLE) {
                treatableSessionInits[id] = InternalSessionInitRecord(sessionMessage, event, record)
                log.warn("$sender has sent a flow request for an unknown flow ${sessionMessage.initiatorFlowClassName}. Install the missing " +
                        "CorDapp this flow belongs to and restart.")
                log.warn("If you know it's safe to ignore this flow request then it can be deleted permanently using the killFlow RPC and " +
                        "the UUID $id (from the node shell you can run 'flow kill $id'). BE VERY CAUTIOUS OF THIS SECOND APPROACH AS THE " +
                        "REQUEST MAY CONTAIN A NOTARISED TRANSACTION THAT NEEDS TO BE RECORDED IN YOUR VAULT.")
            }
            recordsPublisher.onNext(record)
        }

        if (outcome == Outcome.UNTREATABLE) {
            sendBackError(error, sessionMessage, sender, event)
        }
    }

    private fun sendBackError(error: Throwable, sessionMessage: InitialSessionMessage, sender: Party, event: ExternalEvent.ExternalMessageEvent) {
        val message = (error as? SessionRejectException)?.message ?: "Unable to establish session"
        val payload = RejectSessionMessage(message, secureRandom.nextLong())
        val replyError = ExistingSessionMessage(sessionMessage.initiatorSessionId, payload)

        flowMessaging.sendSessionMessage(sender, replyError, SenderDeduplicationId(DeduplicationId.createRandom(secureRandom), ourSenderUUID))
        event.deduplicationHandler.afterDatabaseTransaction()
    }

    /**
     * Drop the errored session-init message with the given ID ([MedicalRecord.SessionInit.id]). This will cause the node
     * to send back the relevant session error to the initiator party and acknowledge its receipt from the message broker
     * so that it never gets redelivered.
     */
    fun dropSessionInit(id: StateMachineRunId): Boolean {
        val (sessionMessage, event, publicRecord) = mutex.locked {
            treatableSessionInits.remove(id) ?: return false
        }
        log.info("Errored session-init permanently dropped: $publicRecord")
        sendBackError(publicRecord.error, sessionMessage, publicRecord.sender, event)
        return true
    }

    /**
     * Forces the flow to be kept in for overnight observation by the hospital. A flow must already exist inside the hospital
     * and have existing medical records for it to be moved to overnight observation. If it does not meet these criteria then
     * an [IllegalArgumentException] will be thrown.
     *
     * @param id The [StateMachineRunId] of the flow that you are trying to force into observation
     * @param errors The errors to include in the new medical record
     */
    fun forceIntoOvernightObservation(id: StateMachineRunId, errors: List<Throwable>) {
        mutex.locked {
            // If a flow does not meet the criteria below, then it has moved into an invalid state or the function is being
            // called from an incorrect location. The assertions below should error out the flow if they are not true.
            requireNotNull(flowsInHospital[id]) { "Flow must already be in the hospital before forcing into overnight observation" }
            val history = requireNotNull(flowPatients[id]) { "Flow must already have history before forcing into overnight observation" }
            // Use the last staff member that last discharged the flow as the current staff member
            val record = history.records.last().copy(
                time = clock.instant(),
                errors = errors,
                outcome = Outcome.OVERNIGHT_OBSERVATION
            )
            onFlowKeptForOvernightObservation.forEach { hook -> hook.invoke(id, record.by.map { it.toString() }) }
            history.records += record
            recordsPublisher.onNext(record)
        }
    }


    /**
     * Request treatment for the [flowFiber]. A flow can only be added to the hospital if they are not already being
     * treated.
     */
    fun requestTreatment(flowFiber: FlowFiber, currentState: StateMachineState, errors: List<Throwable>) {
        // Only treat flows that are not already in the hospital
        if (!currentState.isRemoved && flowsInHospital.putIfAbsent(flowFiber.id, flowFiber) == null) {
            admit(flowFiber, currentState, errors)
        }
    }

    @Suppress("ComplexMethod")
    private fun admit(flowFiber: FlowFiber, currentState: StateMachineState, errors: List<Throwable>) {
        val time = clock.instant()
        log.info("Flow ${flowFiber.id} admitted to hospital in state $currentState")
        onFlowAdmitted.forEach { it.invoke(flowFiber.id) }

        val (event, backOffForChronicCondition) = mutex.locked {
            val medicalHistory = flowPatients.computeIfAbsent(flowFiber.id) { FlowMedicalHistory() }

            val report = consultStaff(flowFiber, currentState, errors, medicalHistory)

            val (outcome, event, backOffForChronicCondition) = when (report.diagnosis) {
                Diagnosis.DISCHARGE -> {
                    val backOff = calculateBackOffForChronicCondition(report, medicalHistory, currentState)
                    log.info("Flow error discharged from hospital (delay ${backOff.seconds}s) by ${report.by} (error was ${report.error.message})")
                    onFlowDischarged.forEach { hook -> hook.invoke(flowFiber.id, report.by.map{it.toString()}) }
                    Triple(Outcome.DISCHARGE, Event.RetryFlowFromSafePoint, backOff)
                }
                Diagnosis.OVERNIGHT_OBSERVATION -> {
                    log.info("Flow error kept for overnight observation by ${report.by} (error was ${report.error.message})")
                    // We don't schedule a next event for the flow - it will automatically retry from its checkpoint on node restart
                    onFlowKeptForOvernightObservation.forEach { hook -> hook.invoke(flowFiber.id, report.by.map{it.toString()}) }
                    Triple(Outcome.OVERNIGHT_OBSERVATION, null, 0.seconds)
                }
                Diagnosis.NOT_MY_SPECIALTY, Diagnosis.TERMINAL -> {
                    // None of the staff care for these errors, or someone decided it is a terminal condition, so we let them propagate
                    log.info("Flow error allowed to propagate", report.error)
                    Triple(Outcome.UNTREATABLE, Event.StartErrorPropagation, 0.seconds)
                }
            }

            val record = MedicalRecord.Flow(time, flowFiber.id, currentState.checkpoint.numberOfSuspends, errors, report.by, outcome)
            medicalHistory.records += record
            recordsPublisher.onNext(record)
            Pair(event, backOffForChronicCondition)
        }

        if (event != null) {
            if (backOffForChronicCondition.isZero) {
                flowFiber.scheduleEvent(event)
            } else {
                hospitalJobTimer.schedule(timerTask {
                    flowFiber.scheduleEvent(event)
                }, backOffForChronicCondition.toMillis())
            }
        }
    }

    private fun calculateBackOffForChronicCondition(report: ConsultationReport, medicalHistory: FlowMedicalHistory, currentState: StateMachineState): Duration {
        return report.by.firstOrNull { it is Chronic }?.let { chronicStaff ->
            return medicalHistory.timesDischargedForTheSameThing(chronicStaff, currentState).let {
                if (it == 0) {
                    0.seconds
                } else {
                    maxOf(10, (10 + (Math.random()) * (10 * 1.5.pow(it)) / 2).toInt()).seconds
                }
            }
        } ?: 0.seconds
    }

    private fun consultStaff(flowFiber: FlowFiber,
                             currentState: StateMachineState,
                             errors: List<Throwable>,
                             medicalHistory: FlowMedicalHistory): ConsultationReport {
        return errors
                .asSequence()
                .mapIndexed { index, error ->
                    // Rely on the logging context to print details of the flow ID.
                    log.info("Error ${index + 1} of ${errors.size}:", error)
                    val diagnoses: Map<Diagnosis, List<Staff>> = staff.groupBy { it.consult(flowFiber, currentState, error, medicalHistory) }
                    // We're only interested in the highest priority diagnosis for the error
                    val (diagnosis, by) = diagnoses.entries.minBy { it.key }!!
                    ConsultationReport(error, diagnosis, by)
                }
                // And we're only interested in the error with the highest priority diagnosis
                .minBy { it.diagnosis }!!
    }

    private data class ConsultationReport(val error: Throwable, val diagnosis: Diagnosis, val by: List<Staff>)

    /**
     * Remove the flow's medical history from the hospital.
     */
    fun removeMedicalHistory(flowId: StateMachineRunId) {
        mutex.locked { flowPatients.remove(flowId) }
    }

    /**
     * Remove the flow from the hospital as it is not currently being treated.
     */
    fun leave(id: StateMachineRunId) {
        flowsInHospital.remove(id)
    }

    // TODO MedicalRecord subtypes can expose the Staff class, something which we probably don't want when wiring this method to RPC
    /** Returns a stream of medical records as flows pass through the hospital. */
    fun track(): DataFeed<List<MedicalRecord>, MedicalRecord> {
        return mutex.locked {
            val snapshot = (flowPatients.values.flatMap { it.records } + treatableSessionInits.values.map { it.publicRecord }).sortedBy { it.time }
            DataFeed(snapshot, recordsPublisher.bufferUntilSubscribed())
        }
    }

    operator fun contains(flowId: StateMachineRunId) = mutex.locked { flowId in flowPatients }

    override fun close() {
        hospitalJobTimer.cancel()
    }

    class FlowMedicalHistory {
        internal val records: MutableList<MedicalRecord.Flow> = mutableListOf()

        fun notDischargedForTheSameThingMoreThan(max: Int, by: Staff, currentState: StateMachineState): Boolean {
            return timesDischargedForTheSameThing(by, currentState) <= max
        }

        fun timesDischargedForTheSameThing(by: Staff, currentState: StateMachineState): Int {
            val lastAdmittanceSuspendCount = currentState.checkpoint.numberOfSuspends
            return records.count { it.outcome == Outcome.DISCHARGE && by in it.by && it.suspendCount == lastAdmittanceSuspendCount }
        }

        override fun toString(): String = "${this.javaClass.simpleName}(records = $records)"
    }

    private data class InternalSessionInitRecord(val sessionMessage: InitialSessionMessage,
                                                 val event: ExternalEvent.ExternalMessageEvent,
                                                 val publicRecord: MedicalRecord.SessionInit)

    sealed class MedicalRecord {
        abstract val time: Instant
        abstract val outcome: Outcome
        abstract val errors: List<Throwable>

        /** Medical record for a flow that has errored. */
        data class Flow(override val time: Instant,
                        val flowId: StateMachineRunId,
                        val suspendCount: Int,
                        override val errors: List<Throwable>,
                        val by: List<Staff>,
                        override val outcome: Outcome) : MedicalRecord()

        /** Medical record for a session initiation that was unsuccessful. */
        data class SessionInit(val id: StateMachineRunId,
                               override val time: Instant,
                               override val outcome: Outcome,
                               val initiatorFlowClassName: String,
                               val flowVersion: Int,
                               val appName: String,
                               val sender: Party,
                               val error: Throwable) : MedicalRecord() {
            override val errors: List<Throwable> get() = listOf(error)
        }
    }

    enum class Outcome { DISCHARGE, OVERNIGHT_OBSERVATION, UNTREATABLE }

    /** The order of the enum values are in priority order. */
    enum class Diagnosis {
        /** The flow should not see other staff members */
        TERMINAL,
        /** Retry from last safe point. */
        DISCHARGE,
        /** Park and await intervention. */
        OVERNIGHT_OBSERVATION,
        /** Please try another member of staff. */
        NOT_MY_SPECIALTY
    }

    interface Staff {
        fun consult(flowFiber: FlowFiber, currentState: StateMachineState, newError: Throwable, history: FlowMedicalHistory): Diagnosis
    }

    interface Chronic

    /**
     * SQL Deadlock detection.
     */
    object DeadlockNurse : Staff, Chronic {
        override fun consult(flowFiber: FlowFiber, currentState: StateMachineState, newError: Throwable, history: FlowMedicalHistory): Diagnosis {
            return if (mentionsDeadlock(newError)) {
                Diagnosis.DISCHARGE
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }

        private fun mentionsDeadlock(exception: Throwable?): Boolean {
            return exception.mentionsThrowable(SQLException::class.java, "deadlock")
        }
    }

    /**
     * Primary key violation detection for duplicate inserts.  Will detect other constraint violations too.
     */
    object DuplicateInsertSpecialist : Staff {
        override fun consult(flowFiber: FlowFiber, currentState: StateMachineState, newError: Throwable, history: FlowMedicalHistory): Diagnosis {
            return if (newError.mentionsThrowable(ConstraintViolationException::class.java)
                && history.notDischargedForTheSameThingMoreThan(2, this, currentState)) {
                Diagnosis.DISCHARGE
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }
    }

    /**
     * Restarts [TimedFlow], keeping track of the number of retries and making sure it does not
     * exceed the limit specified by the [FlowTimeoutException].
     */
    object DoctorTimeout : Staff {
        override fun consult(flowFiber: FlowFiber, currentState: StateMachineState, newError: Throwable, history: FlowMedicalHistory): Diagnosis {
            if (newError is FlowTimeoutException) {
                return Diagnosis.DISCHARGE
            }
            return Diagnosis.NOT_MY_SPECIALTY
        }
    }

    object FinalityDoctor : Staff {
        override fun consult(flowFiber: FlowFiber, currentState: StateMachineState, newError: Throwable, history: FlowMedicalHistory): Diagnosis {
            return if (currentState.flowLogic is FinalityHandler) {
                log.warn("Flow ${flowFiber.id} failed to be finalised. Manual intervention may be required before retrying " +
                        "the flow by re-starting the node. State machine state: $currentState", newError)
                Diagnosis.OVERNIGHT_OBSERVATION
            } else if (isFromReceiveFinalityFlow(newError)) {
                if (isErrorPropagatedFromCounterparty(newError) && isErrorThrownDuringReceiveFinality(newError)) {
                    // no need to keep around the flow, since notarisation has already failed at the counterparty.
                    Diagnosis.NOT_MY_SPECIALTY
                } else {
                    log.warn("Flow ${flowFiber.id} failed to be finalised. Manual intervention may be required before retrying " +
                            "the flow by re-starting the node. State machine state: $currentState", newError)
                    Diagnosis.OVERNIGHT_OBSERVATION
                }
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }

        private fun isFromReceiveFinalityFlow(throwable: Throwable): Boolean {
            return throwable.stackTrace.any { it.className == ReceiveFinalityFlow::class.java.name }
        }

        private fun isErrorPropagatedFromCounterparty(error: Throwable): Boolean {
            return when (error) {
                is UnexpectedFlowEndException -> {
                    val peer = DeclaredField<Party?>(UnexpectedFlowEndException::class.java, "peer", error).value
                    peer != null
                }
                is FlowException -> {
                    val peer = DeclaredField<Party?>(FlowException::class.java, "peer", error).value
                    peer != null
                }
                else -> false
            }
        }

        /**
         * This method will return true if [ReceiveTransactionFlow] is at the top of the stack during the error.
         * As a result, if the failure happened during a sub-flow invoked from [ReceiveTransactionFlow], the method will return false.
         *
         * This is because in the latter case, the transaction might have already been finalised and deleting the flow
         * would introduce risk for inconsistency between nodes.
         */
        private fun isErrorThrownDuringReceiveFinality(error: Throwable): Boolean {
            val strippedStacktrace = error.stackTrace
                    .filterNot { it?.className?.contains("counter-flow exception from peer") ?: false }
                    .filterNot { it?.className?.startsWith("net.corda.node.services.statemachine.") ?: false }
            return strippedStacktrace.isNotEmpty()
                    && strippedStacktrace.first().className.startsWith(ReceiveTransactionFlow::class.qualifiedName!!)
        }
    }

    /**
     * [SQLTransientConnectionException] detection that arise from failing to connect the underlying database/datasource
     */
    object TransientConnectionCardiologist : Staff {
        override fun consult(
                flowFiber: FlowFiber,
                currentState: StateMachineState,
                newError: Throwable,
                history: FlowMedicalHistory
        ): Diagnosis {
            return if (mentionsTransientConnection(newError)) {
                if (history.notDischargedForTheSameThingMoreThan(2, this, currentState)) {
                    Diagnosis.DISCHARGE
                } else {
                    Diagnosis.OVERNIGHT_OBSERVATION
                }
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }

        private fun mentionsTransientConnection(exception: Throwable?): Boolean {
            return exception.mentionsThrowable(SQLTransientConnectionException::class.java, "connection is not available")
        }
    }

    /**
     * Hospitalise any database (SQL and Persistence) exception that wasn't handled otherwise, unless on the configurable whitelist
     * Note that retry decisions from other specialists will not be affected as retries take precedence over hospitalisation.
     */
    object DatabaseEndocrinologist : Staff {
        override fun consult(
                flowFiber: FlowFiber,
                currentState: StateMachineState,
                newError: Throwable,
                history: FlowMedicalHistory
        ): Diagnosis {
            return if ((newError is SQLException || newError is PersistenceException) && !customConditions.any { it(newError) }) {
                Diagnosis.OVERNIGHT_OBSERVATION
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }

        @VisibleForTesting
        val customConditions = mutableSetOf<(t: Throwable) -> Boolean>()
    }

    /**
     * Handles exceptions from internal state transitions that are not dealt with by the rest of the staff.
     *
     * [InterruptedException]s are diagnosed as [Diagnosis.TERMINAL] so they are never retried
     * (can occur when a flow is killed - `killFlow`).
     * [AsyncOperationTransitionException]s ares ignored as the error is likely to have originated in user async code rather than inside
     * of a transition.
     * All other exceptions are retried a maximum of 3 times before being kept in for observation.
     */
    object TransitionErrorGeneralPractitioner : Staff {
        override fun consult(
            flowFiber: FlowFiber,
            currentState: StateMachineState,
            newError: Throwable,
            history: FlowMedicalHistory
        ): Diagnosis {
            return if (newError.mentionsThrowable(StateTransitionException::class.java)) {
                when {
                    newError.mentionsThrowable(InterruptedException::class.java) -> Diagnosis.TERMINAL
                    newError.mentionsThrowable(AsyncOperationTransitionException::class.java) -> Diagnosis.NOT_MY_SPECIALTY
                    history.notDischargedForTheSameThingMoreThan(2, this, currentState) -> Diagnosis.DISCHARGE
                    else -> Diagnosis.OVERNIGHT_OBSERVATION
                }
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }.also { logDiagnosis(it, newError, flowFiber, history) }
        }

        private fun logDiagnosis(diagnosis: Diagnosis, newError: Throwable, flowFiber: FlowFiber, history: FlowMedicalHistory) {
            if (diagnosis != Diagnosis.NOT_MY_SPECIALTY) {
                log.debug {
                    """
                        Flow ${flowFiber.id} given $diagnosis diagnosis due to a transition error
                        - Exception: ${newError.message}
                        - History: $history
                        ${(newError as? StateTransitionException)?.transitionAction?.let { "- Action: $it" }}
                        ${(newError as? StateTransitionException)?.transitionEvent?.let { "- Event: $it" }}
                        """.trimIndent()
                }
            }
        }
    }

    /**
     * Keeps the flow in for overnight observation if [HospitalizeFlowException] is received.
     */
    object SedationNurse : Staff {
        override fun consult(
            flowFiber: FlowFiber,
            currentState: StateMachineState,
            newError: Throwable,
            history: FlowMedicalHistory
        ): Diagnosis {
            return if (newError.mentionsThrowable(HospitalizeFlowException::class.java)) {
                Diagnosis.OVERNIGHT_OBSERVATION
            } else {
                Diagnosis.NOT_MY_SPECIALTY
            }
        }
    }

    /**
     * Retry notarisation if the flow errors with a [NotaryError.General]. Notary flows are idempotent and only success or conflict
     * responses should be returned to the client.
     */
    object NotaryDoctor : Staff, Chronic {
        override fun consult(flowFiber: FlowFiber,
                             currentState: StateMachineState,
                             newError: Throwable,
                             history: FlowMedicalHistory): Diagnosis {
            if (newError is NotaryException && newError.error is NotaryError.General) {
                return Diagnosis.DISCHARGE
            }
            return Diagnosis.NOT_MY_SPECIALTY
        }
    }
}

private fun <T : Throwable> Throwable?.mentionsThrowable(exceptionType: Class<T>, errorMessage: String? = null): Boolean {
    if (this == null) {
        return false
    }
    val containsMessage = if (errorMessage != null) {
        message?.toLowerCase()?.contains(errorMessage) ?: false
    } else {
        true
    }
    return (exceptionType.isAssignableFrom(this::class.java) && containsMessage) || cause.mentionsThrowable(exceptionType, errorMessage)
}

