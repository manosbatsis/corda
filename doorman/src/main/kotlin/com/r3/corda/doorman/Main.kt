package com.r3.corda.doorman

import com.atlassian.jira.rest.client.internal.async.AsynchronousJiraRestClientFactory
import com.google.common.net.HostAndPort
import com.r3.corda.doorman.DoormanServer.Companion.logger
import com.r3.corda.doorman.persistence.CertificationRequestStorage
import com.r3.corda.doorman.persistence.DBCertificateRequestStorage
import com.r3.corda.doorman.persistence.JiraCertificateRequestStorage
import net.corda.core.createDirectories
import net.corda.core.crypto.*
import net.corda.core.crypto.KeyStoreUtilities.loadKeyStore
import net.corda.core.crypto.KeyStoreUtilities.loadOrCreateKeyStore
import net.corda.core.crypto.X509Utilities.CORDA_INTERMEDIATE_CA
import net.corda.core.crypto.X509Utilities.CORDA_INTERMEDIATE_CA_PRIVATE_KEY
import net.corda.core.crypto.X509Utilities.CORDA_ROOT_CA
import net.corda.core.crypto.X509Utilities.CORDA_ROOT_CA_PRIVATE_KEY
import net.corda.core.crypto.X509Utilities.createIntermediateCert
import net.corda.core.crypto.X509Utilities.createServerCert
import net.corda.core.seconds
import net.corda.core.utilities.loggerFor
import net.corda.node.utilities.configureDatabase
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.handler.HandlerCollection
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder
import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer
import java.io.Closeable
import java.lang.Thread.sleep
import java.net.InetSocketAddress
import java.net.URI
import java.security.cert.Certificate
import java.time.Instant
import kotlin.concurrent.thread
import kotlin.system.exitProcess

/**
 *  DoormanServer runs on Jetty server and provide certificate signing service via http.
 *  The server will require keystorePath, keystore password and key password via command line input.
 *  The Intermediate CA certificate,Intermediate CA private key and Root CA Certificate should use alias name specified in [X509Utilities]
 */
class DoormanServer(webServerAddr: HostAndPort, val caCertAndKey: CertificateAndKey, val rootCACert: Certificate, val storage: CertificationRequestStorage) : Closeable {
    val serverStatus = DoormanServerStatus()

    companion object {
        val logger = loggerFor<DoormanServer>()
    }

    private val server: Server = Server(InetSocketAddress(webServerAddr.hostText, webServerAddr.port)).apply {
        handler = HandlerCollection().apply {
            addHandler(buildServletContextHandler())
        }
    }

    val hostAndPort: HostAndPort get() = server.connectors
            .map { it as? ServerConnector }
            .filterNotNull()
            .map { HostAndPort.fromParts(it.host, it.localPort) }
            .first()

    override fun close() {
        logger.info("Shutting down Doorman Web Services...")
        server.stop()
        server.join()
    }

    fun start() {
        logger.info("Starting Doorman Web Services...")
        server.start()
        logger.info("Doorman Web Services started on $hostAndPort")
        serverStatus.serverStartTime = Instant.now()

        // Thread approving request periodically.
        thread(name = "Request Approval Thread") {
            while (true) {
                try {
                    sleep(10.seconds.toMillis())
                    // TODO: Handle rejected request?
                    serverStatus.lastRequestCheckTime = Instant.now()
                    for (id in storage.getApprovedRequestIds()) {
                        storage.approveRequest(id) {
                            val request = JcaPKCS10CertificationRequest(request)
                            createServerCert(request.subject, request.publicKey, caCertAndKey,
                                    if (ipAddress == hostName) listOf() else listOf(hostName), listOf(ipAddress))
                        }
                        logger.info("Approved request $id")
                        serverStatus.lastApprovalTime = Instant.now()
                        serverStatus.approvedRequests++
                    }
                } catch (e: Exception) {
                    // Log the error and carry on.
                    logger.error("Error encountered when approving request.", e)
                }
            }
        }
    }

    private fun buildServletContextHandler(): ServletContextHandler {
        return ServletContextHandler().apply {
            contextPath = "/"
            val resourceConfig = ResourceConfig().apply {
                // Add your API provider classes (annotated for JAX-RS) here
                register(DoormanWebService(caCertAndKey, rootCACert, storage, serverStatus))
            }
            val jerseyServlet = ServletHolder(ServletContainer(resourceConfig)).apply {
                initOrder = 0  // Initialise at server start
            }
            addServlet(jerseyServlet, "/api/*")
        }
    }
}

data class DoormanServerStatus(var serverStartTime: Instant? = null,
                               var lastRequestCheckTime: Instant? = null,
                               var lastApprovalTime: Instant? = null,
                               var approvedRequests: Int = 0)

/** Read password from console, do a readLine instead if console is null (e.g. when debugging in IDE). */
private fun readPassword(fmt: String): String {
    return if (System.console() != null) {
        String(System.console().readPassword(fmt))
    } else {
        print(fmt)
        readLine()!!
    }
}

private fun DoormanParameters.generateRootKeyPair() {
    println("Generating Root CA keypair and certificate.")
    // Get password from console if not in config.
    val rootKeystorePassword = rootKeystorePassword ?: readPassword("Root Keystore Password: ")
    // Ensure folder exists.
    rootStorePath.parent.createDirectories()
    val rootStore = loadOrCreateKeyStore(rootStorePath, rootKeystorePassword)
    val rootPrivateKeyPassword = rootPrivateKeyPassword ?: readPassword("Root Private Key Password: ")

    if (rootStore.containsAlias(CORDA_ROOT_CA_PRIVATE_KEY)) {
        val oldKey = loadOrCreateKeyStore(rootStorePath, rootKeystorePassword).getCertificate(CORDA_ROOT_CA_PRIVATE_KEY).publicKey
        println("Key $CORDA_ROOT_CA_PRIVATE_KEY already exists in keystore, process will now terminate.")
        println(oldKey)
        exitProcess(1)
    }

    val selfSignCert = X509Utilities.createSelfSignedCACert(X500Name(CORDA_ROOT_CA))
    rootStore.addOrReplaceKey(CORDA_ROOT_CA_PRIVATE_KEY, selfSignCert.keyPair.private, rootPrivateKeyPassword.toCharArray(), arrayOf(selfSignCert.certificate))
    rootStore.save(rootStorePath, rootKeystorePassword)

    println("Root CA keypair and certificate stored in $rootStorePath.")
    println(loadKeyStore(rootStorePath, rootKeystorePassword).getCertificate(CORDA_ROOT_CA_PRIVATE_KEY).publicKey)
}

private fun DoormanParameters.generateCAKeyPair() {
    println("Generating Intermediate CA keypair and certificate using root keystore $rootStorePath.")
    // Get password from console if not in config.
    val rootKeystorePassword = rootKeystorePassword ?: readPassword("Root Keystore Password: ")
    val rootPrivateKeyPassword = rootPrivateKeyPassword ?: readPassword("Root Private Key Password: ")
    val rootKeyStore = loadKeyStore(rootStorePath, rootKeystorePassword)

    val rootKeyAndCert = rootKeyStore.getCertificateAndKey(rootPrivateKeyPassword, CORDA_ROOT_CA_PRIVATE_KEY)

    val keystorePassword = keystorePassword ?: readPassword("Keystore Password: ")
    val caPrivateKeyPassword = caPrivateKeyPassword ?: readPassword("CA Private Key Password: ")
    // Ensure folder exists.
    keystorePath.parent.createDirectories()
    val keyStore = loadOrCreateKeyStore(keystorePath, keystorePassword)

    if (keyStore.containsAlias(CORDA_INTERMEDIATE_CA_PRIVATE_KEY)) {
        val oldKey = loadOrCreateKeyStore(keystorePath, rootKeystorePassword).getCertificate(CORDA_INTERMEDIATE_CA_PRIVATE_KEY).publicKey
        println("Key $CORDA_INTERMEDIATE_CA_PRIVATE_KEY already exists in keystore, process will now terminate.")
        println(oldKey)
        exitProcess(1)
    }

    val intermediateKeyAndCert = createIntermediateCert(X500Name(CORDA_INTERMEDIATE_CA), rootKeyAndCert)
    keyStore.addOrReplaceKey(CORDA_INTERMEDIATE_CA_PRIVATE_KEY, intermediateKeyAndCert.keyPair.private,
            caPrivateKeyPassword.toCharArray(), arrayOf(intermediateKeyAndCert.certificate, rootKeyAndCert.certificate))
    keyStore.save(keystorePath, keystorePassword)
    println("Intermediate CA keypair and certificate stored in $keystorePath.")
    println(loadKeyStore(keystorePath, keystorePassword).getCertificate(CORDA_INTERMEDIATE_CA_PRIVATE_KEY).publicKey)
}

private fun DoormanParameters.startDoorman() {
    logger.info("Starting Doorman server.")
    // Get password from console if not in config.
    val keystorePassword = keystorePassword ?: readPassword("Keystore Password: ")
    val caPrivateKeyPassword = caPrivateKeyPassword ?: readPassword("CA Private Key Password: ")

    val keystore = loadOrCreateKeyStore(keystorePath, keystorePassword)
    val rootCACert = keystore.getCertificateChain(CORDA_INTERMEDIATE_CA_PRIVATE_KEY).last()
    val caCertAndKey = keystore.getCertificateAndKey(caPrivateKeyPassword, CORDA_INTERMEDIATE_CA_PRIVATE_KEY)
    // Create DB connection.
    val (datasource, database) = configureDatabase(dataSourceProperties)

    val requestStorage = DBCertificateRequestStorage(database)

    val storage = if (jiraConfig == null) {
        logger.warn("Doorman server is in 'Approve All' mode, this will approve all incoming certificate signing request.")
        // Approve all pending request.
        object : CertificationRequestStorage by requestStorage {
            // The doorman is in approve all mode, returns all pending request id as approved request id.
            override fun getApprovedRequestIds() = getPendingRequestIds()
        }
    } else {
        val jiraClient = AsynchronousJiraRestClientFactory().createWithBasicHttpAuthentication(URI(jiraConfig.address), jiraConfig.username, jiraConfig.password)
        JiraCertificateRequestStorage(requestStorage, jiraClient, jiraConfig.projectCode, jiraConfig.doneTransitionCode)
    }

    val doorman = DoormanServer(HostAndPort.fromParts(host, port), caCertAndKey, rootCACert, storage)
    doorman.start()
    Runtime.getRuntime().addShutdownHook(thread(start = false) { doorman.close() })
}

fun main(args: Array<String>) {
    try {
        // TODO : Remove config overrides and solely use config file after testnet is finalized.
        parseParameters(*args).run {
            when (mode) {
                DoormanParameters.Mode.ROOT_KEYGEN -> generateRootKeyPair()
                DoormanParameters.Mode.CA_KEYGEN -> generateCAKeyPair()
                DoormanParameters.Mode.DOORMAN -> startDoorman()
            }
        }
    } catch (e: ShowHelpException) {
        e.parser.printHelpOn(System.out)
    }
}
