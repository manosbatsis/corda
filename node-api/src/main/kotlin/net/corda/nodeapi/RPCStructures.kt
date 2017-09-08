@file:JvmName("RPCStructures")

package net.corda.nodeapi

import com.esotericsoftware.kryo.Registration
import com.esotericsoftware.kryo.Serializer
import net.corda.core.concurrent.CordaFuture
import net.corda.core.CordaRuntimeException
import net.corda.core.serialization.CordaSerializable
import net.corda.core.serialization.SerializationContext
import net.corda.core.toFuture
import net.corda.core.toObservable
import net.corda.nodeapi.config.OldConfig
import net.corda.nodeapi.internal.serialization.*
import rx.Observable
import java.io.InputStream

data class User(
        @OldConfig("user")
        val username: String,
        val password: String,
        val permissions: Set<String>) {
    override fun toString(): String = "${javaClass.simpleName}($username, permissions=$permissions)"
    fun toMap() = mapOf(
            "username" to username,
            "password" to password,
            "permissions" to permissions
    )
}

/** Records the protocol version in which this RPC was added. */
@Target(AnnotationTarget.FUNCTION)
@MustBeDocumented
annotation class RPCSinceVersion(val version: Int)

/**
 * Thrown to indicate a fatal error in the RPC system itself, as opposed to an error generated by the invoked
 * method.
 */
open class RPCException(message: String?, cause: Throwable?) : CordaRuntimeException(message, cause) {
    constructor(msg: String) : this(msg, null)
}

/**
 * Thrown to indicate that the calling user does not have permission for something they have requested (for example
 * calling a method).
 */
@CordaSerializable
class PermissionException(msg: String) : RuntimeException(msg)

/**
 * The Kryo used for the RPC wire protocol.
 */
// Every type in the wire protocol is listed here explicitly.
// This is annoying to write out, but will make it easier to formalise the wire protocol when the time comes,
// because we can see everything we're using in one place.
class RPCKryo(observableSerializer: Serializer<Observable<*>>, serializationContext: SerializationContext) : CordaKryo(CordaClassResolver(serializationContext)) {
    init {
        DefaultKryoCustomizer.customize(this)

        // RPC specific classes
        register(InputStream::class.java, InputStreamSerializer)
        register(Observable::class.java, observableSerializer)
        register(CordaFuture::class,
                read = { kryo, input -> observableSerializer.read(kryo, input, Observable::class.java).toFuture() },
                write = { kryo, output, obj -> observableSerializer.write(kryo, output, obj.toObservable()) }
        )
    }

    override fun getRegistration(type: Class<*>): Registration {
        if (Observable::class.java != type && Observable::class.java.isAssignableFrom(type)) {
            return super.getRegistration(Observable::class.java)
        }
        if (InputStream::class.java != type && InputStream::class.java.isAssignableFrom(type)) {
            return super.getRegistration(InputStream::class.java)
        }
        if (CordaFuture::class.java != type && CordaFuture::class.java.isAssignableFrom(type)) {
            return super.getRegistration(CordaFuture::class.java)
        }
        type.requireExternal("RPC not allowed to deserialise internal classes")
        return super.getRegistration(type)
    }

    private fun Class<*>.requireExternal(msg: String) {
        require(!name.startsWith("net.corda.node.") && !name.contains(".internal.")) { "$msg: $name" }
    }
}
