package net.mullvad.mullvadvpn.ui.customdns

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView.Adapter
import java.net.InetAddress
import kotlin.properties.Delegates.observable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.mullvad.mullvadvpn.R
import net.mullvad.mullvadvpn.util.JobTracker
import org.apache.commons.validator.routines.InetAddressValidator

class CustomDnsAdapter(
    val onSetCustomDnsEnabled: (Boolean) -> Unit,
    val onAddServer: (InetAddress) -> Boolean,
    val onRemoveDnsServer: (InetAddress) -> Unit,
    val onReplaceDnsServer: (InetAddress, InetAddress) -> Boolean
) : Adapter<CustomDnsItemHolder>() {
    private enum class ViewTypes {
        ADD_SERVER,
        EDIT_SERVER,
        SHOW_SERVER,
        FOOTER,
    }

    private val customDnsServersLock = Mutex()
    private val inetAddressValidator = InetAddressValidator.getInstance()
    private val jobTracker = JobTracker()

    private var editingPosition: Int? = null

    private var activeCustomDnsServers by observable<List<InetAddress>>(
        emptyList()
    ) { _, _, servers ->
        if (servers != cachedCustomDnsServers) {
            cachedCustomDnsServers = servers.toMutableList()
            notifyDataSetChanged()
        }
    }

    private var cachedCustomDnsServers = emptyList<InetAddress>().toMutableList()

    private var enabled by observable(false) { _, oldValue, newValue ->
        if (oldValue != newValue) {
            if (newValue == true) {
                notifyItemRangeInserted(0, cachedCustomDnsServers.size + 1)
            } else {
                notifyItemRangeRemoved(0, cachedCustomDnsServers.size + 1)
                editingPosition = null
            }
        }
    }

    val isEditing
        get() = editingPosition != null

    // By default, refuse the address so that the dialog can be recreated by the user if needed
    var confirmAddAddress: suspend (InetAddress) -> Boolean = { false }

    fun updateServers(servers: List<InetAddress>) {
        jobTracker.newBackgroundJob("toggleCustomDns") {
            if (servers.isEmpty()) {
                onSetCustomDnsEnabled(false)
            }
        }

        jobTracker.newUiJob("updateDnsServers") {
            customDnsServersLock.withLock {
                activeCustomDnsServers = servers
            }
        }
    }

    fun updateState(isEnabled: Boolean) {
        jobTracker.newUiJob("updateEnabled") {
            customDnsServersLock.withLock {
                enabled = isEnabled
            }
        }
    }

    override fun getItemCount() =
        if (enabled) {
            cachedCustomDnsServers.size + 2
        } else {
            1
        }

    override fun getItemViewType(position: Int): Int {
        val count = getItemCount()
        val footer = count - 1
        val addServer = count - 2

        if (position == footer) {
            return ViewTypes.FOOTER.ordinal
        } else if (position == editingPosition) {
            return ViewTypes.EDIT_SERVER.ordinal
        } else if (position == addServer) {
            return ViewTypes.ADD_SERVER.ordinal
        } else {
            return ViewTypes.SHOW_SERVER.ordinal
        }
    }

    override fun onCreateViewHolder(parentView: ViewGroup, type: Int): CustomDnsItemHolder {
        val inflater = LayoutInflater.from(parentView.context)
        when (ViewTypes.values()[type]) {
            ViewTypes.FOOTER -> {
                val view = inflater.inflate(R.layout.custom_dns_footer, parentView, false)
                return CustomDnsFooterHolder(view)
            }
            ViewTypes.ADD_SERVER -> {
                val view = inflater.inflate(R.layout.add_custom_dns_server, parentView, false)
                return AddCustomDnsServerHolder(view, this)
            }
            ViewTypes.EDIT_SERVER -> {
                val view = inflater.inflate(R.layout.edit_custom_dns_server, parentView, false)
                return EditCustomDnsServerHolder(view, this)
            }
            ViewTypes.SHOW_SERVER -> {
                val view = inflater.inflate(R.layout.custom_dns_server, parentView, false)
                return CustomDnsServerHolder(view, this)
            }
        }
    }

    override fun onBindViewHolder(holder: CustomDnsItemHolder, position: Int) {
        if (holder is CustomDnsServerHolder) {
            holder.serverAddress = cachedCustomDnsServers[position]
        } else if (holder is EditCustomDnsServerHolder) {
            if (position >= cachedCustomDnsServers.size) {
                holder.serverAddress = null
            } else {
                holder.serverAddress = cachedCustomDnsServers[position]
            }
        }
    }

    fun onDestroy() {
        jobTracker.newBackgroundJob("toggleCustomDns") {
            if (cachedCustomDnsServers.isEmpty()) {
                onSetCustomDnsEnabled(false)
            }
        }
    }

    fun newDnsServer() {
        jobTracker.newUiJob("newDnsServer") {
            customDnsServersLock.withLock {
                if (enabled) {
                    val count = getItemCount()

                    editDnsServerAt(count - 2)
                }
            }
        }
    }

    fun saveDnsServer(address: String, errorCallback: () -> Unit) {
        jobTracker.newUiJob("saveDnsServer $address") {
            customDnsServersLock.withLock {
                editingPosition?.let { position ->
                    var validAddress: Boolean

                    if (position >= cachedCustomDnsServers.size) {
                        validAddress = addDnsServer(address)
                    } else {
                        validAddress = replaceDnsServer(address, position)
                    }

                    if (!validAddress) {
                        errorCallback()
                    }
                }
            }
        }
    }

    fun editDnsServer(address: InetAddress) {
        jobTracker.newUiJob("editDnsServer $address") {
            customDnsServersLock.withLock {
                if (enabled) {
                    val position = cachedCustomDnsServers.indexOf(address)

                    editDnsServerAt(position)
                }
            }
        }
    }

    fun stopEditing() {
        jobTracker.newUiJob("stopEditing") {
            customDnsServersLock.withLock {
                if (enabled) {
                    editDnsServerAt(null)
                }
            }
        }
    }

    fun stopEditing(address: InetAddress) {
        jobTracker.newUiJob("stopEditing $address") {
            customDnsServersLock.withLock {
                if (enabled) {
                    editingPosition?.let { position ->
                        if (cachedCustomDnsServers.getOrNull(position) == address) {
                            editDnsServerAt(null)
                        }
                    }
                }
            }
        }
    }

    fun removeDnsServer(address: InetAddress) {
        jobTracker.newUiJob("removeDnsServer $address") {
            customDnsServersLock.withLock {
                val position = jobTracker.runOnBackground {
                    val index = cachedCustomDnsServers.indexOf(address)
                    cachedCustomDnsServers.removeAt(index)
                    onRemoveDnsServer(address)
                    index
                }

                // Immediately disable custom dns in the ui when the last server in the list has
                // been removed to avoid glitches with the ADD_SERVER view.
                if (cachedCustomDnsServers.size == 0) {
                    enabled = false
                }

                notifyItemRemoved(position)
            }
        }
    }

    private suspend fun addDnsServer(addressText: String): Boolean {
        var added = false

        withValidAddress(addressText) { address ->
            if (onAddServer(address)) {
                cachedCustomDnsServers.add(address)
                added = true
            }
        }

        if (added) {
            editingPosition = null

            val count = getItemCount()

            notifyItemChanged(count - 3)
            notifyItemInserted(count - 2)
        }

        return added
    }

    private suspend fun replaceDnsServer(address: String, position: Int): Boolean {
        var replaced = false

        withValidAddress(address) { newAddress ->
            val oldAddress = cachedCustomDnsServers[position]

            if (onReplaceDnsServer(oldAddress, newAddress)) {
                cachedCustomDnsServers[position] = newAddress
                replaced = true
            }
        }

        if (replaced) {
            editingPosition = null
            notifyItemChanged(position)
        }

        return replaced
    }

    private fun editDnsServerAt(position: Int?) {
        editingPosition?.let { oldPosition ->
            notifyItemChanged(oldPosition)
        }

        editingPosition = position

        position?.let { newPosition ->
            notifyItemChanged(newPosition)
        }
    }

    private suspend fun withValidAddress(addressText: String, handler: (InetAddress) -> Unit) {
        jobTracker.runOnBackground {
            if (inetAddressValidator.isValid(addressText)) {
                val address = InetAddress.getByName(addressText)

                if (!address.isLoopbackAddress() && confirmAddAddress(address)) {
                    handler(address)
                }
            }
        }
    }
}
