package net.mullvad.mullvadvpn.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class ObfuscationSettings(
    val selectedObfuscation: SelectedObfuscation,
    val udp2tcp: Udp2TcpObfuscationSettings
) : Parcelable

@Parcelize
enum class SelectedObfuscation : Parcelable {
    Auto,
    Off,
    Udp2Tcp,
}

@Parcelize
data class Udp2TcpObfuscationSettings(
    val port: Constraint<Int>
) : Parcelable
