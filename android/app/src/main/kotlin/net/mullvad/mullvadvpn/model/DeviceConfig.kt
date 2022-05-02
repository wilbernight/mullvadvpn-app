package net.mullvad.mullvadvpn.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

@Parcelize
data class DeviceConfig(
    val account_token: String,
    val device: Device
) : Parcelable
