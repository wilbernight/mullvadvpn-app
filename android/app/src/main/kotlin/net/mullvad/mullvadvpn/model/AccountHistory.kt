package net.mullvad.mullvadvpn.model

import android.os.Parcelable
import kotlinx.android.parcel.Parcelize

sealed class AccountHistory : Parcelable {
    @Parcelize
    data class WithHistory(val accountToken: String) : AccountHistory()
    @Parcelize
    object WithoutHistory : AccountHistory()
}
