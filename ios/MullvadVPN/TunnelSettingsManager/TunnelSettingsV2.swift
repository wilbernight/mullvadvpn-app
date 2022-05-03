//
//  TunnelSettingsV2.swift
//  MullvadVPN
//
//  Created by pronebird on 27/04/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import struct Network.IPv4Address
import class WireGuardKitTypes.PublicKey
import struct WireGuardKitTypes.IPAddressRange

struct StoredAccountData: Codable, Equatable {
    /// Mullvad account number.
    var number: String

    /// Mullvad account expiry.
    var expiry: Date
}

struct StoredDeviceData: Codable, Equatable {
    /// Device creation date.
    var creationDate: Date

    /// Device identifier.
    var identifier: String

    /// Device name.
    var name: String

    /// Private key.
    var privateKey: PrivateKeyWithMetadata

    /// Returns public key derived from private key.
    var publicKey: PublicKey {
        return privateKey.publicKeyWithMetadata.publicKey
    }

    /// Next private key.
    var nextPrivateKey: PrivateKeyWithMetadata?

    /// IP addresses assigned for tunnel interface.
    var addresses: [IPAddressRange]
}

struct TunnelSettingsV2: Codable, Equatable {
    /// Mullvad account number.
    var account: StoredAccountData

    /// Device information.
    var device: StoredDeviceData

    /// Relay constraints
    var relayConstraints: RelayConstraints

    /// DNS settings.
    var dnsSettings: DNSSettings
}
