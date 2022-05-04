//
//  TunnelManagerError.swift
//  TunnelManagerError
//
//  Created by pronebird on 07/09/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

extension TunnelManager {
    /// An error emitted by all public methods of TunnelManager
    enum Error: ChainedError {
        /// Account is unset.
        case unsetAccount

        /// A failure to start the VPN tunnel via system call.
        case startVPNTunnel(Swift.Error)

        /// A failure to load the system VPN configurations created by the app.
        case loadAllVPNConfigurations(Swift.Error)

        /// A failure to save the system VPN configuration.
        case saveVPNConfiguration(Swift.Error)

        /// A failure to reload the system VPN configuration.
        case reloadVPNConfiguration(Swift.Error)

        /// A failure to remove the system VPN configuration.
        case removeVPNConfiguration(Swift.Error)

        /// A failure to perform a recovery (by removing the VPN configuration) when a corrupt
        /// VPN configuration is detected.
        case removeInconsistentVPNConfiguration(Swift.Error)

        /// A failure to read tunnel settings.
        case readTunnelSettings(Swift.Error)

        /// A failure to read relays cache.
        case readRelays(RelayCache.Error)

        /// A failure to find a relay satisfying the given constraints.
        case cannotSatisfyRelayConstraints

        /// A failure to add the tunnel settings.
        case addTunnelSettings(Swift.Error)

        /// A failure to update the tunnel settings.
        case updateTunnelSettings(Swift.Error)

        /// A failure to remove the tunnel settings from Keychain.
        case removeTunnelSettings(Swift.Error)

        /// A failure to create device.
        case createDevice(REST.Error)

        /// A failure to replace the public WireGuard key.
        case replaceWireguardKey(REST.Error)

        /// A failure to delete device.
        case deleteDevice(REST.Error)

        /// A failure to schedule background task.
        case backgroundTaskScheduler(Swift.Error)

        /// A failure to reload tunnel.
        case reloadTunnel(TunnelIPC.Error)

        var errorDescription: String? {
            switch self {
            case .unsetAccount:
                return "Account is unset."
            case .startVPNTunnel:
                return "Failed to start the VPN tunnel."
            case .loadAllVPNConfigurations:
                return "Failed to load the system VPN configurations."
            case .saveVPNConfiguration:
                return "Failed to save the system VPN configuration."
            case .reloadVPNConfiguration:
                return "Failed to reload the system VPN configuration."
            case .removeVPNConfiguration:
                return "Failed to remove the system VPN configuration."
            case .removeInconsistentVPNConfiguration:
                return "Failed to remove the inconsistent VPN tunnel."
            case .readTunnelSettings:
                return "Failed to read the tunnel settings."
            case .readRelays:
                return "Failed to read relays."
            case .cannotSatisfyRelayConstraints:
                return "Failed to satisfy the relay constraints."
            case .addTunnelSettings:
                return "Failed to add the tunnel settings."
            case .updateTunnelSettings:
                return "Failed to update the tunnel settings."
            case .removeTunnelSettings:
                return "Failed to remove the tunnel settings."
            case .createDevice:
                return "Failed to create a device."
            case .replaceWireguardKey:
                return "Failed to replace the WireGuard key on server."
            case .deleteDevice:
                return "Failed to delete a device."
            case .backgroundTaskScheduler:
                return "Failed to schedule background task."
            case .reloadTunnel:
                return "Failed to reload tunnel."
            }
        }
    }
}
