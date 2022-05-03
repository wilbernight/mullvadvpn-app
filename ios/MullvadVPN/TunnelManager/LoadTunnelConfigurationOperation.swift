//
//  LoadTunnelConfigurationOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 16/12/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging

class LoadTunnelConfigurationOperation: ResultOperation<(), TunnelManager.Error> {
    private let queue: DispatchQueue
    private let state: TunnelManager.State

    private let logger = Logger(label: "TunnelManager.LoadTunnelConfigurationOperation")

    init(queue: DispatchQueue, state: TunnelManager.State, completionHandler: @escaping CompletionHandler) {
        self.queue = queue
        self.state = state

        super.init(completionQueue: queue, completionHandler: completionHandler)
    }

    override func main() {
        queue.async {
            TunnelProviderManagerType.loadAllFromPreferences { tunnels, error in
                self.queue.async {
                    if let error = error {
                        self.finish(completion: .failure(.loadAllVPNConfigurations(error)))
                    } else {
                        self.didLoadVPNConfigurations(tunnels: tunnels)
                    }
                }
            }
        }
    }

    private func didLoadVPNConfigurations(tunnels: [TunnelProviderManagerType]?) {
        let tunnelProvider = tunnels?.first

        do {
            let tunnelSettings = try TunnelSettingsManagerV2.readSettings()
            let tunnel = tunnelProvider.map { tunnelProvider in
                return Tunnel(tunnelProvider: tunnelProvider)
            }

            state.tunnelInfo = TunnelInfo(
                token: tunnelSettings.account.number,
                tunnelSettings: tunnelSettings
            )
            state.setTunnel(tunnel, shouldRefreshTunnelState: true)

            finish(completion: .success(()))
        } catch let settingsError {
            state.tunnelInfo = nil
            state.setTunnel(nil, shouldRefreshTunnelState: true)

            if case .some(.itemNotFound) = settingsError as? KeychainError {
                logger.debug("Tunnel settings not found in Keychain.")

                if let tunnelProvider = tunnelProvider {
                    removeOrphanedTunnel(tunnelProvider: tunnelProvider) { error in
                        self.finish(completion: error.map { .failure($0) } ?? .success(()))
                    }
                } else {
                    finish(completion: .success(()))
                }
            } else {
                if let decodingError = settingsError as? DecodingError {
                    do {
                        logger.error(
                            chainedError: AnyChainedError(decodingError),
                            message: "Cannot decode tunnel settings. Will attempt to delete them from Keychain."
                        )

                        try TunnelSettingsManagerV2.deleteSettings()
                    } catch {
                        logger.error(
                            chainedError: AnyChainedError(error),
                            message: "Failed to delete tunnel settings from Keychain."
                        )
                    }
                }

                let returnError: TunnelManager.Error = .readTunnelSettings(settingsError)

                if let tunnelProvider = tunnelProvider {
                    removeOrphanedTunnel(tunnelProvider: tunnelProvider) { _ in
                        self.finish(completion: .failure(returnError))
                    }
                } else {
                    finish(completion: .failure(returnError))
                }
            }
        }
    }

    private func removeOrphanedTunnel(tunnelProvider: TunnelProviderManagerType, completion: @escaping (TunnelManager.Error?) -> Void) {
        logger.debug("Remove orphaned VPN configuration.")

        tunnelProvider.removeFromPreferences { error in
            self.queue.async {
                if let error = error {
                    self.logger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to remove VPN configuration."
                    )
                    completion(.removeInconsistentVPNConfiguration(error))
                } else {
                    completion(nil)
                }
            }
        }
    }
}
