//
//  SetAccountOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 16/12/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import class WireGuardKitTypes.PublicKey
import Logging

class SetAccountOperation: ResultOperation<(), TunnelManager.Error> {
    typealias WillDeleteVPNConfigurationHandler = () -> Void

    private let queue: DispatchQueue
    private let state: TunnelManager.State
    private let devicesProxy: REST.DevicesProxy
    private let accountNumber: String?
    private var task: Cancellable?

    private var willDeleteVPNConfigurationHandler: WillDeleteVPNConfigurationHandler?
    private let logger = Logger(label: "TunnelManager.SetAccountOperation")

    init(
        queue: DispatchQueue,
        state: TunnelManager.State,
        devicesProxy: REST.DevicesProxy,
        accountNumber: String?,
        willDeleteVPNConfigurationHandler: @escaping WillDeleteVPNConfigurationHandler,
        completionHandler: @escaping CompletionHandler
    )
    {
        self.queue = queue
        self.state = state
        self.devicesProxy = devicesProxy
        self.accountNumber = accountNumber
        self.willDeleteVPNConfigurationHandler = willDeleteVPNConfigurationHandler

        super.init(completionQueue: queue, completionHandler: completionHandler)
    }

    override func main() {
        queue.async {
            guard !self.isCancelled else {
                self.finish(completion: .cancelled)
                return
            }

            if let tunnelInfo = self.state.tunnelInfo {
                self.logger.debug("Delete current device...")

                let tunnelSettings = tunnelInfo.tunnelSettings

                let handleCompletion = { (_ completion: OperationCompletion<Bool, REST.Error>) in
                    switch completion {
                    case .success(let isDeleted):
                        if isDeleted {
                            self.logger.debug("Deleted device.")
                        } else {
                            self.logger.debug("Device is already deleted.")
                        }

                        self.deleteKeychainEntryAndVPNConfiguration { error in
                            if let error = error {
                                self.finish(completion: .failure(error))
                            } else {
                                self.createDevice { completion in
                                    self.finish(completion: completion)
                                }
                            }
                        }

                    case .failure(let error):
                        self.logger.error(chainedError: error, message: "Failed to delete a device.")
                        self.finish(completion: .failure(.deleteDevice(error)))

                    case .cancelled:
                        self.logger.debug("Device deletion was cancelled.")
                        self.finish(completion: .cancelled)
                    }
                }

                self.task = self.devicesProxy.deleteDevice(
                    accountNumber: tunnelInfo.token,
                    identifier: tunnelSettings.device.identifier,
                    retryStrategy: .default
                ) { completion in
                    self.queue.async {
                        handleCompletion(completion)
                    }
                }
            } else {
                self.createDevice { completion in
                    self.finish(completion: completion)
                }
            }
        }
    }

    private func createDevice(completionHandler: @escaping CompletionHandler) {
        guard let accountNumber = accountNumber else {
            logger.debug("Account number is unset.")
            completionHandler(.success(()))
            return
        }

        logger.debug("Create new device...")

        let newPrivateKey = PrivateKeyWithMetadata()

        let request = REST.CreateDeviceRequest(
            publicKey: newPrivateKey.publicKey,
            hijackDNS: false
        )

        let handleCompletion = { (_ completion: OperationCompletion<REST.Device, REST.Error>) in
            switch completion {
            case .success(let device):
                self.logger.debug("Created device.")

                let tunnelSettings = TunnelSettingsV2(
                    account: StoredAccountData(
                        number: accountNumber,
                        expiry: Date() // TODO: obtain account expiry.
                    ),
                    device: StoredDeviceData(
                        creationDate: device.created,
                        identifier: device.id,
                        name: device.name,
                        privateKey: newPrivateKey,
                        nextPrivateKey: nil,
                        addresses: [
                            device.ipv4Address,
                            device.ipv6Address
                        ]
                    ),
                    relayConstraints: RelayConstraints(),
                    dnsSettings: DNSSettings()
                )

                self.logger.debug("Write tunnel settings.")
                do {
                    try TunnelSettingsManagerV2.writeSettings(tunnelSettings)
                } catch {
                    self.logger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to write tunnel settings."
                    )

                    completionHandler(.failure(.addTunnelSettings(error)))
                    return
                }

                completionHandler(.success(()))

            case .failure(let error):
                self.logger.error(chainedError: error, message: "Failed to create a device.")
                completionHandler(.failure(.createDevice(error)))

            case .cancelled:
                self.logger.debug("Device creation was cancelled.")
                completionHandler(.cancelled)
            }
        }

        task = devicesProxy.createDevice(
            accountNumber: accountNumber,
            request: request,
            retryStrategy: .default
        ) { completion in
            self.queue.async {
                handleCompletion(completion)
            }
        }
    }

    private func deleteKeychainEntryAndVPNConfiguration(completionHandler: @escaping (TunnelManager.Error?) -> Void) {
        // Delete keychain entry.
        do {
            try TunnelSettingsManagerV2.deleteSettings()
            self.logger.debug("Removed tunnel settings.")
        } catch {
            if let keychainError = error as? KeychainError, keychainError != .itemNotFound {
                self.logger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to remove tunnel settings."
                )
                completionHandler(.removeTunnelSettings(error))
                return
            }
        }

        // Tell the caller to unsubscribe from VPN status notifications.
        willDeleteVPNConfigurationHandler?()
        willDeleteVPNConfigurationHandler = nil

        // Reset tunnel state to disconnected
        state.tunnelStatus.reset(to: .disconnected)

        // Remove tunnel info
        state.tunnelInfo = nil

        // Finish immediately if tunnel provider is not set.
        guard let tunnel = state.tunnel else {
            completionHandler(nil)
            return
        }

        // Remove VPN configuration
        tunnel.removeFromPreferences { error in
            self.queue.async {
                // Ignore error but log it
                if let error = error {
                    self.logger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to remove VPN configuration."
                    )
                }

                self.state.setTunnel(nil, shouldRefreshTunnelState: false)

                completionHandler(nil)
            }
        }
    }
}
