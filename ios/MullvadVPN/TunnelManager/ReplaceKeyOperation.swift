//
//  ReplaceKeyOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 15/12/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import class WireGuardKitTypes.PrivateKey

class ReplaceKeyOperation: ResultOperation<TunnelManager.KeyRotationResult, TunnelManager.Error> {
    private let queue: DispatchQueue
    private let state: TunnelManager.State

    private let devicesProxy: REST.DevicesProxy
    private var task: Cancellable?

    private let rotationInterval: TimeInterval?

    private let logger = Logger(label: "TunnelManager.ReplaceKeyOperation")

    class func operationForKeyRotation(
        queue: DispatchQueue,
        state: TunnelManager.State,
        devicesProxy: REST.DevicesProxy,
        rotationInterval: TimeInterval,
        completionHandler: @escaping CompletionHandler
    ) -> ReplaceKeyOperation {
        return ReplaceKeyOperation(
            queue: queue,
            state: state,
            devicesProxy: devicesProxy,
            rotationInterval: rotationInterval,
            completionHandler: completionHandler
        )
    }

    class func operationForKeyRegeneration(
        queue: DispatchQueue,
        state: TunnelManager.State,
        devicesProxy: REST.DevicesProxy,
        completionHandler: @escaping (OperationCompletion<(), TunnelManager.Error>) -> Void
    ) -> ReplaceKeyOperation {
        return ReplaceKeyOperation(
            queue: queue,
            state: state,
            devicesProxy: devicesProxy,
            rotationInterval: nil
        ) { completion in
            let mappedCompletion = completion.map { keyRotationResult -> () in
                switch keyRotationResult {
                case .finished:
                    return ()
                case .throttled:
                    fatalError("ReplaceKeyOperation.operationForKeyRegeneration() must never recieve throttled!")
                }
            }

            completionHandler(mappedCompletion)
        }
    }

    private init(
        queue: DispatchQueue,
        state: TunnelManager.State,
        devicesProxy: REST.DevicesProxy,
        rotationInterval: TimeInterval?,
        completionHandler: @escaping CompletionHandler
    ) {
        self.queue = queue
        self.state = state

        self.devicesProxy = devicesProxy
        self.rotationInterval = rotationInterval

        super.init(completionQueue: queue, completionHandler: completionHandler)
    }

    override func main() {
        queue.async {
            guard !self.isCancelled else {
                self.finish(completion: .cancelled)
                return
            }

            guard let tunnelInfo = self.state.tunnelInfo else {
                self.finish(completion: .failure(.unsetAccount))
                return
            }

            if let rotationInterval = self.rotationInterval {
                let creationDate = tunnelInfo.tunnelSettings.interface.creationDate
                let nextRotationDate = creationDate.addingTimeInterval(rotationInterval)

                if nextRotationDate > Date() {
                    self.logger.debug("Throttle private key rotation.")

                    self.finish(completion: .success(.throttled(creationDate)))
                    return
                } else {
                    self.logger.debug("Private key is old enough, rotate right away.")
                }
            } else {
                self.logger.debug("Rotate private key right away.")
            }

            let newPrivateKey: PrivateKey

            if let nextPrivateKey = tunnelInfo.tunnelSettings.interface.nextPrivateKey {
                newPrivateKey = nextPrivateKey

                self.logger.debug("Next private key is already created.")
            } else {
                newPrivateKey = PrivateKey()

                self.logger.debug("Create next private key.")

                do {
                    var newTunnelSettings = tunnelInfo.tunnelSettings

                    newTunnelSettings.interface.nextPrivateKey = newPrivateKey

                    try TunnelSettingsManagerV2.writeSettings(newTunnelSettings)

                    self.logger.debug("Saved next private key.")

                    self.state.tunnelInfo?.tunnelSettings = newTunnelSettings
                } catch {
                    self.logger.error(chainedError: AnyChainedError(error), message: "Failed to save next private key.")

                    self.finish(completion: .failure(.updateTunnelSettings(error)))
                    return
                }
            }

            self.logger.debug("Replacing old key with new key on server...")

            // TODO: handle missing device data

            self.task = self.devicesProxy.rotateDeviceKey(
                accountNumber: tunnelInfo.tunnelSettings.account.number,
                identifier: tunnelInfo.tunnelSettings.device!.identifier,
                publicKey: newPrivateKey.publicKey,
                retryStrategy: .default
            ) { completion in
                self.queue.async {
                    switch completion {
                    case .success(let associatedAddresses):
                        self.logger.debug("Replaced old key with new key on server.")

                        do {
                            var tunnelSettings = tunnelInfo.tunnelSettings
                            tunnelSettings.interface.creationDate = Date()
                            tunnelSettings.interface.privateKey = newPrivateKey
                            tunnelSettings.interface.nextPrivateKey = nil
                            tunnelSettings.interface.addresses = [
                                associatedAddresses.ipv4Address,
                                associatedAddresses.ipv6Address
                            ]

                            try TunnelSettingsManagerV2.writeSettings(tunnelSettings)

                            self.logger.debug("Saved associated addresses.")

                            self.state.tunnelInfo?.tunnelSettings = tunnelSettings

                            self.finish(completion: .success(.finished))
                        } catch {
                            self.logger.error(
                                chainedError: AnyChainedError(error),
                                message: "Failed to write tunnel settings."
                            )

                            self.finish(completion: .failure(.updateTunnelSettings(error)))
                        }

                    case .failure(let restError):
                        self.logger.error(
                            chainedError: restError,
                            message: "Failed to replace old key with new key on server."
                        )

                        self.finish(completion: .failure(.replaceWireguardKey(restError)))

                    case .cancelled:
                        self.logger.debug("Cancelled replace key request.")

                        self.finish(completion: .cancelled)
                    }
                }
            }
        }
    }

    override func cancel() {
        super.cancel()

        queue.async {
            self.task?.cancel()
        }
    }
}
