//
//  SettingsMigration.swift
//  MullvadVPN
//
//  Created by pronebird on 06/05/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging

class SettingsMigration {
    typealias CompletionHandler = (OperationCompletion<TunnelSettingsV2?, Error>) -> Void

    private static let accountTokenKey = "accountToken"
    private static let accountExpiryKey = "accountExpiry"

    private let accountsProxy: REST.AccountsProxy
    private let logger = Logger(label: "SettingsMigration")

    private var task: Cancellable?

    init(accountsProxy: REST.AccountsProxy) {
        self.accountsProxy = accountsProxy
    }

    func perform(completionHandler: @escaping CompletionHandler) {
        // Read legacy settings from keychain.
        let settingsArray: [LegacyTunnelSettings?]
        do {
            settingsArray = try TunnelSettingsManagerV2.readLegacySettings()
        } catch .itemNotFound as KeychainError {
            // Clean up old preferences storage if keychain is empty.
            removePreferences()

            completionHandler(.success(nil))
            return
        } catch {
            completionHandler(.failure(error))
            return
        }

        // Map account number stored in preferences against legacy settings stored in keychain.
        let accountNumber = UserDefaults.standard.string(forKey: Self.accountTokenKey)
        let matchingSettings = settingsArray.first { settings in
            if let settings = settings {
                return settings.accountNumber == accountNumber
            } else {
                return false
            }
        }

        guard let matchingSettings = matchingSettings else {
            // Clean up legacy settings storage if no match found.
            if !settingsArray.isEmpty {
                removePreferences()
                removeLegacyKeychainItems()
            }

            completionHandler(.success(nil))
            return
        }

        migrateSettings(legacySettings: matchingSettings!) { completion in
            switch completion {
            case .success:
                // Clean up legacy settings storage.
                self.removePreferences()
                self.removeLegacyKeychainItems()

                self.logger.debug("Finished migration.")

            case .failure(let error):
                self.logger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to migrate legacy settings."
                )

            case .cancelled:
                self.logger.debug("Migration was cancelled.")
            }

            completionHandler(completion)
        }
    }

    private func migrateSettings(
        legacySettings: LegacyTunnelSettings,
        completionHandler: @escaping CompletionHandler
    ) {
        task = accountsProxy.getAccountData(
            accountNumber: legacySettings.accountNumber,
            retryStrategy: .aggressive
        ) { completion in
            let mappedCompletion = completion.tryMap { accountData -> TunnelSettingsV2? in
                do {
                    return try self.storeNewSettings(
                        accountData: accountData,
                        matchingSettings: legacySettings
                    )
                } catch {
                    self.logger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to write new settings."
                    )
                    throw error
                }
            }

            completionHandler(mappedCompletion)
        }
    }

    private func storeNewSettings(accountData: REST.AccountData, matchingSettings: LegacyTunnelSettings) throws -> TunnelSettingsV2 {
        let oldSettings = matchingSettings.tunnelSettings
        let interface = oldSettings.interface

        let newSettings = TunnelSettingsV2(
            account: StoredAccountData(
                identifier: accountData.id,
                number: matchingSettings.accountNumber,
                expiry: accountData.expiry
            ),
            device: nil,
            interface: InterfaceData(
                creationDate: interface.privateKey.creationDate,
                privateKey: interface.privateKey.privateKey,
                nextPrivateKey: interface.nextPrivateKey?.privateKey,
                addresses: interface.addresses
            ),
            relayConstraints: oldSettings.relayConstraints,
            dnsSettings: interface.dnsSettings
        )

        try TunnelSettingsManagerV2.writeSettings(newSettings)

        return newSettings
    }

    private func removePreferences() {
        logger.debug("Remove legacy data from preferences...")

        UserDefaults.standard.removeObject(forKey: Self.accountTokenKey)
        UserDefaults.standard.removeObject(forKey: Self.accountExpiryKey)
    }

    private func removeLegacyKeychainItems() {
        logger.debug("Remove legacy settings from keychain...")

        TunnelSettingsManagerV2.deleteLegacySettings()
    }
}
