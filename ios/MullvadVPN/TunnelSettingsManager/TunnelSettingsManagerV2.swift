//
//  TunnelSettingsManagerV2.swift
//  MullvadVPN
//
//  Created by pronebird on 29/04/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging

enum TunnelSettingsManagerV2 {}

struct LegacyTunnelSettings {
    let accountNumber: String
    let tunnelSettings: TunnelSettingsV1
}

extension TunnelSettingsManagerV2 {
    private static let serviceName = "Mullvad VPN"

    private static var defaultAttributes: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: serviceName,
        kSecAttrAccount: ""
    ]

    static func readSettings() throws -> TunnelSettingsV2 {
        var query = defaultAttributes
        query[kSecReturnData] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainError(code: status)
        }

        let dict = result as! [CFString: Any]
        let data = dict[kSecValueData] as! Data

        let decoder = JSONDecoder()
        return try decoder.decode(TunnelSettingsV2.self, from: data)
    }

    static func writeSettings(_ settings: TunnelSettingsV2) throws {
        let encoder = JSONEncoder()
        let data = try encoder.encode(settings)

        var update = defaultAttributes
        update[kSecValueData] = data

        var status = SecItemUpdate(
            defaultAttributes as CFDictionary,
            update as CFDictionary
        )

        switch status {
        case errSecItemNotFound:
            var insert = defaultAttributes
            insert[kSecAttrAccessGroup] = ApplicationConfiguration.securityGroupIdentifier
            insert[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlock
            insert[kSecValueData] = data

            status = SecItemAdd(insert as CFDictionary, nil)
            if status != errSecSuccess {
                throw KeychainError(code: status)
            }

        case errSecSuccess:
            break

        default:
            throw KeychainError(code: status)
        }
    }

    static func deleteSettings() throws {
        let status = SecItemDelete(defaultAttributes as CFDictionary)
        if status != errSecSuccess {
            throw KeychainError(code: status)
        }
    }

    // MARK: - Legacy settings support

    private static let logger = Logger(label: "TunnelSettingsManagerV2")

    static func readLegacySettings() throws -> [LegacyTunnelSettings] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName
        ]
        query[kSecReturnAttributes] = true
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            throw KeychainError(code: status)
        }

        guard let items = result as? [[CFString: Any]] else {
            return []
        }

        return items.compactMap { item -> LegacyTunnelSettings? in
            guard let accountNumber = item[kSecAttrAccount] as? String,
                  let data = item[kSecValueData] as? Data else {
                      return nil
                  }

            // New entries set account attribute to empty string.
            guard accountNumber != "" else {
                return nil
            }

            do {
                let tunnelSettings = try JSONDecoder().decode(
                    TunnelSettingsV1.self,
                    from: data
                )

                return LegacyTunnelSettings(
                    accountNumber: accountNumber,
                    tunnelSettings: tunnelSettings
                )
            } catch {
                logger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to decode legacy tunnel settings."
                )
                return nil
            }
        }
    }

    static func deleteLegacySettings() {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName
        ]
        query[kSecReturnAttributes] = true
        query[kSecReturnRef] = true
        query[kSecMatchLimit] = kSecMatchLimitAll

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            let error = KeychainError(code: status)

            if error != .itemNotFound {
                logger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to list legacy settings."
                )
            }

            return
        }

        guard let items = result as? [[CFString: Any]] else {
            return
        }

        for (index, item) in items.enumerated() {
            guard let accountNumber = item[kSecAttrAccount] as? String,
                  let itemRef = item[kSecValueRef] else {
                      continue
                  }

            // New entries set account attribute to empty string.
            guard accountNumber != "" else {
                continue
            }

            let status = SecItemDelete([kSecValueRef: itemRef] as CFDictionary)
            if status != errSecSuccess {
                let error = KeychainError(code: status)

                logger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to remove legacy settings entry \(index)"
                )
            }
        }
    }
}
