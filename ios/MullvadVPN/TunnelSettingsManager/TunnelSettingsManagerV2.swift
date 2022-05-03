//
//  TunnelSettingsManagerV2.swift
//  MullvadVPN
//
//  Created by pronebird on 29/04/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation

enum TunnelSettingsManagerV2 {}

extension TunnelSettingsManagerV2 {
    private static var defaultAttributes: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: "Mullvad VPN",
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
}
