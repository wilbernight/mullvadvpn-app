//
//  TunnelSettingsManager.swift
//  MullvadVPN
//
//  Created by pronebird on 02/10/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Security

/// Service name used for keychain items
private let kServiceName = "Mullvad VPN"

enum TunnelSettingsManager {}

extension TunnelSettingsManager {
    typealias Result<T> = Swift.Result<T, Error>

    /// Keychain access level that should be used for all items containing tunnel settings
    private static let keychainAccessibleLevel = Keychain.Accessible.afterFirstUnlock

    enum KeychainSearchTerm {
        case accountToken(String)
        case persistentReference(Data)

        /// Returns `Keychain.Attributes` appropriate for adding or querying the item
        fileprivate func makeKeychainAttributes() -> Keychain.Attributes {
            var attributes = Keychain.Attributes()
            attributes.class = .genericPassword

            switch self {
            case .accountToken(let accountToken):
                attributes.account = accountToken
                attributes.service = kServiceName

            case .persistentReference(let persistentReference):
                attributes.valuePersistentReference = persistentReference
            }

            return attributes
        }
    }

    struct KeychainEntry {
        let accountToken: String
        let tunnelSettings: TunnelSettingsV1
    }

    static func load(searchTerm: KeychainSearchTerm) -> Result<KeychainEntry> {
        var query = searchTerm.makeKeychainAttributes()
        query.return = [.data, .attributes]

        return Keychain.findFirst(query: query)
            .mapError { .lookupEntry($0) }
            .flatMap { (attributes) in
                guard let account = attributes?.account, let data = attributes?.valueData else {
                    return .failure(.missingRequiredAttributes)
                }

                return Self.decode(data: data)
                    .map { KeychainEntry(accountToken: account, tunnelSettings: $0) }
            }
    }

    static func add(configuration: TunnelSettingsV1, account: String) -> Result<()> {
        Self.encode(tunnelConfig: configuration)
            .flatMap { (data) -> Result<()> in
                var attributes = KeychainSearchTerm.accountToken(account)
                    .makeKeychainAttributes()

                // Share the item with the application group
                attributes.accessGroup = ApplicationConfiguration.securityGroupIdentifier

                // Make sure the keychain item is available after the first unlock to enable
                // automatic key rotation in background (from the packet tunnel process)
                attributes.accessible = Self.keychainAccessibleLevel

                // Store value
                attributes.valueData = data

                return Keychain.add(attributes)
                    .mapError { .addEntry($0) }
                    .map { _ in () }
        }
    }

    /// Migrate keychain entries created by 2020.2 or before by adding the appropriate
    /// access attribute to them so that the Packet Tunnel could read the entries.
    static func migrateKeychainEntry(searchTerm: KeychainSearchTerm) -> Result<Bool> {
        var queryAttributes = searchTerm.makeKeychainAttributes()
        queryAttributes.return = [.attributes]

        return Keychain.findFirst(query: queryAttributes)
            .mapError { .lookupEntry($0) }
            .flatMap { itemAttributes -> Result<Bool> in
                let searchAttributes = searchTerm.makeKeychainAttributes()
                var updateAttributes = Keychain.Attributes()

                // Fix the access permission for Keychain entry
                if itemAttributes?.accessible != Self.keychainAccessibleLevel {
                    updateAttributes.accessible = Self.keychainAccessibleLevel
                }

                // Return immediately if nothing to update (i.e the keychain query is empty)
                if updateAttributes.keychainRepresentation().isEmpty {
                    return .success(false)
                } else {
                    return Keychain.update(query: searchAttributes, update: updateAttributes)
                        .mapError { .updateEntry($0) }
                        .map { true }
                }
        }
    }

    /// Reads the tunnel settings from Keychain, then passes it to the given closure for
    /// modifications, saves the result back to Keychain.
    ///
    /// The given block may run multiple times if Keychain entry was changed between read and write
    /// operations.
    static func update(searchTerm: KeychainSearchTerm,
                       using changeConfiguration: (inout TunnelSettingsV1) -> Void) -> Result<TunnelSettingsV1>
    {
        var searchQuery = searchTerm.makeKeychainAttributes()
        searchQuery.return = [.attributes, .data]

        let result = Keychain.findFirst(query: searchQuery)
            .mapError { .lookupEntry($0) }
            .flatMap { itemAttributes -> Result<TunnelSettingsV1> in
                guard let serializedData = itemAttributes?.valueData,
                      let account = itemAttributes?.account else { return .failure(.missingRequiredAttributes) }

                return Self.decode(data: serializedData)
                    .flatMap { (tunnelConfig) -> Result<TunnelSettingsV1> in
                        var tunnelConfig = tunnelConfig
                        changeConfiguration(&tunnelConfig)

                        return Self.encode(tunnelConfig: tunnelConfig)
                            .flatMap { (newData) -> Result<TunnelSettingsV1> in
                                // `SecItemUpdate` does not accept query parameters when using
                                // persistent reference, so constraint the query to account
                                // token instead now when we know it
                                let updateQuery = KeychainSearchTerm
                                    .accountToken(account)
                                    .makeKeychainAttributes()

                                var updateAttributes = Keychain.Attributes()
                                updateAttributes.valueData = newData

                                return Keychain.update(query: updateQuery, update: updateAttributes)
                                    .mapError { .updateEntry($0) }
                                    .map { tunnelConfig }
                            }
                    }
            }

        return result
    }

    static func remove(searchTerm: KeychainSearchTerm) -> Result<()> {
        return Keychain.delete(query: searchTerm.makeKeychainAttributes())
            .mapError { .removeEntry($0) }
    }

    /// Get a persistent reference to the Keychain item for the given account token
    static func getPersistentKeychainReference(account: String) -> Result<Data> {
        var query = KeychainSearchTerm.accountToken(account)
            .makeKeychainAttributes()
        query.return = [.persistentReference]

        return Keychain.findFirst(query: query)
            .mapError { .lookupEntry($0) }
            .flatMap { attributes -> Result<Data> in
                guard let persistentReference = attributes?.valuePersistentReference else {
                    return .failure(.missingRequiredAttributes)
                }
                return .success(persistentReference)
        }
    }

    /// Verify that the keychain entry exists.
    /// Returns an error in case of failure to access Keychain.
    static func exists(searchTerm: KeychainSearchTerm) -> Result<Bool> {
        let query = searchTerm.makeKeychainAttributes()

        return Keychain.findFirst(query: query)
            .map({ (attributes) -> Bool in
                return true
            })
            .flatMapError({ (error) -> Result<Bool> in
                if case .itemNotFound = error {
                    return .success(false)
                } else {
                    return .failure(.lookupEntry(error))
                }
            })
    }

    private static func encode(tunnelConfig: TunnelSettingsV1) -> Result<Data> {
        return Swift.Result { try JSONEncoder().encode(tunnelConfig) }
            .mapError { .encode($0) }
    }

    private static func decode(data: Data) -> Result<TunnelSettingsV1> {
        return Swift.Result { try JSONDecoder().decode(TunnelSettingsV1.self, from: data) }
            .mapError { .decode($0) }
    }
}
