//
//  TunnelSettingsManagerError.swift
//  MullvadVPN
//
//  Created by pronebird on 29/04/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation

extension TunnelSettingsManager {
    enum Error: ChainedError {
        /// A failure to encode the given tunnel settings
        case encode(Swift.Error)

        /// A failure to decode the data stored in Keychain
        case decode(Swift.Error)

        /// A failure to add a new entry to Keychain
        case addEntry(Keychain.Error)

        /// A failure to update the existing entry in Keychain
        case updateEntry(Keychain.Error)

        /// A failure to remove an entry in Keychain
        case removeEntry(Keychain.Error)

        /// A failure to query the entry in Keychain
        case lookupEntry(Keychain.Error)

        /// Missing attributes required to perform an operation.
        case missingRequiredAttributes

        var errorDescription: String? {
            switch self {
            case .encode:
                return "Failure to encode settings."
            case .decode:
                return "Failure to decode settings."
            case .addEntry:
                return "Failure to add keychain entry."
            case .updateEntry:
                return "Failure to update keychain entry."
            case .removeEntry:
                return "Failure to remove keychain entry."
            case .lookupEntry:
                return "Failure to lookup keychain entry."
            case .missingRequiredAttributes:
                return "Keychain entry is missing required set of attributes."
            }
        }
    }

}
