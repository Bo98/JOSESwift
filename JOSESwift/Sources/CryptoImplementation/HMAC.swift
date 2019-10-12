//
//  HMAC.swift
//  JOSESwift
//
//  Created by Carol Capek on 05.12.17.
//
//  ---------------------------------------------------------------------------
//  Copyright 2018 Airside Mobile Inc.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//  ---------------------------------------------------------------------------
//

import Foundation
import CommonCrypto

enum HMACError: Error {
    case inputMustBeGreaterThanZero
    case algorithmNotSupported
}

fileprivate extension HMACAlgorithm {
    var ccAlgorithm: CCAlgorithm {
        switch self {
		case .SHA256:
			return CCAlgorithm(kCCHmacAlgSHA256)
		case .SHA384:
			return CCAlgorithm(kCCHmacAlgSHA384)
        case .SHA512:
            return CCAlgorithm(kCCHmacAlgSHA512)
        }
    }
}

fileprivate extension SignatureAlgorithm {
	var hmacAlgorithm: HMACAlgorithm? {
		switch self {
		case .HS256:
			return .SHA256
		case .HS384:
			return .SHA384
		case .HS512:
			return .SHA512
		default:
			return nil
		}
	}
}

internal struct HMAC {
	typealias KeyType = Data

	/// Helper method that converts SignatureAlgorithm to HMACAlgorithm before calling the calculate method below.
	///
	/// - Parameters:
	///   - input: The input to calculate a HMAC for.
	///   - key: The key used in the HMAC algorithm.
	///   - algorithm: The algorithm used to calculate the HMAC.
	/// - Returns: The calculated HMAC.
	/// - Throws: `HMACError` if the algorithm is invalid.
	static func calculate(from input: Data, with key: KeyType, using algorithm: SignatureAlgorithm) throws -> Data {
		guard let algorithm = algorithm.hmacAlgorithm else {
			throw HMACError.algorithmNotSupported
		}
		return try HMAC.calculate(from: input, with: key, using: algorithm)
	}

    /// Calculates a HMAC of an input with a specific HMAC algorithm and the corresponding HMAC key.
    ///
    /// - Parameters:
    ///   - input: The input to calculate a HMAC for.
    ///   - key: The key used in the HMAC algorithm. Must not be empty.
    ///   - algorithm: The algorithm used to calculate the HMAC.
    /// - Returns: The calculated HMAC.
    static func calculate(from input: Data, with key: KeyType, using algorithm: HMACAlgorithm) throws -> Data {
        guard input.count > 0 else {
            throw HMACError.inputMustBeGreaterThanZero
        }

        var hmacOutData = Data(count: algorithm.outputLength)

        // Force unwrapping is ok, since input count is checked and key and algorithm are assumed not to be empty.
        // From the docs: If the baseAddress of this buffer is nil, the count is zero.
        // swiftlint:disable force_unwrapping
        hmacOutData.withUnsafeMutableBytes { hmacOutBytes in
            key.withUnsafeBytes { keyBytes in
                input.withUnsafeBytes { inputBytes in
                    CCHmac(
                        algorithm.ccAlgorithm,
                        keyBytes.baseAddress!, key.count,
                        inputBytes.baseAddress!, input.count,
                        hmacOutBytes.baseAddress!
                    )
                }
            }
        }
        // swiftlint:enable force_unwrapping

        return hmacOutData
    }
}
