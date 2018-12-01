//
//  HMACVerifier.swift
//  JOSESwift
//
//  Created by Bo Anderson on 01/12/2018.
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

/// A `Verifier` to verify a signature created with a `HMAC` algorithm.
internal struct HMACVerifier: VerifierProtocol {
	typealias KeyType = HMAC.KeyType

	let algorithm: SignatureAlgorithm
	let key: KeyType

	func verify(_ verifyingInput: Data, against signature: Data) throws -> Bool {
		return try HMAC.calculate(from: verifyingInput, with: key, using: algorithm) == signature
	}
}
