//
//  ECPublicKeyToSecKeyTests.swift
//  Tests
//
//  Created by Jarrod Moldrich on 27.10.18.
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

import XCTest
@testable import JOSESwift

class ECPublicKeyToSecKeyTests: ECCryptoTestCase {
    private func _testPublicKeyToSecKey(testData: ECTestKeyData) {
        let jwk = ECPublicKey(
                crv: ECCurveType(rawValue: testData.expectedCurveType)!,
                x: testData.expectedXCoordinateBase64Url,
                y: testData.expectedYCoordinateBase64Url)
        let key = try! jwk.converted(to: SecKey.self)

        XCTAssertEqual(SecKeyCopyExternalRepresentation(key, nil)! as Data, testData.publicKeyData)
    }

    // TODO: tests for failure cases

    func testPublicKeyToSecKey() {
        [p256, p384, p521].forEach { testData in
            _testPublicKeyToSecKey(testData: testData)
        }
    }
}
