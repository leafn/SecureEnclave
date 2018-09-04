import Security

let applicationTag: String = "com.leafn.secureenclavetest"
let operationPrompt: String = "인증이 필요합니다."

struct SecureEnclaveError : Error {
    let localizedDescription: String
    let status: OSStatus?
    
    init(status: OSStatus?, localizedDescription: String) {
        self.localizedDescription = localizedDescription
        self.status = status
    }
}

class SecureEnclave: NSObject {
    
    private var keyTypeEllipticCurve: String {
        if #available(iOS 10.0, *) {
            return kSecAttrKeyTypeECSECPrimeRandom as String
        } else {
            return kSecAttrKeyTypeEC as String
        }
    }
    
    func generateECCKeyPair(privateLabel: String, publicLabel: String, accessGroup: String?) throws {
        
        let privateAccess: SecAccessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], nil)!
        
        // private
        var privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: privateLabel,
            kSecAttrIsPermanent as String: true,
            //            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIAllow,
            //            kSecUseAuthenticationContext as String: operationPrompt
            kSecAttrAccessControl as String: privateAccess
        ]
        
        if let accessGroup = accessGroup {
            privateKeyParams[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var publicKeyParams: [String: Any] = [
            kSecAttrLabel as String: publicLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        if let accessGroup = accessGroup {
            publicKeyParams[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: keyTypeEllipticCurve,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyParams,
            kSecPublicKeyAttrs as String: publicKeyParams
        ]
        
        var error: Unmanaged<CFError>?
        guard SecKeyCreateRandomKey(attributes as CFDictionary, &error) != nil else {
            throw error!.takeRetainedValue() as Error
        }
    }
    
    func getPublicKey(label: String) throws -> Data{
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: keyTypeEllipticCurve,
            //kSecAttrApplicationTag as String: applicationTag,
            kSecAttrApplicationTag as String: label,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true,
            kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true
        ]
        
        let rawKey = try getSecKeyWithQuery(query)
        let converted = rawKey as! [String: Any]
        return converted[kSecValueData as String] as! Data
    }
    
    func getPrivateKey(label: String) throws -> SecKey{
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
            kSecUseOperationPrompt as String: operationPrompt
        ]
        
        let raw = try getSecKeyWithQuery(query)
        return raw as! SecKey
    }
    
    func getSecKeyWithQuery(_ query: [String: Any]) throws -> CFTypeRef {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(status: status, localizedDescription: "OSStatus Error")
        }
        
        return result!
    }
    
    func removePublicKey(label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: keyTypeEllipticCurve,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: label
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(status: status, localizedDescription: "OSStatus Error")
        }
    }
    
    func removePrivateKey(label: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(status: status, localizedDescription: "OSStatus Error")
        }
    }
    
    func sign(digest: Data, privateKey: SecKey) throws -> Data{
        let blockSize = 256
        let maxChunkSize = blockSize - 11
        
        guard digest.count / MemoryLayout<UInt8>.size <= maxChunkSize else {
            throw SecureEnclaveError(status: nil, localizedDescription: "data length exceeds \(maxChunkSize)")
        }
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count / MemoryLayout<UInt8>.size)
        digest.copyBytes(to: &digestBytes, count: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: blockSize)
        var signatureLength = blockSize
        
        let status = SecKeyRawSign(privateKey, .PKCS1, digestBytes, digestBytes.count, &signatureBytes, &signatureLength)
        
        guard status == errSecSuccess else {
            if status == errSecParam {
                throw SecureEnclaveError(status: status, localizedDescription: "Could not create signature due to bad parameters")
            } else {
                throw SecureEnclaveError(status: status, localizedDescription: "Could not create signature")
            }
        }
        return Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureLength)
    }
    
    func verify(signature: Data, digest: Data, publicKey: SecKey) throws -> Bool {
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        digest.copyBytes(to: &digestBytes, count: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.count)
        signature.copyBytes(to: &signatureBytes, count: signature.count)
        
        let status = SecKeyRawVerify(publicKey, .PKCS1, digestBytes, digestBytes.count, signatureBytes, signatureBytes.count)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(status: status, localizedDescription: "Could not create signature")
        }
        
        return true
    }
}
