import UIKit
import CommonCrypto

struct SecureEnclaveError: Error {
    let message: String
    let osStatus: OSStatus?
    
    init(message: String, osStatus: OSStatus?) {
        self.message = message
        self.osStatus = osStatus
    }
}

class SecureEnclave: NSObject {
    
    let operationPrompt: String = "인증이 필요합니다."
    let publicLabel: String
    let privateLabel: String
    
    private var attrKeyTypeEllipticCurve: String {
        if #available(iOS 10.0, *) {
            return kSecAttrKeyTypeECSECPrimeRandom as String
        } else {
            return kSecAttrKeyTypeEC as String
        }
    }
    
    init(publicLabel: String, privateLabel: String) {
        self.publicLabel = publicLabel
        self.privateLabel = privateLabel
    }
    
    func generate() throws -> (SecKey, SecKey) {
        let access: SecAccessControl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
        
        let privateKeyParams: [String: Any] = [
            kSecAttrLabel as String: privateLabel,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: access,
        ]
        
        let params: [String: Any] = [
            kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyParams
        ]
        
        var publicKey, privateKey: SecKey?
        
        let status = SecKeyGeneratePair(params as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "could not generate keypair", osStatus: status)
        }
        
        return (publicKey: publicKey!, privateKey: privateKey!)
    }
    
    func publicKey() throws -> (SecKey, Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
            kSecAttrApplicationTag as String: publicLabel,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecReturnData as String: true,
            kSecReturnRef as String: true,
            kSecReturnPersistentRef as String: true,
        ]
        
        let raw = try getSecKeyWithQuery(query)
        
        return (ref: raw[kSecValueRef as String] as! SecKey, privateKey: raw[kSecValueData as String] as! Data)
    }
    
    func privateKey() throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
            kSecReturnRef as String: true
        ]
        
        let raw = try getSecKeyWithQuery(query)
        return raw as! SecKey
    }
    
    func forceSavePublicKey(publicKey: SecKey) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: publicLabel,
            kSecValueRef as String: publicKey,
            kSecAttrIsPermanent as String: true,
            kSecReturnData as String: true,
        ]
        
        var raw: CFTypeRef?
        var status = SecItemAdd(query as CFDictionary, &raw)
        
        if status == errSecDuplicateItem {
            status = SecItemDelete(query as CFDictionary)
            status = SecItemAdd(query as CFDictionary, &raw)
        }
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "could not save keypair", osStatus: status)
        }
    }
    
    func getSecKeyWithQuery(_ query: [String: Any]) throws -> CFTypeRef {
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "could not get key for query: \(query)", osStatus: status)
        }
        
        return result!
    }
    
    func removePublicKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: attrKeyTypeEllipticCurve,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrApplicationTag as String: publicLabel
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "could not delete private key", osStatus: status)
        }
    }
    
    func removePrivateKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: privateLabel,
            kSecReturnRef as String: true,
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        
        guard status == errSecSuccess else {
            throw SecureEnclaveError(message: "could not delete private key", osStatus: status)
        }
    }
    
    func sign(_ digest: Data, privateKey: SecKey) throws -> Data{
        
        let blockSize = 256
        
        var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes({digestBytes in
            digest.withUnsafeBytes({messageBytes in
                CC_SHA256(messageBytes, CC_LONG(digest.count), digestBytes)
            })
        })
        
        var digestBytes = [UInt8](repeating: 0, count: digestData.count)
        digestData.copyBytes(to: &digestBytes, count: digestData.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: blockSize)
        var signatureLength = blockSize
        
        let status = SecKeyRawSign(privateKey, .PKCS1SHA256, digestBytes, digestBytes.count, &signatureBytes, &signatureLength)
        
        guard status == errSecSuccess else {
            if status == errSecParam {
                throw SecureEnclaveError(message: "Could not create signature due to bad parameters", osStatus: status)
            } else {
                throw SecureEnclaveError(message: "Could not create signature", osStatus: status)
            }
        }
        
        return Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureLength)
    }
    
    func verify() {
        
    }
    
    func remove() {
        try! removePublicKey()
        try! removePrivateKey()
    }
    
    
}
