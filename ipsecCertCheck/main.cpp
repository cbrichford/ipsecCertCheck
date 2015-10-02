//
//  main.cpp
//  ipsecCertCheck
//
//  Created by Christopher Brichford on 9/28/15.
//  Copyright © 2015 Christopher Brichford. All rights reserved.
//

#include <iostream>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdexcept>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

class MMappedData
{
public:
    MMappedData(MMappedData&& other)
        : m_start(other.m_start)
        , m_requestedSize(other.m_requestedSize)
    {
        other.m_start = 0;
    }
    
    
    ~MMappedData()
    {
        if (m_start) {
            munmap(const_cast<uint8_t*>(m_start), m_requestedSize);
        }
    }
    
    static MMappedData mapFileByName(const char* fileName)
    {
        int const fd = open(fileName, O_RDONLY);
        if (fd == -1) {
            throw std::runtime_error("Failed to open file!");
        }
        struct stat s;
        if (fstat(fd, &s) != 0) {
            throw std::runtime_error("Failed to stat file!");
        }
        
        size_t const size = s.st_size;
        
        void* const start = mmap(0, size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);
        if (!start) {
            throw std::runtime_error("Failed to mmap!!");
        }
        
        return MMappedData(reinterpret_cast<const uint8_t*>(start), size);
    }
    
    inline const uint8_t* start() const {
        return m_start;
    }
    
    inline size_t size() const {
        return m_requestedSize;
    }
    
    
private:
    
    MMappedData(const uint8_t* start, size_t requestedSize)
    : m_start(start)
    , m_requestedSize(requestedSize)
    {
    }

    
    MMappedData(const MMappedData& other);
    MMappedData& operator=(const MMappedData& other);
    
    const uint8_t* m_start;
    const size_t m_requestedSize;
};


SecCertificateRef parseCertificate(const MMappedData& data)
{
    CFDataRef const cfData = CFDataCreateWithBytesNoCopy(0, data.start(), data.size(), kCFAllocatorNull);
    if (!cfData) {
        throw std::runtime_error("Failed to allocate CFData!");
    }
    
    SecCertificateRef const cert = SecCertificateCreateWithData(0, cfData);
    CFRelease(cfData);
    return cert;
}

static SecPolicyRef createCERTPolicy(const char* hostname)
{
    size_t hostnameLen = strlen(hostname);
    CFStringRef hostnameStrRef = CFStringCreateWithBytes(kCFAllocatorDefault,
                                                         reinterpret_cast<const uint8_t*>(hostname),
                                                         hostnameLen,
                                                         kCFStringEncodingUTF8,
                                                         false);
    
    const void			*key[] = { kSecPolicyName };
    const void			*value[] = { hostnameStrRef };
    
    CFDictionaryRef const properties = CFDictionaryCreate(NULL, key, value, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!properties) {
        throw std::runtime_error("Unable to create CF dictionary!!!");
    }
    
    SecPolicyRef const policyRef = SecPolicyCreateWithProperties(kSecPolicyAppleIPsec, properties);
    CFRelease(properties);
    return policyRef;
}

static CFArrayRef createCERTChain(const MMappedData& leafCERTBytes,
                                  const MMappedData& intCERTBytes,
                                  const MMappedData& caCERTBytes)
{
    SecCertificateRef certs[] = {
        parseCertificate(leafCERTBytes),
        parseCertificate(intCERTBytes),
        parseCertificate(caCERTBytes)
    };
    
    CFArrayRef chain = CFArrayCreate(kCFAllocatorDefault, (const void**)&(certs[0]), 3, &kCFTypeArrayCallBacks);
    return chain;
}


union CFGuber {
    CFStringRef strRef;
    void* opaque;
};

inline std::string toStdString(CFStringRef s) {
    return std::string(CFStringGetCStringPtr(s,kCFStringEncodingUTF8));
}

void EvaluateCERTChain(CFArrayRef certChain, SecPolicyRef policyRef)
{
    SecTrustRef trustRef = 0;
    
    OSStatus const trustCreate = SecTrustCreateWithCertificates(certChain, policyRef, &trustRef);
    if (trustCreate != noErr) {
        throw std::runtime_error("Failed to create SecTrust!");
    }
    
    SecTrustResultType evalResult;
    OSStatus const trustEval = SecTrustEvaluate(trustRef, &evalResult);
    if (trustEval != noErr) {
        throw std::runtime_error("Trust Eval failed!!!");
    }
    if (evalResult == kSecTrustResultProceed) {
        return;
    }
    
    CFArrayRef props = SecTrustCopyProperties(trustRef);
    
    CFIndex numDictionaries = CFArrayGetCount(props);
    for (unsigned i = 0; i < numDictionaries; ++i) {
        CFDictionaryRef const d = reinterpret_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(props, i));
        size_t nEntries = CFDictionaryGetCount(d);
        CFGuber* const keys = new CFGuber[nEntries];
        CFGuber* const values = new CFGuber[nEntries];
        CFDictionaryGetKeysAndValues(d, (const void**)keys, (const void**)values);
        std::cout << "---------------------------" << std::endl;
        for (unsigned j = 0; j < nEntries; ++j) {
            std::cout << toStdString(keys[j].strRef) << " : " << toStdString(values[j].strRef) << std::endl;
        }
        delete[] keys;
        delete[] values;
    }
    std::cout << "---------------------------" << std::endl;
    
    
    
    CFRelease(props);
    
    throw std::runtime_error("Cert failed check!!!");
}



void usage() {
    std::cout << "ipsecCertCheck hostname leafCert.der intCert.der caCert.der" << std::endl;
    throw std::runtime_error("Missing argument!");
}

int main(int argc, const char * argv[]) {
    
    try {
        if (argc < 5) {
            usage();
        }
        
        MMappedData leafCERTBytes = MMappedData::mapFileByName(argv[2]);
        MMappedData intCERTBytes = MMappedData::mapFileByName(argv[3]);
        MMappedData caCERTBytes = MMappedData::mapFileByName(argv[4]);
        
        CFArrayRef const chain = createCERTChain(leafCERTBytes, intCERTBytes, caCERTBytes);
        SecPolicyRef const policy = createCERTPolicy(argv[1]);

        EvaluateCERTChain(chain, policy);
        
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
    
    
    return 0;
}
