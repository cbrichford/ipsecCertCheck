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
#include <vector>

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


template <class t_CFRef> class CFRef
{
public:
    
    
    
    CFRef()
    : m_cfRef(0)
    {
    }
    
    CFRef(const CFRef<t_CFRef> &other)
    : m_cfRef(other.m_cfRef)
    {
        if (m_cfRef)
            CFRetain(m_cfRef);
    }
    
    CFRef(CFRef<t_CFRef> &&other)
    : m_cfRef(other.m_cfRef)
    {
        other.m_cfRef = 0;
    }
    
    
    ~CFRef()
    {
        if (m_cfRef)
            CFRelease(m_cfRef);
    }
    
    operator t_CFRef() const
    {
        return m_cfRef;
    }
    
    template <typename... t_Args, typename t_F>
    static CFRef<t_CFRef> create(t_F f, t_Args... args)
    {
        return CFRef(f(args...));
    }
    
    template <typename t_Return, typename... t_Args, typename t_F>
    static std::pair<t_Return, CFRef<t_CFRef>> createWithLastOutParam(t_F f, t_Args... args)
    {
        t_CFRef result = 0;
        t_Return ret = f(args..., &result);
        return std::pair<t_Return, CFRef<t_CFRef> >(ret, CFRef(result));
    }
    
    
    CFRef<t_CFRef>& operator=(const CFRef<t_CFRef>& other)
    {
        if (m_cfRef)
            CFRelease(m_cfRef);
        m_cfRef = other.m_cfRef;
        if (m_cfRef)
            CFRetain(m_cfRef);
        return *this;
    }
    
    operator bool() const
    {
        return m_cfRef;
    }
    
private:
    
    CFRef(t_CFRef cfRef)
    : m_cfRef(cfRef)
    {
    }
    
    t_CFRef m_cfRef;
};




CFRef<SecCertificateRef> parseCertificate(const MMappedData& data)
{
    CFRef<CFDataRef> const cfData =
        CFRef<CFDataRef>::create(CFDataCreateWithBytesNoCopy,
                                 kCFAllocatorDefault,
                                 data.start(),
                                 data.size(),
                                 kCFAllocatorNull);
    if (!cfData) {
        throw std::runtime_error("Failed to allocate CFData!");
    }
    
    return CFRef<SecCertificateRef>::create(SecCertificateCreateWithData,
                                            kCFAllocatorDefault,
                                            cfData);
}

static CFRef<SecPolicyRef> createCERTPolicy(const char* hostname)
{
    size_t hostnameLen = strlen(hostname);
    CFRef<CFStringRef> const hostnameStrRef =
        CFRef<CFStringRef>::create(CFStringCreateWithBytes,
                                   kCFAllocatorDefault,
                                   reinterpret_cast<const uint8_t*>(hostname),
                                   hostnameLen,
                                   kCFStringEncodingUTF8,
                                   false);
    
    const void			*key[] = { kSecPolicyName };
    const void			*value[] = { hostnameStrRef };
    
    CFRef<CFDictionaryRef> const properties = CFRef<CFDictionaryRef>::create(CFDictionaryCreate,
                                                                             kCFAllocatorDefault,
                                                                             key,
                                                                             value,
                                                                             1,
                                                                             &kCFTypeDictionaryKeyCallBacks,
                                                                             &kCFTypeDictionaryValueCallBacks);
    if (!properties) {
        throw std::runtime_error("Unable to create CF dictionary!!!");
    }
    
    return CFRef<SecPolicyRef>::create(SecPolicyCreateWithProperties, kSecPolicyAppleIPsec, properties);
}

static CFRef<CFArrayRef> createCERTChain(const std::vector<MMappedData>& certsBytes)
{
    std::vector<CFRef<SecCertificateRef>> certs;
    for (auto i = certsBytes.begin(); i != certsBytes.end(); ++i)
    {
        certs.emplace_back(parseCertificate(*i));
    }
    
    std::vector<SecCertificateRef> rawCertRefs;
    for (auto i = certs.begin(); i != certs.end(); ++i)
    {
        rawCertRefs.emplace_back(*i);
    }

    
    CFRef<CFArrayRef> chain =
        CFRef<CFArrayRef>::create(CFArrayCreate,
                                  kCFAllocatorDefault,
                                  (const void**)rawCertRefs.data(),
                                  rawCertRefs.size(),
                                  &kCFTypeArrayCallBacks);
    return chain;
}


union CFGuber {
    CFStringRef strRef;
    void* opaque;
};

inline std::string toStdString(CFStringRef s) {
    return std::string(CFStringGetCStringPtr(s,kCFStringEncodingUTF8));
}

void EvaluateCERTChain(const CFRef<CFArrayRef>& certChain, const CFRef<SecPolicyRef>& policyRef)
{
    std::pair<OSStatus, CFRef<SecTrustRef>> trustCreate =
        CFRef<SecTrustRef>::createWithLastOutParam<OSStatus>(SecTrustCreateWithCertificates,
                                                             certChain,
                                                             policyRef);
    
    if (trustCreate.first != noErr) {
        throw std::runtime_error("Failed to create SecTrust!");
    }
    
    SecTrustResultType evalResult;
    OSStatus const trustEval = SecTrustEvaluate(trustCreate.second, &evalResult);
    if (trustEval != noErr) {
        throw std::runtime_error("Trust Eval failed!!!");
    }
    if (evalResult == kSecTrustResultProceed) {
        return;
    }
    
    CFRef<CFArrayRef> const props =
        CFRef<CFArrayRef>::create(SecTrustCopyProperties, trustCreate.second);
    
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
    
    
    
    throw std::runtime_error("Cert failed check!!!");
}



void usage() {
    std::cout << "ipsecCertCheck hostname leafCert.der [[intCert.der ...] caCert.der" << std::endl;
    throw std::runtime_error("Missing argument!");
}

int main(int argc, const char * argv[]) {
    
    try {
        if (argc < 3) {
            usage();
        }
        
        std::vector<MMappedData> certBytes;
        for (int i = 2; i < argc; ++i) {
            certBytes.emplace_back(MMappedData::mapFileByName(argv[i]));
        }
        
        CFRef<CFArrayRef> const chain = createCERTChain(certBytes);
        CFRef<SecPolicyRef> const policy = createCERTPolicy(argv[1]);

        EvaluateCERTChain(chain, policy);
        
    }
    catch (const std::runtime_error& e) {
        std::cerr << e.what() << std::endl;
    }
    
    
    return 0;
}
