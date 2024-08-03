package com.trodix.demo.sslbundlemanage;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ssl-bundles")
public class SSLBundlesController {

    private final CertificateUtils certificateUtils;

    public SSLBundlesController(CertificateUtils certificateUtils) {
        this.certificateUtils = certificateUtils;
    }

    @GetMapping
    public Map<String, List<CertificateUtils.CertInfo>> info() {
        return certificateUtils.getBundlesCertificates();
    }

}