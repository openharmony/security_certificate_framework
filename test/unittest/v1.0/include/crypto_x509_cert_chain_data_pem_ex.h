/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CRYPTO_X509_CERT_CHAIN_DATA_PEM_EX_H
#define CRYPTO_X509_CERT_CHAIN_DATA_PEM_EX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

static const char g_testCertChainPem163[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIHhjCCBm6gAwIBAgIQCiHYt41dl8jvQUTy1HbbZTANBgkqhkiG9w0BAQsFADBE\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMR4wHAYDVQQDExVE\r\n"
    "aWdpQ2VydCBFViBSU0EgQ0EgRzIwHhcNMjMxMDA2MDAwMDAwWhcNMjQwNzMwMjM1\r\n"
    "OTU5WjCBwTETMBEGCysGAQQBgjc8AgEDEwJVUzEVMBMGCysGAQQBgjc8AgECEwRV\r\n"
    "dGFoMR0wGwYDVQQPDBRQcml2YXRlIE9yZ2FuaXphdGlvbjEVMBMGA1UEBRMMNTI5\r\n"
    "OTUzNy0wMTQyMQswCQYDVQQGEwJVUzENMAsGA1UECBMEVXRhaDENMAsGA1UEBxME\r\n"
    "TGVoaTEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xGTAXBgNVBAMTEHd3dy5kaWdp\r\n"
    "Y2VydC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY3zNZwTun\r\n"
    "OIxdni/jz8vqUDo2/nenmFJNwsqUeI/m81ddOHfy09drpJBC93EeWGqSDZWRXzJx\r\n"
    "sZMc9dvgCtbSqNpvGoA5V03lr5dYUtGsQhjhmS9esL0dO/KMXoytp5n1pVHRYUpl\r\n"
    "qRcjnrsQhrU2nqozh4wAbyjsKlzZUU5cNAgkOo9hhaixj2yecn6hi4gxgQfolXUv\r\n"
    "KAkOkbT5LBx/xTQVXlm8IRxOo6x/skx25MSc2cHOVvOmBx9D8JrF3Qk/YHcn2A9V\r\n"
    "BZuC8vYgQAoFBGG51xHmJomVeNMgxW8JGdib4ZrYzeMyaRHOPwz+NMDKJUmdRdBn\r\n"
    "ftl4yQ40lYg5AgMBAAGjggP0MIID8DAfBgNVHSMEGDAWgBRqTlC/mGidW3sgddRZ\r\n"
    "AXlIZpIyBjAdBgNVHQ4EFgQU1DiwneJjUpHHggPwHwDO7qD6t5MwgbMGA1UdEQSB\r\n"
    "qzCBqIIQd3d3LmRpZ2ljZXJ0LmNvbYIMZGlnaWNlcnQuY29tghJhZG1pbi5kaWdp\r\n"
    "Y2VydC5jb22CEGFwaS5kaWdpY2VydC5jb22CFGNvbnRlbnQuZGlnaWNlcnQuY29t\r\n"
    "ghJsb2dpbi5kaWdpY2VydC5jb22CEm9yZGVyLmRpZ2ljZXJ0LmNvbYIPd3MuZGln\r\n"
    "aWNlcnQuY29tghFjYXJ0LmRpZ2ljZXJ0LmNvbTBKBgNVHSAEQzBBMAsGCWCGSAGG\r\n"
    "/WwCATAyBgVngQwBATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0\r\n"
    "LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr\r\n"
    "BgEFBQcDAjB1BgNVHR8EbjBsMDSgMqAwhi5odHRwOi8vY3JsMy5kaWdpY2VydC5j\r\n"
    "b20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMDSgMqAwhi5odHRwOi8vY3JsNC5kaWdp\r\n"
    "Y2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIuY3JsMHMGCCsGAQUFBwEBBGcwZTAk\r\n"
    "BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMD0GCCsGAQUFBzAC\r\n"
    "hjFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRFVlJTQUNBRzIu\r\n"
    "Y3J0MAwGA1UdEwEB/wQCMAAwggGBBgorBgEEAdZ5AgQCBIIBcQSCAW0BawB3AO7N\r\n"
    "0GTV2xrOxVy3nbTNE6Iyh0Z8vOzew1FIWUZxH7WbAAABiwZXNrQAAAQDAEgwRgIh\r\n"
    "AKisAHa9Fhp0k9OYBHWtCe0Y8BSbCgRvaH+QzfhfatS7AiEA2sb429SqQN8RD+Z4\r\n"
    "Iu5JHElklce8a4FTzG0lDWAuL2oAdwBIsONr2qZHNA/lagL6nTDrHFIBy1bdLIHZ\r\n"
    "u7+rOdiEcwAAAYsGVzbkAAAEAwBIMEYCIQCFhGhC3inngXvZk4qIQYti0lst+fvC\r\n"
    "nBpI7TNav708RQIhAIbDu40b2Hmizr49xvZrgrvs8YBSqF58EHf/hWCOdVBaAHcA\r\n"
    "PxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4AAAGLBlc3GQAABAMASDBG\r\n"
    "AiEAgQsADJ7ot+IAxKqE3U1ET6II9DOsxOK/NylSUZvMxzICIQDGHKJHe+Vh860p\r\n"
    "JBOvEFaOxLesbbYbcoiM9Bfkom0UPDANBgkqhkiG9w0BAQsFAAOCAQEADAB18iHj\r\n"
    "zEkXqexS87Nvnwdf/wfvx7VBY2lh75pjBcmBwqB6oqwoH8fh7HCW9y98ouqI13mi\r\n"
    "zBR8PIyjXf9EKceHbcsrYykg+gW9Ogo9oXdqzyS4Il2JSDg053vQlpkhhh3bSat4\r\n"
    "Yd/5W42YRpoRIGNGer48aVFB5GyX7iJFYzMHZVq4ZwK0g0Nx6JmPhPUd5BgPu+dO\r\n"
    "7xlrw2u/t2wihilLlNFoHj0nyrj+AB9Y6MhzK5MLC6k1Yl0olNSTgsG7ZrwsucXC\r\n"
    "LBxhhsK4xPIZq/WEnK8z5SwLI65P4w/ypmv4XCVt8IksrsaIUdCZv9lbV1Y7CNtG\r\n"
    "d6U1KOkPY/h3VQ==\r\n"
    "-----END CERTIFICATE-----\r\n"
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIFPDCCBCSgAwIBAgIQAWePH++IIlXYsKcOa3uyIDANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0yMDA3MDIxMjQyNTBaFw0zMDA3MDIxMjQyNTBaMEQxCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxHjAcBgNVBAMTFURpZ2lDZXJ0IEVWIFJT\r\n"
    "QSBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0eZsx/neTr\r\n"
    "f4MXJz0R2fJTIDfN8AwUAu7hy4gI0vp7O8LAAHx2h3bbf8wl+pGMSxaJK9ffDDCD\r\n"
    "63FqqFBqE9eTmo3RkgQhlu55a04LsXRLcK6crkBOO0djdonybmhrfGrtBqYvbRat\r\n"
    "xenkv0Sg4frhRl4wYh4dnW0LOVRGhbt1G5Q19zm9CqMlq7LlUdAE+6d3a5++ppfG\r\n"
    "cnWLmbEVEcLHPAnbl+/iKauQpQlU1Mi+wEBnjE5tK8Q778naXnF+DsedQJ7NEi+b\r\n"
    "QoonTHEz9ryeEcUHuQTv7nApa/zCqes5lXn1pMs4LZJ3SVgbkTLj+RbBov/uiwTX\r\n"
    "tkBEWawvZH8CAwEAAaOCAgswggIHMB0GA1UdDgQWBBRqTlC/mGidW3sgddRZAXlI\r\n"
    "ZpIyBjAfBgNVHSMEGDAWgBROIlQgGJXm427mD/r6uRLtBhePOTAOBgNVHQ8BAf8E\r\n"
    "BAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQI\r\n"
    "MAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz\r\n"
    "cC5kaWdpY2VydC5jb20wewYDVR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGln\r\n"
    "aWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA3oDWgM4YxaHR0cDov\r\n"
    "L2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDCBzgYD\r\n"
    "VR0gBIHGMIHDMIHABgRVHSAAMIG3MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k\r\n"
    "aWdpY2VydC5jb20vQ1BTMIGKBggrBgEFBQcCAjB+DHxBbnkgdXNlIG9mIHRoaXMg\r\n"
    "Q2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgUmVseWlu\r\n"
    "ZyBQYXJ0eSBBZ3JlZW1lbnQgbG9jYXRlZCBhdCBodHRwczovL3d3dy5kaWdpY2Vy\r\n"
    "dC5jb20vcnBhLXVhMA0GCSqGSIb3DQEBCwUAA4IBAQBSMgrCdY2+O9spnYNvwHiG\r\n"
    "+9lCJbyELR0UsoLwpzGpSdkHD7pVDDFJm3//B8Es+17T1o5Hat+HRDsvRr7d3MEy\r\n"
    "o9iXkkxLhKEgApA2Ft2eZfPrTolc95PwSWnn3FZ8BhdGO4brTA4+zkPSKoMXi/X+\r\n"
    "WLBNN29Z/nbCS7H/qLGt7gViEvTIdU8x+H4l/XigZMUDaVmJ+B5d7cwSK7yOoQdf\r\n"
    "oIBGmA5Mp4LhMzo52rf//kXPfE3wYIZVHqVuxxlnTkFYmffCX9/Lon7SWaGdg6Rc\r\n"
    "k4RHhHLWtmz2lTZ5CEo2ljDsGzCFGJP7oT4q6Q8oFC38irvdKIJ95cUxYzj4tnOI\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testOcspResponderCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIFPDCCBCSgAwIBAgIQAWePH++IIlXYsKcOa3uyIDANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0yMDA3MDIxMjQyNTBaFw0zMDA3MDIxMjQyNTBaMEQxCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxHjAcBgNVBAMTFURpZ2lDZXJ0IEVWIFJT\r\n"
    "QSBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0eZsx/neTr\r\n"
    "f4MXJz0R2fJTIDfN8AwUAu7hy4gI0vp7O8LAAHx2h3bbf8wl+pGMSxaJK9ffDDCD\r\n"
    "63FqqFBqE9eTmo3RkgQhlu55a04LsXRLcK6crkBOO0djdonybmhrfGrtBqYvbRat\r\n"
    "xenkv0Sg4frhRl4wYh4dnW0LOVRGhbt1G5Q19zm9CqMlq7LlUdAE+6d3a5++ppfG\r\n"
    "cnWLmbEVEcLHPAnbl+/iKauQpQlU1Mi+wEBnjE5tK8Q778naXnF+DsedQJ7NEi+b\r\n"
    "QoonTHEz9ryeEcUHuQTv7nApa/zCqes5lXn1pMs4LZJ3SVgbkTLj+RbBov/uiwTX\r\n"
    "tkBEWawvZH8CAwEAAaOCAgswggIHMB0GA1UdDgQWBBRqTlC/mGidW3sgddRZAXlI\r\n"
    "ZpIyBjAfBgNVHSMEGDAWgBROIlQgGJXm427mD/r6uRLtBhePOTAOBgNVHQ8BAf8E\r\n"
    "BAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQI\r\n"
    "MAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz\r\n"
    "cC5kaWdpY2VydC5jb20wewYDVR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGln\r\n"
    "aWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA3oDWgM4YxaHR0cDov\r\n"
    "L2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDCBzgYD\r\n"
    "VR0gBIHGMIHDMIHABgRVHSAAMIG3MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k\r\n"
    "aWdpY2VydC5jb20vQ1BTMIGKBggrBgEFBQcCAjB+DHxBbnkgdXNlIG9mIHRoaXMg\r\n"
    "Q2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgUmVseWlu\r\n"
    "ZyBQYXJ0eSBBZ3JlZW1lbnQgbG9jYXRlZCBhdCBodHRwczovL3d3dy5kaWdpY2Vy\r\n"
    "dC5jb20vcnBhLXVhMA0GCSqGSIb3DQEBCwUAA4IBAQBSMgrCdY2+O9spnYNvwHiG\r\n"
    "+9lCJbyELR0UsoLwpzGpSdkHD7pVDDFJm3//B8Es+17T1o5Hat+HRDsvRr7d3MEy\r\n"
    "o9iXkkxLhKEgApA2Ft2eZfPrTolc95PwSWnn3FZ8BhdGO4brTA4+zkPSKoMXi/X+\r\n"
    "WLBNN29Z/nbCS7H/qLGt7gViEvTIdU8x+H4l/XigZMUDaVmJ+B5d7cwSK7yOoQdf\r\n"
    "oIBGmA5Mp4LhMzo52rf//kXPfE3wYIZVHqVuxxlnTkFYmffCX9/Lon7SWaGdg6Rc\r\n"
    "k4RHhHLWtmz2lTZ5CEo2ljDsGzCFGJP7oT4q6Q8oFC38irvdKIJ95cUxYzj4tnOI\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_testCertChainPemRoot163[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIFPDCCBCSgAwIBAgIQAWePH++IIlXYsKcOa3uyIDANBgkqhkiG9w0BAQsFADBh\r\n"
    "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
    "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
    "MjAeFw0yMDA3MDIxMjQyNTBaFw0zMDA3MDIxMjQyNTBaMEQxCzAJBgNVBAYTAlVT\r\n"
    "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxHjAcBgNVBAMTFURpZ2lDZXJ0IEVWIFJT\r\n"
    "QSBDQSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0eZsx/neTr\r\n"
    "f4MXJz0R2fJTIDfN8AwUAu7hy4gI0vp7O8LAAHx2h3bbf8wl+pGMSxaJK9ffDDCD\r\n"
    "63FqqFBqE9eTmo3RkgQhlu55a04LsXRLcK6crkBOO0djdonybmhrfGrtBqYvbRat\r\n"
    "xenkv0Sg4frhRl4wYh4dnW0LOVRGhbt1G5Q19zm9CqMlq7LlUdAE+6d3a5++ppfG\r\n"
    "cnWLmbEVEcLHPAnbl+/iKauQpQlU1Mi+wEBnjE5tK8Q778naXnF+DsedQJ7NEi+b\r\n"
    "QoonTHEz9ryeEcUHuQTv7nApa/zCqes5lXn1pMs4LZJ3SVgbkTLj+RbBov/uiwTX\r\n"
    "tkBEWawvZH8CAwEAAaOCAgswggIHMB0GA1UdDgQWBBRqTlC/mGidW3sgddRZAXlI\r\n"
    "ZpIyBjAfBgNVHSMEGDAWgBROIlQgGJXm427mD/r6uRLtBhePOTAOBgNVHQ8BAf8E\r\n"
    "BAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1UdEwEB/wQI\r\n"
    "MAYBAf8CAQAwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz\r\n"
    "cC5kaWdpY2VydC5jb20wewYDVR0fBHQwcjA3oDWgM4YxaHR0cDovL2NybDMuZGln\r\n"
    "aWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDA3oDWgM4YxaHR0cDov\r\n"
    "L2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNybDCBzgYD\r\n"
    "VR0gBIHGMIHDMIHABgRVHSAAMIG3MCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k\r\n"
    "aWdpY2VydC5jb20vQ1BTMIGKBggrBgEFBQcCAjB+DHxBbnkgdXNlIG9mIHRoaXMg\r\n"
    "Q2VydGlmaWNhdGUgY29uc3RpdHV0ZXMgYWNjZXB0YW5jZSBvZiB0aGUgUmVseWlu\r\n"
    "ZyBQYXJ0eSBBZ3JlZW1lbnQgbG9jYXRlZCBhdCBodHRwczovL3d3dy5kaWdpY2Vy\r\n"
    "dC5jb20vcnBhLXVhMA0GCSqGSIb3DQEBCwUAA4IBAQBSMgrCdY2+O9spnYNvwHiG\r\n"
    "+9lCJbyELR0UsoLwpzGpSdkHD7pVDDFJm3//B8Es+17T1o5Hat+HRDsvRr7d3MEy\r\n"
    "o9iXkkxLhKEgApA2Ft2eZfPrTolc95PwSWnn3FZ8BhdGO4brTA4+zkPSKoMXi/X+\r\n"
    "WLBNN29Z/nbCS7H/qLGt7gViEvTIdU8x+H4l/XigZMUDaVmJ+B5d7cwSK7yOoQdf\r\n"
    "oIBGmA5Mp4LhMzo52rf//kXPfE3wYIZVHqVuxxlnTkFYmffCX9/Lon7SWaGdg6Rc\r\n"
    "k4RHhHLWtmz2lTZ5CEo2ljDsGzCFGJP7oT4q6Q8oFC38irvdKIJ95cUxYzj4tnOI\r\n"
    "-----END CERTIFICATE-----\r\n";

const uint8_t g_testChainKeystore[] = { 0x30, 0x82, 0x0D, 0xF1, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0D, 0xB7, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x82, 0x0D, 0xA8, 0x04, 0x82, 0x0D, 0xA4, 0x30, 0x82,
    0x0D, 0xA0, 0x30, 0x82, 0x08, 0x57, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06, 0xA0, 0x82,
    0x08, 0x48, 0x30, 0x82, 0x08, 0x44, 0x02, 0x01, 0x00, 0x30, 0x82, 0x08, 0x3D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x07, 0x01, 0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x01, 0x06,
    0x30, 0x0E, 0x04, 0x08, 0x42, 0xDC, 0x29, 0x1C, 0xD8, 0x58, 0x22, 0x17, 0x02, 0x02, 0x08, 0x00, 0x80, 0x82, 0x08,
    0x10, 0x1E, 0x7C, 0x00, 0xA3, 0x82, 0x23, 0x9A, 0xEB, 0x02, 0x9E, 0xCC, 0xA2, 0xF8, 0xF2, 0xBA, 0x16, 0x56, 0x5F,
    0x29, 0x84, 0xE4, 0xB2, 0x1C, 0x70, 0xB9, 0xF8, 0x6D, 0x55, 0xEC, 0xA5, 0xFB, 0x54, 0xAB, 0x03, 0xA4, 0x6E, 0x2F,
    0x5E, 0x9E, 0xCB, 0x48, 0xF1, 0x07, 0x54, 0xFA, 0x44, 0x7D, 0xE3, 0x8D, 0xB9, 0x11, 0xD5, 0xC2, 0xCE, 0x43, 0xF2,
    0xB3, 0x41, 0x12, 0x6D, 0xDD, 0xD0, 0xF4, 0xD9, 0xEB, 0x1B, 0xAE, 0xFE, 0x31, 0x2B, 0xB8, 0xAF, 0x65, 0x7B, 0xDE,
    0xB1, 0x85, 0xC0, 0x81, 0xFB, 0xDE, 0xEC, 0x56, 0x11, 0xE9, 0xD1, 0x11, 0x15, 0x34, 0x3D, 0x89, 0x6D, 0x79, 0x48,
    0xA5, 0xB0, 0xBC, 0x38, 0x2B, 0x13, 0xA8, 0xB0, 0xB4, 0xD2, 0xCF, 0x35, 0x61, 0x88, 0x7D, 0x92, 0xAF, 0xFD, 0xE8,
    0x31, 0x91, 0x81, 0x58, 0x05, 0x93, 0x0E, 0x9C, 0x08, 0xB7, 0x0F, 0xCE, 0x58, 0x82, 0xD5, 0x77, 0x27, 0x63, 0xF7,
    0x6F, 0x9A, 0xE8, 0x60, 0x82, 0x7A, 0x3F, 0x21, 0x77, 0x3F, 0x3D, 0x15, 0xB0, 0x30, 0x72, 0x38, 0x01, 0x5D, 0x6F,
    0xFB, 0x57, 0xC9, 0x28, 0x5C, 0xBD, 0x0C, 0x26, 0xD8, 0x31, 0x34, 0x1A, 0x25, 0x9A, 0xDD, 0x3E, 0x8B, 0x4F, 0x85,
    0x74, 0xCD, 0x0B, 0x2B, 0xEB, 0x5E, 0x78, 0x21, 0x2B, 0x6D, 0x55, 0xC3, 0x24, 0x99, 0x09, 0x73, 0xFF, 0xAB, 0xC9,
    0x8A, 0x04, 0x1A, 0x91, 0x50, 0xFA, 0x6C, 0x06, 0x0E, 0xCC, 0x25, 0x2A, 0xD4, 0xC6, 0xC9, 0x8E, 0x6F, 0x1D, 0x5F,
    0x92, 0x0C, 0x70, 0x9A, 0x93, 0xCF, 0xE7, 0x41, 0x6C, 0x65, 0x11, 0x35, 0x2D, 0x3A, 0x1D, 0x58, 0x67, 0x72, 0xF4,
    0xDF, 0xF1, 0x07, 0x04, 0x06, 0x02, 0x74, 0x20, 0xC8, 0x67, 0x7A, 0xBC, 0xF8, 0x26, 0xA1, 0x7F, 0x4E, 0x2C, 0x17,
    0x23, 0x27, 0x81, 0xCE, 0x29, 0xEE, 0x35, 0xD4, 0x69, 0x9A, 0xBB, 0x3C, 0x37, 0x0D, 0x3C, 0xC9, 0xE4, 0xF6, 0xFE,
    0x20, 0x6F, 0x41, 0xBD, 0x32, 0x73, 0x00, 0x86, 0x5C, 0x2A, 0xB2, 0x50, 0x83, 0xD9, 0x65, 0x2A, 0xF4, 0x37, 0xD8,
    0xB6, 0x67, 0xEF, 0x8E, 0x93, 0x63, 0x05, 0xA5, 0x16, 0xEA, 0xEC, 0x5C, 0x50, 0xDF, 0x55, 0x3E, 0x89, 0x74, 0xC6,
    0x57, 0xC2, 0x84, 0xFE, 0x8B, 0x7D, 0x18, 0x3E, 0x06, 0xCB, 0x83, 0x76, 0x76, 0xBC, 0xF0, 0x97, 0x15, 0x19, 0x15,
    0x57, 0x47, 0x3B, 0xA0, 0xF8, 0xC9, 0x4B, 0x2E, 0xD9, 0xA1, 0xB1, 0xE0, 0x9F, 0x7F, 0x4F, 0x95, 0xF1, 0xB8, 0x6C,
    0xDE, 0x95, 0xAF, 0xEA, 0x61, 0xCB, 0x95, 0x68, 0x1C, 0x2D, 0xBD, 0xF5, 0x39, 0xDE, 0xBC, 0x31, 0x8E, 0xF6, 0x32,
    0xED, 0xBD, 0x76, 0x74, 0x1A, 0x7E, 0x37, 0x52, 0xDD, 0x0B, 0xA1, 0x17, 0x9A, 0x1F, 0x58, 0xB2, 0x8B, 0x09, 0x5C,
    0xD5, 0xD1, 0x2C, 0x0D, 0x34, 0x0B, 0x60, 0x57, 0x4B, 0x89, 0xBC, 0xA1, 0xBE, 0x74, 0xD2, 0x3E, 0x80, 0x3D, 0xD7,
    0x0A, 0x66, 0xEC, 0x7C, 0x28, 0x64, 0x9B, 0x48, 0x87, 0xF6, 0xAD, 0xBA, 0x42, 0xCF, 0x52, 0xE6, 0xB5, 0xD2, 0x5F,
    0xA5, 0xDF, 0x92, 0x2C, 0xFB, 0x61, 0x59, 0xA4, 0x82, 0x19, 0xA5, 0x72, 0x26, 0x86, 0xDB, 0xCD, 0x8A, 0x34, 0xBF,
    0x4C, 0x54, 0x33, 0x52, 0x13, 0x3D, 0x58, 0xE4, 0xC4, 0x52, 0xEA, 0x9E, 0x97, 0xC6, 0x40, 0x50, 0xAD, 0x03, 0xF0,
    0xB2, 0x1D, 0x71, 0xB6, 0x3A, 0xCF, 0xD9, 0x9E, 0xBB, 0x3A, 0x2C, 0xCB, 0x6F, 0xB3, 0xE9, 0x17, 0xFD, 0x8A, 0x2C,
    0x12, 0x5B, 0x79, 0x4F, 0xF7, 0x47, 0xC1, 0x12, 0x29, 0xC4, 0x81, 0x60, 0xCA, 0x22, 0x30, 0x95, 0xB3, 0xA8, 0x35,
    0xBA, 0xBA, 0x6A, 0x82, 0x46, 0xB7, 0x5A, 0xE6, 0x03, 0xB7, 0x8C, 0xC7, 0x1C, 0xD5, 0xCD, 0x9E, 0x9A, 0x2D, 0x40,
    0xC0, 0xFC, 0x06, 0x68, 0x05, 0x50, 0x74, 0xE1, 0x36, 0x5B, 0x71, 0x27, 0x76, 0x5B, 0x38, 0x78, 0xE0, 0xFA, 0x9A,
    0xF5, 0x3E, 0x78, 0x9C, 0x53, 0x08, 0x17, 0xCB, 0x98, 0x65, 0x4A, 0x1B, 0x0B, 0x63, 0xD9, 0xD3, 0xC2, 0x85, 0x56,
    0xB1, 0x87, 0x41, 0x69, 0x89, 0xF5, 0xDA, 0x63, 0x88, 0x79, 0x2C, 0x8D, 0x7C, 0x7E, 0x1C, 0x4F, 0x1C, 0x30, 0xB7,
    0xF0, 0x65, 0x2A, 0x41, 0xED, 0x78, 0xA2, 0xB7, 0xA2, 0x50, 0xB1, 0x25, 0x15, 0xDD, 0xAA, 0xE5, 0x00, 0x94, 0xC3,
    0x9A, 0x2F, 0xC6, 0x8C, 0xF1, 0x54, 0xEF, 0x39, 0x52, 0x36, 0x3D, 0x76, 0xF5, 0x82, 0x17, 0x47, 0xC2, 0x36, 0x5E,
    0x76, 0x97, 0xF0, 0xB2, 0x53, 0xF0, 0x38, 0xB1, 0x61, 0xB4, 0x6E, 0x46, 0x82, 0x38, 0x94, 0x62, 0xC7, 0xA0, 0x24,
    0xEC, 0x3A, 0xBF, 0x31, 0xFC, 0x7C, 0xBE, 0xB2, 0xD7, 0xBE, 0x4B, 0x92, 0xC7, 0x95, 0x29, 0xEC, 0xED, 0xE5, 0xA8,
    0x61, 0x44, 0x85, 0x2F, 0xC5, 0xF3, 0xDA, 0xCE, 0xE8, 0x4E, 0xBE, 0x81, 0xD6, 0xA1, 0x92, 0xA4, 0x17, 0x28, 0xFA,
    0xE8, 0xDF, 0x84, 0x9C, 0x34, 0x5E, 0x17, 0x25, 0xB1, 0x6A, 0x2D, 0x5B, 0xDA, 0xDE, 0xDA, 0xBD, 0x41, 0xF5, 0x8F,
    0xE3, 0x36, 0xB1, 0x91, 0xB2, 0x61, 0x35, 0x8B, 0xA5, 0x38, 0x00, 0x00, 0x5A, 0x4F, 0xAA, 0x70, 0xC3, 0xEC, 0x6B,
    0xE2, 0xE4, 0x3A, 0xDF, 0xC8, 0x24, 0xB1, 0x1D, 0xC1, 0xF5, 0x50, 0xF2, 0xE7, 0xB9, 0xCF, 0x3C, 0xEC, 0xA4, 0x7D,
    0x4B, 0xA6, 0xB3, 0x9E, 0x16, 0x6D, 0x7F, 0x26, 0x7B, 0x2F, 0x33, 0x96, 0x1A, 0x5B, 0x85, 0xD2, 0x05, 0xA2, 0xE4,
    0xF6, 0x0F, 0xF4, 0x88, 0x1B, 0xE5, 0x12, 0x5F, 0xF0, 0xF7, 0x67, 0x3B, 0x8F, 0xF1, 0x27, 0x63, 0xB2, 0x3C, 0xBB,
    0xDA, 0xBE, 0x36, 0xDD, 0x3C, 0x98, 0x35, 0x53, 0x07, 0xBF, 0x3F, 0x1F, 0x46, 0xA5, 0x64, 0xA5, 0x84, 0xC4, 0x53,
    0x87, 0x5F, 0xEB, 0xDC, 0x8A, 0xED, 0x0F, 0xA5, 0xC6, 0x41, 0x42, 0xDA, 0x54, 0x27, 0x83, 0xF4, 0xA1, 0x90, 0xE7,
    0xC3, 0x66, 0xAC, 0x50, 0x87, 0xFE, 0xAC, 0x86, 0xBF, 0xD6, 0xA2, 0x92, 0x6E, 0x1E, 0x7A, 0x3C, 0x83, 0xAB, 0x67,
    0x49, 0x16, 0x00, 0x50, 0x88, 0x4B, 0x1E, 0x08, 0x54, 0x91, 0xCE, 0x16, 0x2F, 0x7C, 0x03, 0x2A, 0xFA, 0x2B, 0x4B,
    0xB4, 0x55, 0x6A, 0xEE, 0x66, 0x26, 0x94, 0x88, 0x8B, 0x50, 0xFA, 0xDA, 0x24, 0xD2, 0x48, 0xF2, 0xDA, 0xC0, 0x05,
    0x1E, 0x74, 0x70, 0x36, 0x7A, 0x9F, 0x7A, 0x2D, 0x6D, 0x52, 0xF2, 0x12, 0x5D, 0x7C, 0xEF, 0x4B, 0x91, 0x46, 0xDF,
    0x73, 0x5D, 0xE3, 0x5C, 0x72, 0xD7, 0xE1, 0x1B, 0x95, 0x1D, 0x17, 0x2B, 0x8C, 0x1E, 0xBB, 0x2C, 0x1E, 0xAB, 0xA9,
    0x26, 0xB0, 0x43, 0x22, 0x8F, 0xC3, 0xC5, 0x3E, 0xE3, 0xAC, 0xAA, 0xFA, 0xE1, 0xA0, 0x18, 0xD8, 0xD4, 0x40, 0xFC,
    0x02, 0xDF, 0x32, 0x3C, 0x46, 0xB4, 0x72, 0x87, 0xDB, 0x0B, 0x27, 0x3C, 0x92, 0xE2, 0x6A, 0x01, 0x6C, 0x6D, 0xFF,
    0xFF, 0x33, 0x4E, 0x91, 0xE2, 0xE7, 0x90, 0xD6, 0x87, 0x52, 0x8B, 0xE5, 0x45, 0xC9, 0x16, 0xE0, 0xB2, 0x7E, 0xE2,
    0x9D, 0x6C, 0x63, 0xB7, 0xD9, 0xD2, 0xB5, 0x9B, 0xB4, 0xE7, 0xD8, 0xB6, 0x56, 0x1C, 0xEA, 0x21, 0x64, 0x06, 0xCE,
    0xBE, 0x39, 0x29, 0xBA, 0xE5, 0x20, 0x9B, 0x84, 0x35, 0x39, 0xDB, 0x12, 0x95, 0xC7, 0xBD, 0x88, 0x76, 0x0F, 0x57,
    0xDC, 0x5A, 0xCF, 0x3D, 0x7C, 0x79, 0x65, 0xEF, 0x23, 0xEB, 0x95, 0x55, 0xF8, 0x73, 0x97, 0x1C, 0x04, 0xDE, 0xDD,
    0x4A, 0xEA, 0x2B, 0x5A, 0xCF, 0xC3, 0xE7, 0x11, 0x34, 0x31, 0x00, 0xCE, 0x5E, 0x2B, 0x33, 0xF0, 0x04, 0x2E, 0xA5,
    0x9C, 0xD6, 0x25, 0x79, 0x38, 0x36, 0x13, 0xD7, 0xE0, 0x24, 0xC8, 0x79, 0xAB, 0xEA, 0x4F, 0x5A, 0x93, 0x29, 0x71,
    0xEB, 0x99, 0xC1, 0x90, 0x71, 0x33, 0x13, 0xD2, 0x5D, 0x50, 0x5F, 0x44, 0x11, 0xC1, 0x3D, 0x5C, 0x44, 0x8E, 0xE1,
    0x74, 0x5B, 0x31, 0x7F, 0xFC, 0x97, 0xA8, 0x83, 0x1D, 0xA7, 0xDF, 0xD0, 0x92, 0xA1, 0xD4, 0xDF, 0x67, 0x57, 0x9E,
    0x4C, 0xB7, 0x15, 0x62, 0x23, 0x05, 0xF0, 0x9A, 0xAD, 0xC6, 0xCE, 0x3B, 0x38, 0x52, 0x32, 0xDC, 0xB7, 0xDF, 0x33,
    0x3A, 0x9D, 0xCB, 0xFD, 0xD5, 0xE2, 0xF9, 0x72, 0x5B, 0x95, 0x21, 0xEA, 0x55, 0x68, 0x37, 0x4D, 0x9B, 0x07, 0x73,
    0x04, 0x11, 0xE5, 0x08, 0xF9, 0xBA, 0x50, 0x45, 0x92, 0x4A, 0x9B, 0x7D, 0xCB, 0x98, 0x66, 0x5E, 0xED, 0x24, 0x80,
    0x29, 0x86, 0xB4, 0x79, 0x66, 0x07, 0xD1, 0x81, 0xD5, 0xFE, 0xFA, 0xAC, 0x60, 0x50, 0xFC, 0x8A, 0xF1, 0x7C, 0x17,
    0x29, 0x56, 0xEE, 0xBE, 0x6B, 0x34, 0x9C, 0xC1, 0x83, 0xB6, 0x78, 0x9A, 0xA5, 0x7E, 0xF9, 0x45, 0xF5, 0x35, 0xE0,
    0x49, 0x5A, 0x7C, 0xFF, 0x99, 0x4C, 0x61, 0x76, 0xCD, 0xCA, 0xD7, 0xAC, 0x5B, 0xE2, 0xC7, 0x3A, 0x0B, 0xF9, 0x9A,
    0x74, 0xCF, 0x55, 0xF8, 0x03, 0xB2, 0xAF, 0x6D, 0xD6, 0xD8, 0x55, 0xDB, 0x68, 0x06, 0xE3, 0x1A, 0x2B, 0x65, 0x4D,
    0x13, 0x5F, 0xDD, 0xDA, 0xE8, 0xA5, 0x2F, 0x01, 0x86, 0xCB, 0x5F, 0x23, 0x8A, 0xB5, 0x37, 0xB9, 0x34, 0x3B, 0x09,
    0xC5, 0xE6, 0x83, 0xA7, 0x7B, 0xDF, 0xF8, 0x19, 0x75, 0xF5, 0xCC, 0xC4, 0xD6, 0x7F, 0x0C, 0xF9, 0xD2, 0xA6, 0x65,
    0xD8, 0xA5, 0x19, 0x74, 0x09, 0x41, 0x34, 0x04, 0xCB, 0xD3, 0x1D, 0xF9, 0x73, 0x9E, 0xA6, 0xAE, 0x71, 0x1B, 0xB1,
    0x71, 0x0B, 0x16, 0x0A, 0xCD, 0xAF, 0x99, 0x68, 0x11, 0xFF, 0x64, 0x23, 0xF2, 0x51, 0xA6, 0x79, 0x2C, 0x55, 0x12,
    0x4A, 0x29, 0x30, 0xE8, 0xD5, 0x20, 0x41, 0xE0, 0x8E, 0x66, 0x86, 0x14, 0x3D, 0xB7, 0xED, 0x1B, 0x60, 0x0C, 0xFB,
    0xF4, 0xF0, 0x9D, 0x52, 0xF3, 0x0C, 0x29, 0xD9, 0xF8, 0x30, 0x1F, 0xE5, 0x67, 0x16, 0x1B, 0x21, 0x1D, 0x49, 0xE3,
    0xDC, 0xDC, 0x91, 0xF9, 0x32, 0xD1, 0x79, 0xC9, 0xE4, 0xD7, 0xC8, 0x2D, 0x67, 0xB4, 0x3E, 0x97, 0xDB, 0xE5, 0x50,
    0x96, 0x0D, 0x5E, 0x9C, 0x3C, 0x59, 0x59, 0x43, 0x71, 0x71, 0xEF, 0xC7, 0x90, 0xD4, 0xCE, 0xC8, 0x98, 0xB0, 0xCB,
    0xB6, 0x3D, 0x98, 0xF7, 0x99, 0x6F, 0x53, 0x2A, 0xEE, 0x74, 0xB8, 0x57, 0x52, 0x98, 0xDA, 0xB8, 0xE5, 0x8A, 0x41,
    0x1A, 0x01, 0x5F, 0x57, 0xDA, 0x2C, 0xC3, 0xB4, 0xB5, 0x6B, 0x72, 0x1F, 0xCC, 0x4B, 0x52, 0x28, 0x3F, 0xB3, 0x04,
    0x53, 0x04, 0xC8, 0xA2, 0xA0, 0x2D, 0xBB, 0x28, 0xB2, 0xFB, 0x81, 0xBA, 0x6D, 0xC0, 0x61, 0x20, 0x01, 0xF7, 0xE7,
    0xFD, 0xCA, 0x0C, 0xBA, 0x81, 0x8F, 0x55, 0xD7, 0x4E, 0xDF, 0xDB, 0x6F, 0xC7, 0x8D, 0x75, 0x35, 0x6D, 0x02, 0x7C,
    0xF6, 0x44, 0x45, 0xC2, 0x1D, 0xEB, 0x85, 0x36, 0x7C, 0x84, 0x41, 0xA1, 0x68, 0xC5, 0x95, 0xE2, 0xB2, 0x95, 0x0E,
    0x10, 0x72, 0x28, 0x84, 0xBB, 0xD5, 0xD9, 0xDE, 0xC2, 0x34, 0x64, 0x26, 0x01, 0xE1, 0x9D, 0x9D, 0xA3, 0xD0, 0xCC,
    0x64, 0xDC, 0x15, 0xF2, 0x49, 0x50, 0xB3, 0x94, 0x08, 0x9F, 0x8B, 0x5B, 0xBD, 0x11, 0x96, 0xA6, 0x4B, 0xF4, 0x7F,
    0x79, 0xB6, 0x6C, 0x89, 0xBD, 0xDE, 0xB8, 0xE1, 0xFE, 0x50, 0x9E, 0xE1, 0xEF, 0x0C, 0x89, 0xD8, 0xC0, 0x4B, 0xBD,
    0xCB, 0xAE, 0x47, 0xC6, 0x38, 0x55, 0x1A, 0x8C, 0xEA, 0xD6, 0xCD, 0xF9, 0xFA, 0x63, 0x33, 0xF9, 0x2A, 0x2D, 0xE6,
    0x34, 0x72, 0x1C, 0xCB, 0x19, 0xB6, 0x50, 0xAD, 0x75, 0xDA, 0x0D, 0xCD, 0x01, 0xBD, 0x7A, 0x9E, 0x12, 0x56, 0x00,
    0xF5, 0xE8, 0x4B, 0x86, 0xB1, 0x69, 0x9D, 0x01, 0xA1, 0x75, 0x85, 0x60, 0xCD, 0x72, 0x70, 0xF8, 0x49, 0xD7, 0x2D,
    0xC4, 0x17, 0xEB, 0xCB, 0x7E, 0x75, 0x5C, 0x1D, 0x5A, 0x6D, 0x67, 0x08, 0xE3, 0x95, 0xFF, 0xD8, 0x91, 0xE5, 0x1F,
    0x13, 0x06, 0x88, 0xE3, 0x4E, 0x06, 0xA7, 0xD6, 0x4E, 0x94, 0x11, 0x8F, 0x03, 0x8E, 0xFA, 0x2E, 0x15, 0x96, 0xC9,
    0x83, 0xEE, 0x59, 0xB2, 0x94, 0x29, 0xDB, 0xAF, 0x04, 0x31, 0x75, 0xB0, 0x7D, 0x4C, 0xEA, 0x93, 0xA8, 0x8D, 0xC4,
    0x4C, 0xEB, 0xAE, 0x82, 0xB5, 0x17, 0xDB, 0xF5, 0x64, 0x8B, 0x43, 0xE6, 0x0E, 0xBF, 0x28, 0xE9, 0x1A, 0x29, 0x31,
    0x46, 0xDC, 0xC2, 0xD7, 0x57, 0xD6, 0x3C, 0xF0, 0x09, 0xB6, 0x72, 0x58, 0x97, 0xCB, 0xC4, 0x7F, 0x54, 0x60, 0xD5,
    0x71, 0x37, 0x9C, 0x6D, 0xF8, 0xBC, 0x5F, 0x41, 0xEE, 0x15, 0x8A, 0x6D, 0x88, 0x02, 0xEB, 0xEF, 0x45, 0x78, 0xD3,
    0xCA, 0xC7, 0x72, 0xA9, 0xD8, 0x9B, 0xD4, 0xE5, 0xE2, 0xD3, 0xA1, 0x01, 0x64, 0x3C, 0x1E, 0x4E, 0x5A, 0x86, 0x31,
    0x0C, 0xAD, 0x3D, 0xDA, 0xED, 0xA7, 0x95, 0xE8, 0xA0, 0x32, 0x4D, 0x23, 0xD7, 0xF1, 0x8A, 0x0D, 0xA1, 0xA5, 0x2D,
    0x39, 0x89, 0xB4, 0x0C, 0xEC, 0x8E, 0x07, 0x6E, 0xB0, 0x96, 0x80, 0x50, 0x84, 0x50, 0x2F, 0xBE, 0x46, 0x7D, 0xFC,
    0x61, 0x3B, 0x40, 0x67, 0xBB, 0xE0, 0x15, 0xC9, 0xE6, 0xC7, 0xB6, 0x14, 0x8D, 0xFF, 0x73, 0x25, 0xDA, 0xE5, 0x58,
    0x69, 0x7A, 0x50, 0xE7, 0xCD, 0xDE, 0x09, 0xBE, 0x3F, 0x02, 0xB1, 0xF6, 0x10, 0xC1, 0x45, 0xE9, 0x98, 0x83, 0x81,
    0x40, 0x42, 0x3E, 0x6E, 0x64, 0xEA, 0x2B, 0x8E, 0x8B, 0x72, 0x0D, 0xF5, 0xD3, 0xB3, 0x42, 0xE1, 0xA9, 0x51, 0x76,
    0x21, 0xB0, 0xF4, 0x84, 0x70, 0x8A, 0x30, 0x27, 0x8C, 0x1A, 0x9C, 0xAD, 0x4A, 0x66, 0xD4, 0x02, 0x70, 0x4F, 0x76,
    0xA9, 0xE8, 0x55, 0x66, 0xE5, 0x56, 0xAD, 0x8C, 0xF6, 0xEB, 0xB6, 0x49, 0x4E, 0xB8, 0xD8, 0xBF, 0x9C, 0x08, 0x9A,
    0x59, 0x74, 0xD4, 0xFE, 0xDA, 0x56, 0xB8, 0x95, 0xF6, 0x63, 0xB6, 0xF6, 0x50, 0xBC, 0xAE, 0xA5, 0x1D, 0x73, 0x48,
    0x62, 0xFD, 0x4B, 0x17, 0x42, 0x38, 0x5B, 0xEF, 0x18, 0xC0, 0x83, 0x51, 0xC9, 0x7A, 0x60, 0x48, 0x4D, 0xB1, 0xF0,
    0x3B, 0x8E, 0xC0, 0x85, 0xFB, 0xEA, 0x69, 0xE5, 0x84, 0xD6, 0x84, 0xEA, 0x4B, 0x1C, 0x66, 0xB3, 0x7E, 0x2A, 0xA1,
    0x44, 0xAA, 0x2E, 0xA4, 0x0C, 0x76, 0x70, 0xDB, 0x06, 0xC3, 0xC4, 0xD2, 0x0D, 0x4A, 0xA5, 0x5D, 0x95, 0x61, 0xB2,
    0x4A, 0x12, 0x0A, 0xB0, 0x0B, 0x5E, 0xC6, 0x03, 0x18, 0x3B, 0x55, 0xD4, 0x46, 0x0F, 0x2D, 0x78, 0x0E, 0x00, 0xD3,
    0xDA, 0xB0, 0x8B, 0xCF, 0x09, 0x34, 0x48, 0xE4, 0x23, 0x19, 0x55, 0x95, 0x88, 0xAF, 0x0B, 0x94, 0x7E, 0x89, 0xA6,
    0x8E, 0x5E, 0x77, 0x58, 0x05, 0x55, 0x66, 0x8D, 0x40, 0x60, 0xB2, 0xB8, 0x2B, 0x5F, 0x9D, 0x76, 0xDF, 0x6A, 0x68,
    0xF2, 0x3E, 0x2E, 0x83, 0x4F, 0x45, 0xAA, 0xEA, 0xFB, 0xC0, 0xAB, 0xE0, 0x00, 0xD5, 0xCC, 0x19, 0xA7, 0x2C, 0x6B,
    0x62, 0xC5, 0xBA, 0xF6, 0xEA, 0x4C, 0xE5, 0xD2, 0xD6, 0xFE, 0x2F, 0xF2, 0xB4, 0x5E, 0xAE, 0x16, 0xAF, 0xAA, 0xBC,
    0x81, 0x56, 0x27, 0x68, 0xAB, 0xD2, 0x6E, 0x0C, 0x2F, 0xB9, 0xEF, 0x4A, 0x16, 0x16, 0x84, 0xF3, 0x99, 0x0B, 0xA4,
    0xB7, 0x1A, 0x95, 0x46, 0xB5, 0x02, 0x2F, 0x7B, 0xA0, 0x23, 0x13, 0x85, 0xAF, 0xCD, 0xC3, 0x90, 0x70, 0xC2, 0x4B,
    0x92, 0x4E, 0x71, 0xAD, 0x4A, 0x49, 0xE8, 0x07, 0x28, 0x0F, 0x3C, 0xA3, 0xF4, 0x30, 0x82, 0x05, 0x41, 0x06, 0x09,
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01, 0xA0, 0x82, 0x05, 0x32, 0x04, 0x82, 0x05, 0x2E, 0x30, 0x82,
    0x05, 0x2A, 0x30, 0x82, 0x05, 0x26, 0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01, 0x02,
    0xA0, 0x82, 0x04, 0xEE, 0x30, 0x82, 0x04, 0xEA, 0x30, 0x1C, 0x06, 0x0A, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
    0x0C, 0x01, 0x03, 0x30, 0x0E, 0x04, 0x08, 0x95, 0x40, 0x08, 0x71, 0xA3, 0x56, 0x67, 0x32, 0x02, 0x02, 0x08, 0x00,
    0x04, 0x82, 0x04, 0xC8, 0x2E, 0xBD, 0xE2, 0x3F, 0x70, 0xF9, 0x05, 0xEF, 0x99, 0x46, 0xC5, 0x4B, 0x70, 0xA5, 0x8B,
    0xDB, 0x8B, 0xDF, 0xA6, 0xF1, 0xAF, 0x8B, 0xE4, 0xE9, 0xB0, 0x13, 0xFF, 0xA4, 0x9F, 0xF4, 0xED, 0x0F, 0x1C, 0x98,
    0x91, 0x91, 0x81, 0xC2, 0x85, 0xBC, 0x8B, 0xFE, 0x85, 0x65, 0x41, 0x92, 0x87, 0x2E, 0xFF, 0x5D, 0x0B, 0x07, 0x0B,
    0x73, 0x65, 0x76, 0x44, 0x19, 0xB9, 0x6E, 0xF4, 0xC5, 0x16, 0xFC, 0x69, 0xA9, 0x6E, 0xEF, 0xE2, 0x0F, 0x6A, 0x3C,
    0x2A, 0xDB, 0xAD, 0x75, 0xD3, 0x95, 0x2C, 0x5B, 0x73, 0x03, 0x31, 0x0F, 0x1D, 0x50, 0x6B, 0x81, 0x86, 0x18, 0xCD,
    0x2C, 0x4F, 0xD2, 0x9E, 0xC2, 0x28, 0xF4, 0xA4, 0xF3, 0xAA, 0x0B, 0xAE, 0x58, 0xBD, 0xB0, 0xA8, 0x63, 0xDA, 0xDF,
    0x3F, 0x8B, 0xE8, 0x91, 0x83, 0x1B, 0x0C, 0xE3, 0x19, 0xC7, 0xF6, 0xC4, 0x1A, 0x8E, 0x00, 0x97, 0xE5, 0x6A, 0xD9,
    0x4F, 0xDE, 0x0D, 0x3A, 0xF8, 0x36, 0x7F, 0x6D, 0x36, 0x30, 0x9C, 0x8D, 0x49, 0x0A, 0x16, 0xBC, 0xE3, 0x19, 0x7F,
    0xEA, 0x37, 0x03, 0x3F, 0x6B, 0x41, 0x9A, 0xD3, 0x21, 0xA2, 0xFD, 0xD1, 0xB8, 0x79, 0x52, 0x22, 0xAC, 0x4E, 0xFA,
    0xA9, 0x36, 0x2F, 0x37, 0xD9, 0x41, 0xCD, 0xB1, 0x5F, 0xF4, 0x4B, 0x7B, 0xFF, 0xC8, 0x0B, 0x43, 0x80, 0xB1, 0x8E,
    0x67, 0x0E, 0x2A, 0x89, 0xBE, 0xC2, 0x8E, 0x94, 0x19, 0xBF, 0x38, 0xC3, 0x16, 0x4B, 0x1C, 0xC0, 0x0E, 0xE8, 0xDE,
    0x12, 0x3E, 0xB5, 0x01, 0xFE, 0xC4, 0x5B, 0x25, 0x6D, 0x91, 0xD7, 0xCF, 0xEA, 0xC8, 0x31, 0x87, 0xC9, 0xE0, 0x58,
    0x25, 0x37, 0x84, 0xCA, 0x76, 0x21, 0xD1, 0x25, 0x25, 0xC5, 0xAC, 0x66, 0xBB, 0x7A, 0x00, 0xAE, 0xE5, 0xC8, 0x50,
    0xC0, 0xDD, 0x97, 0x9D, 0x86, 0x81, 0x9E, 0xC1, 0x6C, 0xF4, 0x5E, 0xB4, 0xC1, 0xC5, 0x7C, 0x2D, 0x7C, 0xB5, 0x0C,
    0xF7, 0xF6, 0x9C, 0x5F, 0xBB, 0x27, 0x5D, 0xEF, 0x09, 0x94, 0x25, 0x2E, 0xFB, 0x8F, 0x28, 0x7F, 0x10, 0x1D, 0xFC,
    0x82, 0x34, 0xDF, 0x09, 0x11, 0x58, 0xA5, 0xD8, 0x37, 0x85, 0xF4, 0x6A, 0x56, 0x8C, 0x0F, 0xEB, 0x46, 0xBB, 0x24,
    0x19, 0xEC, 0xB9, 0xC2, 0x2B, 0xDC, 0xED, 0x4A, 0x16, 0xA2, 0x0A, 0x06, 0x43, 0x32, 0xD6, 0x19, 0xF9, 0x3D, 0x03,
    0x72, 0xAD, 0x8A, 0x92, 0x2C, 0x7B, 0x6D, 0x95, 0x21, 0x59, 0x07, 0xF8, 0x5F, 0x07, 0xF4, 0x9F, 0x8A, 0xA8, 0xAC,
    0x1B, 0x78, 0x1A, 0xCA, 0x7A, 0x63, 0xEB, 0xE2, 0xC5, 0xB5, 0xA9, 0x4E, 0x58, 0x9B, 0xA1, 0x43, 0xD2, 0x04, 0xE5,
    0x08, 0xC0, 0x17, 0x5F, 0x1D, 0x9E, 0x1F, 0x78, 0x85, 0xBB, 0xE3, 0x50, 0xBF, 0x95, 0x74, 0xBE, 0x7E, 0x2B, 0xBB,
    0xCF, 0x88, 0x57, 0x3F, 0xBB, 0x52, 0x87, 0x73, 0x27, 0xC3, 0xAC, 0xC5, 0x84, 0x3D, 0x8E, 0x03, 0xD2, 0x94, 0x16,
    0x0E, 0x0D, 0xB9, 0x36, 0x40, 0x74, 0xAF, 0x17, 0x47, 0x92, 0x43, 0x13, 0x15, 0xE1, 0x24, 0xB5, 0x5E, 0xEF, 0x0A,
    0x33, 0x76, 0xC1, 0x8F, 0x8A, 0xAE, 0x91, 0xF1, 0x5F, 0xFF, 0xA8, 0xAA, 0x57, 0x29, 0x4B, 0x60, 0x83, 0xA7, 0x6A,
    0xCD, 0xF0, 0xF4, 0xB1, 0xCB, 0x56, 0xDD, 0xF0, 0xDD, 0xFB, 0x36, 0x8A, 0xB4, 0x4F, 0xD2, 0x2E, 0x0C, 0x1C, 0x6A,
    0xB4, 0xF0, 0x77, 0x58, 0x4B, 0xD1, 0x7B, 0xFD, 0x94, 0x4F, 0x66, 0x52, 0x1B, 0x05, 0x5A, 0x55, 0x68, 0x63, 0xE5,
    0xDE, 0x90, 0xF6, 0x4D, 0x63, 0xC2, 0x21, 0x9E, 0xDD, 0x36, 0xA0, 0x58, 0x8A, 0x5E, 0xA7, 0xFF, 0xA7, 0x39, 0xC7,
    0x5A, 0x8C, 0x3C, 0xD0, 0xA6, 0x21, 0x63, 0xF7, 0x09, 0x80, 0xE0, 0x05, 0x35, 0x47, 0x6A, 0x95, 0xBB, 0xD3, 0x94,
    0x30, 0xC8, 0x22, 0xBB, 0xA1, 0x43, 0x64, 0xF2, 0xEF, 0x7E, 0xAA, 0x04, 0x71, 0x5D, 0x04, 0x29, 0xFC, 0xF2, 0x22,
    0xC5, 0x7C, 0x3A, 0xF9, 0x18, 0x53, 0xBC, 0x41, 0xDE, 0x37, 0xDD, 0xEE, 0xEA, 0xA1, 0x76, 0xF3, 0xB6, 0x3A, 0x8E,
    0x93, 0x44, 0x74, 0x54, 0x34, 0x50, 0x3A, 0xAA, 0x75, 0xFE, 0x7D, 0x78, 0xD8, 0xF0, 0x04, 0x61, 0xE6, 0x87, 0x09,
    0x00, 0x0D, 0xE7, 0x10, 0x42, 0xE4, 0x1A, 0xDA, 0x9B, 0x02, 0x7F, 0x41, 0xFE, 0x47, 0xC1, 0x1F, 0x4B, 0x53, 0xF6,
    0x8A, 0x09, 0xFB, 0x99, 0x7C, 0x8C, 0x91, 0xEB, 0xE0, 0x6B, 0x45, 0x0A, 0x18, 0xAE, 0x3D, 0xED, 0x25, 0x62, 0x2D,
    0x2E, 0x4A, 0x40, 0xF3, 0x68, 0xAA, 0xA1, 0x6A, 0xE2, 0x04, 0x34, 0xFA, 0xD9, 0x52, 0xA4, 0x44, 0x5D, 0x8E, 0x40,
    0xCE, 0x2C, 0x0A, 0x97, 0xB8, 0x1E, 0x6F, 0xC7, 0x05, 0x9C, 0x4F, 0x83, 0x68, 0x66, 0x3F, 0x65, 0xA6, 0x0B, 0xF7,
    0x43, 0x6E, 0x22, 0x42, 0x47, 0x10, 0x2A, 0xD3, 0xC9, 0x3B, 0x97, 0x8E, 0x21, 0xF2, 0x60, 0x9C, 0x90, 0xBB, 0x86,
    0x33, 0x10, 0x9B, 0xD4, 0x18, 0x5C, 0x32, 0xD7, 0xAE, 0xE6, 0x9F, 0x26, 0x88, 0xF7, 0x41, 0xF3, 0x42, 0x97, 0x06,
    0x16, 0x8B, 0x4E, 0xAE, 0x8F, 0x29, 0xDA, 0xAB, 0xE8, 0x18, 0x8A, 0x4B, 0x48, 0x5F, 0xF0, 0xF6, 0x36, 0x50, 0x86,
    0x9C, 0xF9, 0xE3, 0xCF, 0xB5, 0x62, 0xD1, 0x50, 0xCF, 0x98, 0xC0, 0x4A, 0x67, 0xAE, 0x54, 0x8B, 0xAC, 0x81, 0x89,
    0xCB, 0x38, 0x18, 0xCD, 0xC8, 0x7D, 0x35, 0xA9, 0xCD, 0xBE, 0xD2, 0x96, 0xFC, 0xD3, 0xDA, 0x6C, 0xC8, 0x68, 0x2E,
    0x23, 0xCF, 0x99, 0x7F, 0x55, 0xDB, 0x91, 0xBA, 0x23, 0xE9, 0xEE, 0x23, 0xEA, 0x2D, 0x4B, 0x6A, 0x53, 0x32, 0xED,
    0x05, 0xB7, 0x31, 0xAF, 0xFA, 0x47, 0x6C, 0x2E, 0xAF, 0x02, 0xD8, 0xC5, 0xCE, 0x8E, 0x71, 0x5D, 0xB3, 0xE7, 0xAF,
    0x4B, 0x74, 0xDB, 0x68, 0x9B, 0x3F, 0x29, 0xD1, 0x82, 0x8A, 0x68, 0xC9, 0xE2, 0xC1, 0x1B, 0x15, 0x6F, 0xD6, 0x90,
    0xC4, 0x1B, 0xE0, 0x73, 0xF2, 0xE9, 0x53, 0x8F, 0x05, 0x28, 0x3F, 0xAC, 0x79, 0xCE, 0x05, 0xFF, 0x47, 0x27, 0x18,
    0x43, 0x3B, 0x31, 0x86, 0x3E, 0x77, 0x5A, 0xFF, 0x5F, 0x51, 0x21, 0x02, 0x23, 0x81, 0x07, 0x98, 0xB9, 0xC1, 0xBC,
    0x99, 0x6D, 0x36, 0x19, 0xDF, 0xC2, 0x32, 0x99, 0x2D, 0xA8, 0x4C, 0x42, 0x93, 0x6A, 0x04, 0x0A, 0x3E, 0x9A, 0xFC,
    0xD4, 0xD4, 0x4A, 0xD7, 0x8E, 0x7C, 0xDE, 0x71, 0x04, 0x7B, 0x92, 0x92, 0xC9, 0xE8, 0x86, 0xCC, 0x0F, 0xAD, 0xAE,
    0xA6, 0x9F, 0x28, 0x2F, 0x74, 0xC1, 0x6C, 0x10, 0x4C, 0xCB, 0x5A, 0xFF, 0x90, 0xE8, 0xA1, 0x11, 0x4A, 0x2A, 0x3E,
    0x2A, 0xE4, 0x37, 0x8A, 0xED, 0x04, 0x7D, 0xC2, 0x3B, 0xBD, 0x0E, 0x0B, 0x7A, 0x5E, 0x60, 0x7B, 0xF6, 0x9D, 0x5C,
    0xD2, 0xDF, 0xF9, 0x02, 0x9D, 0x7D, 0x28, 0x81, 0xBF, 0xF8, 0x01, 0x60, 0x05, 0x68, 0x78, 0xA4, 0xB9, 0x1C, 0x63,
    0xCD, 0xB6, 0x64, 0xD8, 0x85, 0xD9, 0x8E, 0x1A, 0xE0, 0x3B, 0x36, 0xA3, 0x71, 0x61, 0x57, 0x3F, 0xB6, 0x96, 0x9C,
    0xFB, 0xED, 0xAB, 0x53, 0x5D, 0xD5, 0x69, 0xEB, 0x5F, 0xCA, 0xDF, 0x62, 0x3C, 0x5A, 0x5B, 0x06, 0xBC, 0x63, 0xC7,
    0x81, 0x1E, 0xAA, 0x79, 0x87, 0x63, 0x31, 0x95, 0x63, 0x91, 0xC4, 0xD2, 0xBF, 0xD4, 0xF2, 0x54, 0xF9, 0x65, 0x9C,
    0x87, 0x68, 0xC4, 0xD9, 0xCB, 0x40, 0xD7, 0xC9, 0x65, 0x45, 0x1E, 0xDB, 0x47, 0x3E, 0x30, 0xE8, 0x31, 0xEA, 0xCF,
    0x87, 0x9F, 0x92, 0x99, 0xC2, 0x71, 0x03, 0x63, 0x82, 0x42, 0x5B, 0x86, 0x01, 0x11, 0xE8, 0x87, 0xC5, 0xDB, 0x81,
    0x7B, 0x6F, 0x0F, 0xB3, 0xB2, 0xEF, 0x85, 0xDB, 0x17, 0x23, 0xAB, 0x0D, 0x9B, 0xC2, 0x27, 0x19, 0x95, 0x87, 0xF4,
    0x0F, 0x4C, 0x57, 0xE1, 0xB3, 0x0B, 0x97, 0xC0, 0xE1, 0x4D, 0xDB, 0x4F, 0xE5, 0x67, 0x2B, 0x7A, 0x9B, 0x30, 0x05,
    0xFE, 0x9D, 0x68, 0xD6, 0x11, 0x57, 0x30, 0x92, 0x34, 0x7B, 0x9C, 0xB0, 0xE0, 0x15, 0x35, 0xFF, 0xBC, 0x35, 0x59,
    0x8E, 0xDA, 0x15, 0x84, 0x75, 0x7B, 0x42, 0x84, 0xD8, 0xB7, 0xD0, 0x6A, 0x3F, 0xC0, 0xFA, 0x0C, 0xC7, 0x40, 0x78,
    0xA0, 0xCA, 0x55, 0x8C, 0xFB, 0xBB, 0x27, 0x0D, 0x92, 0xDB, 0x6E, 0xC8, 0x5F, 0xBA, 0xD0, 0xCA, 0x7E, 0xEC, 0x5E,
    0x56, 0xCE, 0x4A, 0x77, 0x9C, 0xAF, 0x3E, 0xAA, 0x5F, 0x8C, 0x0F, 0x97, 0x99, 0xC5, 0xE1, 0xBE, 0x9C, 0xB7, 0x4D,
    0xF9, 0xA4, 0xB7, 0x89, 0x73, 0x40, 0x51, 0x66, 0xF4, 0xB3, 0x52, 0x13, 0x09, 0x6E, 0x1D, 0xB6, 0xC2, 0x71, 0xAF,
    0x2D, 0x8D, 0x8E, 0x13, 0x54, 0x43, 0xE5, 0x77, 0x65, 0xB8, 0x08, 0xC9, 0xCB, 0x88, 0x06, 0x4A, 0xC6, 0x05, 0xE9,
    0xC1, 0xCD, 0x72, 0xA3, 0xDB, 0x55, 0x4E, 0xD4, 0x8F, 0xC3, 0x90, 0x63, 0x8C, 0xCC, 0x68, 0x9D, 0x88, 0xEC, 0xE8,
    0x7F, 0x18, 0x63, 0x8C, 0x96, 0xD6, 0xD0, 0x7B, 0xAF, 0xAF, 0xCD, 0x38, 0xBB, 0x36, 0x1C, 0xC4, 0x52, 0x7D, 0x84,
    0xF9, 0xD2, 0x81, 0x62, 0x9A, 0x00, 0x83, 0x8F, 0x19, 0x36, 0x56, 0x64, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x15, 0x31, 0x16, 0x04, 0x14, 0x3B, 0x51, 0x48, 0xCB, 0xF5, 0x82, 0xCA,
    0xA7, 0x9A, 0xC0, 0xBC, 0xD5, 0x0A, 0xCE, 0x47, 0x15, 0x6E, 0xA6, 0x29, 0x7A, 0x30, 0x31, 0x30, 0x21, 0x30, 0x09,
    0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0xB6, 0x87, 0xA3, 0x30, 0xEA, 0x41, 0x98, 0x2D,
    0x88, 0xB0, 0x1F, 0x25, 0xF7, 0x1C, 0x55, 0xB9, 0x1D, 0xA7, 0xA9, 0x19, 0x04, 0x08, 0xB4, 0xEF, 0x77, 0xFC, 0x23,
    0x4A, 0xFE, 0xBB, 0x02, 0x02, 0x08, 0x00 };

static const char g_testKeystorePwd[] = "123456";

const uint8_t g_testIssuerValid[] = { 0x30, 0x17, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0C,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x4E, 0x43, 0x20, 0x43, 0x41, 0x20, 0x31 };

static const uint8_t g_testOcspResponses[] = {
    0x30, 0x82, 0x01, 0xd3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0xcc, 0x30,
    0x82, 0x01, 0xc8, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x01, 0x01, 0x04, 0x82, 0x01, 0xb9, 0x30, 0x82, 0x01, 0xb5, 0x30, 0x81,
    0x9e, 0xa2, 0x16, 0x04, 0x14, 0x6a, 0x4e, 0x50, 0xbf, 0x98, 0x68, 0x9d,
    0x5b, 0x7b, 0x20, 0x75, 0xd4, 0x59, 0x01, 0x79, 0x48, 0x66, 0x92, 0x32,
    0x06, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x30, 0x35, 0x32,
    0x30, 0x33, 0x36, 0x33, 0x31, 0x5a, 0x30, 0x73, 0x30, 0x71, 0x30, 0x49,
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
    0x14, 0xd6, 0x13, 0x07, 0x5f, 0xb6, 0xde, 0xa1, 0x1b, 0xdf, 0x01, 0x82,
    0xd3, 0x97, 0xe1, 0xd3, 0x7c, 0x6e, 0x92, 0x55, 0x09, 0x04, 0x14, 0x6a,
    0x4e, 0x50, 0xbf, 0x98, 0x68, 0x9d, 0x5b, 0x7b, 0x20, 0x75, 0xd4, 0x59,
    0x01, 0x79, 0x48, 0x66, 0x92, 0x32, 0x06, 0x02, 0x10, 0x0a, 0x21, 0xd8,
    0xb7, 0x8d, 0x5d, 0x97, 0xc8, 0xef, 0x41, 0x44, 0xf2, 0xd4, 0x76, 0xdb,
    0x65, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x30,
    0x35, 0x32, 0x30, 0x32, 0x31, 0x30, 0x32, 0x5a, 0xa0, 0x11, 0x18, 0x0f,
    0x32, 0x30, 0x32, 0x34, 0x30, 0x37, 0x31, 0x32, 0x31, 0x39, 0x32, 0x31,
    0x30, 0x32, 0x5a, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
    0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x8f,
    0xaa, 0x3d, 0xe7, 0x93, 0xbd, 0x42, 0x35, 0xd2, 0x47, 0x68, 0x9a, 0x3b,
    0x5d, 0x33, 0x42, 0xa6, 0xb4, 0xda, 0xfd, 0xd4, 0x18, 0x67, 0x61, 0xe4,
    0x56, 0x4a, 0x07, 0x75, 0x1d, 0x67, 0xd0, 0xfd, 0xc9, 0xde, 0xfa, 0x31,
    0xc9, 0xe7, 0xba, 0xf9, 0x8d, 0xfe, 0xa8, 0xc3, 0x67, 0x63, 0x8e, 0xa7,
    0x28, 0x7e, 0x00, 0x51, 0x81, 0x4d, 0x37, 0xa8, 0x15, 0x87, 0xc0, 0x4f,
    0xa5, 0xef, 0x5b, 0x37, 0x9e, 0x00, 0x49, 0x82, 0x90, 0x91, 0x04, 0x0b,
    0x81, 0xb3, 0x60, 0x64, 0x85, 0x76, 0x78, 0xf7, 0xe3, 0xd6, 0x23, 0xf9,
    0x5e, 0x81, 0x69, 0xdc, 0xd8, 0x43, 0x31, 0xd1, 0xab, 0xa2, 0xf8, 0x76,
    0x1a, 0xe1, 0x5b, 0xb1, 0x03, 0xe7, 0xa0, 0xd5, 0xe7, 0x87, 0x71, 0x8b,
    0x2d, 0x6d, 0x80, 0x3e, 0x02, 0x97, 0xbf, 0x3f, 0x56, 0xb5, 0x54, 0xda,
    0x38, 0x86, 0x18, 0x34, 0x6b, 0xab, 0xe5, 0x64, 0x70, 0xc0, 0x76, 0xb8,
    0x03, 0xbd, 0x64, 0x92, 0x05, 0xa9, 0x0e, 0x7c, 0x7b, 0x72, 0x62, 0x24,
    0x7e, 0x40, 0x03, 0x32, 0xb1, 0x6b, 0xa8, 0x8c, 0x2a, 0x8c, 0x9c, 0xd8,
    0x43, 0x0a, 0x72, 0x17, 0x27, 0x71, 0x54, 0xbc, 0x77, 0x1e, 0xd2, 0x37,
    0x3b, 0x38, 0x7c, 0xc8, 0x54, 0x22, 0x3c, 0xaa, 0x02, 0x15, 0x07, 0x1c,
    0xc3, 0xdc, 0x0e, 0x6a, 0x4c, 0xea, 0x5a, 0x88, 0xbe, 0x8e, 0xc9, 0xe0,
    0x08, 0xfc, 0x87, 0xdc, 0x39, 0xe4, 0x50, 0x47, 0x9c, 0xda, 0xdb, 0x95,
    0xd5, 0x41, 0x09, 0x14, 0x23, 0x8d, 0x54, 0xb8, 0x34, 0x91, 0x2e, 0x10,
    0x6b, 0xe2, 0x6c, 0xa0, 0x8c, 0x5c, 0x88, 0x81, 0x08, 0x7e, 0x1d, 0xc8,
    0x8b, 0xcf, 0x8d, 0xe2, 0xfc, 0x2f, 0xf3, 0xc6, 0x27, 0xf9, 0x27, 0xd4,
    0x21, 0xe8, 0x1b, 0x30, 0xe1, 0x65, 0x80, 0x76, 0xa7, 0x8d, 0x4d, 0x68,
    0x80, 0x3b, 0x4b};

static const char g_crlDownloadURI[] =
    "http://crl3.digicert.com/DigiCertGlobalRootG2.crl";

static const char g_digest[] = "SHA1";

static const char g_crlDownloadURIHttps[] = "https://ocsp.digicert.cn";

static const char g_crlDownloadURIHttpsInvalid[] = "https://www.123.com";

#ifdef __cplusplus
}
#endif
#endif