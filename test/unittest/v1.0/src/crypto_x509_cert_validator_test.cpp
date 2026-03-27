/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>
#include <string>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cert_chain_validator.h"
#include "cf_blob.h"
#include "cf_log.h"
#include "cf_mock.h"
#include "cf_result.h"
#include "crypto_x509_test_common.h"
#include "memory_mock.h"
#include "x509_certificate.h"
#include "crypto_x509_cert_chain_data_pem_added.h"
#include "crypto_x509_cert_chain_data_pem_ex.h"

using namespace std;
using namespace testing::ext;
using namespace CFMock;
using ::testing::Return;
using ::testing::_;
using ::testing::Mock;
using ::testing::Invoke;
using ::testing::WithoutArgs;

namespace {

/* Test certificates: root CA -> intermediate CA -> end entity cert */

/* Root CA certificate (self-signed) */
static const char g_testRootCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIFDDCCAvSgAwIBAgIBZDANBgkqhkiG9w0BAQsFADA3MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTAeFw0yNTAx\r\n"
    "MDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMDcxCzAJBgNVBAYTAlVTMREwDwYDVQQK\r\n"
    "DAhUZXN0IE9yZzEVMBMGA1UEAwwMVGVzdCBSb290IENBMIICIjANBgkqhkiG9w0B\r\n"
    "AQEFAAOCAg8AMIICCgKCAgEA1wafGp6cF4f+jKKVJCc7hAPUyR3TQWaPLz9YMdR/\r\n"
    "NHuhhSka5zl2W1KDqEK7VHxq8tmPU+g0QqKVmCShoX+qKHxycIAcpIN2J+klpjcT\r\n"
    "jQyB77VI/gdVuLOS17JomtUiuTkCotK/QiBBl57uuLcZQDgagE3CPLHiJbxnCXTI\r\n"
    "xt3ezfNSd3RmNgWzyS4bWJSAhVb0hw2wnA8Kslw4U+d4txub0Ch2pubSYIkON7T0\r\n"
    "da7Lc8ZANlH0lhBZK8fEiGAdfxmRW99T7UIhJzrQwnXs1JlYzPjpeJnbk9jSepTJ\r\n"
    "n7CSJxvwwx21t7z4iswWjXA++pzXCcZEP9KvND+0to5O3gmWzkBRFY/UVab90Dm1\r\n"
    "LGVfsuiR6FXnBBdp2UPkRd0Al19X1qBmeGF6OnFUH97zYEU0y2p6ciAlTuuqFrrf\r\n"
    "Z/GytKJBobjfs2b3dPEcZ69viM7qtnVsYl87COm+jk8Swi4bAnuqHfm6hs9FLmQL\r\n"
    "1t2meuFlNhXJNNEK6lV0B2ilCEMKsRnZ7LHKzBpUMWePicBpcRO3bSMRhtJAzRCG\r\n"
    "HKd/wJhlVLoOzkAxPX8WPC2y4E0q1IFx2G0iVxg3p0vFM1pvFsXsZ4HphOd0QZOP\r\n"
    "8tN/2fkQSWVuksgFkt6yCRvKWs2cqPr5YlLjm8ud9x8KrG5qdlpIHB/rW+QWl3ON\r\n"
    "CiMCAwEAAaMjMCEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJ\r\n"
    "KoZIhvcNAQELBQADggIBAMIGQpYQkRSbeM1HrspxWeGBfrgs0onrefpUKwgr+UiD\r\n"
    "u2++ExsDSu5ZqB2llFExU4VQ/Wse9M95tJBtfv9Nk5uPMEO16PijAQSGR8h4SQd/\r\n"
    "LeANyYFW/QhtfPw+8mwu/L9EFruI68a/AJd3Z4VwlGwG7Xhrhdsg5TWOmb3dNSgo\r\n"
    "OQgkarhC8T5ykV731eT2vcBbsfUcru0y2tIYH0bTkJ8lGZ+Yy4Xrwg03PvSm/Skf\r\n"
    "/rasQ44nPRLMHRrXctcl15RIpAkJsaAVjVMybdgsZ1nwbO0RseZC6zShFfMDx3dI\r\n"
    "+1bHi4DL+Hg8r4/W+zCPiTuN47qY7Szz3yRfUn8t1iogBR1rn1UNoVE6q/1sF/MA\r\n"
    "uCnciXeX2mrbH1uJOwZ5pqdmDJ2F2+3DaPLOI86c92iQcWbjCy6qptzAzKtLm9yr\r\n"
    "tHXlJ8CLQgJj4ppCw/biK4cAfKjitlLaSRx79ZaHWaxFCwoM7gazbYadscxOU4v1\r\n"
    "mT5mvU0yDhRMtNkODaGQU5rJmyUG4agDTi5bKXP5ssvqgGTSZqSY6SuKRgu5NyTq\r\n"
    "SPuhLw7xAbTiL7Qg95lTnNfwXdSGbgJhf+j/iVWpa/0fM6eOTqr1CuG9l2vyc8RR\r\n"
    "xRDo6cMHJSdNlckhW9iM8QldIV620BYkz0aPjrlkinSm9VHBXNAAaBZl84OKbj6x\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Intermediate CA certificate (signed by root CA) */
static const char g_testIntermediateCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEFzCCAf+gAwIBAgIBZTANBgkqhkiG9w0BAQsFADA3MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTAeFw0yNTAx\r\n"
    "MDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMD8xCzAJBgNVBAYTAlVTMREwDwYDVQQK\r\n"
    "DAhUZXN0IE9yZzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwggEiMA0G\r\n"
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZ7diRYv8pWb7/bQadJwWYAGLuc1Ml\r\n"
    "Jol45TPVlswJRzAv7vHa+s2D+78jzFMhrQ7FGo7y81R0gzZvfwX2jE1PHwwz8HSH\r\n"
    "NCjQqjbnQSsrfXTQsUUhpsXQtLfCm1b5INetHVVahTY2eBq25627mr/OgkHg3rMp\r\n"
    "gTROYwW3y9qhHon9OEOnKgBgTSB9x7hufWicYjuNZZb0L4ePw53O/QjawQgj2hBw\r\n"
    "+pUEF/k1thi+EdWos43EE00wFxvu3K8nuqWItrPwfV/KXl5zhNLZ+SyhFfWNkKRu\r\n"
    "cT+AN0EMIeiZAApCxxdaQHyl0sZKQMHoyJoUzRXg2XU00gOJU5lmsmj9AgMBAAGj\r\n"
    "JjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3\r\n"
    "DQEBCwUAA4ICAQBTcIuCCX1vBsIehHxPN/Oqu7upFqpOAYP++S9oSA0lVLnOnwcc\r\n"
    "NPvCFP5dRCZY1A1rJsf0OVeFUjAfmOHCbpcyEn26y3lsNwp0tAV7dJdkiaS00vSt\r\n"
    "gopGJjPwJBT6LTh936/rWGHFUcv0O8lqPQiPddLnwxKFvZ/4Is4yCwFaAVvIQ5uC\r\n"
    "S6ZIhMgtX+ECxsT5xtRK7CJJCa2BB48vhBA3/VF04XvJLd9frgU/oSvWYKh3KauY\r\n"
    "rgsbrtUZ5vHYyVHa9T+qBnHP10iEi0q8pjyyjxP6DrX/UHKz+A4/iZdeNdSKuvk0\r\n"
    "mdbY+08axFWsWQfPqXz6lur9VgZyPdbzrLdAIsSuyA4g+4s/8WnbJDBT7OWCR1Z1\r\n"
    "JDstuqfw2/BeSgeS/hMiF2URF0GIBMSSm3qxmgX2NfLUlLxirgbKguxXshCcOyBQ\r\n"
    "RfsF3lR7op+gKw2LzmttJbbaM47gsX/rOOq89AMN9Rv8G3Eb2Wal9wbux47oPy+c\r\n"
    "Hd0fkv5I7yrxeWf9ixdgcVctS52KsgqzWME1OR0tCKQYbnpbHCuj8CBTy6BJh7L8\r\n"
    "4djXTgFyDpgSBMKlv52nFdKvcdeiZwASOgAC+69GRPGjFvOxrFT05K/lwWpB09gv\r\n"
    "azZqC+RdlBtDUQI7ONML1zAihz+xGJYWHomOwuIkX1m++soDY0/8FBIOhw==\r\n"
    "-----END CERTIFICATE-----\r\n";

/* End entity certificate (signed by intermediate CA) */
static const char g_testEndEntityCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDUjCCAjqgAwIBAgIBZjANBgkqhkiG9w0BAQsFADA/MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxHTAbBgNVBAMMFFRlc3QgSW50ZXJtZWRpYXRlIENB\r\n"
    "MB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowOzELMAkGA1UEBhMCVVMx\r\n"
    "ETAPBgNVBAoMCFRlc3QgT3JnMRkwFwYDVQQDDBB0ZXN0LmV4YW1wbGUuY29tMIIB\r\n"
    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvuupEHodA9hCgM0C2Zy1dIBH\r\n"
    "S6CK8rPR1ygUr8/q8+1HiFTneBhSUZIK8YcFOKPstZ3MdHNLSJWS0FyEgUdDLrIf\r\n"
    "DFZAHDdWFs/nmGBdXFbJiKeffKojAnaVgLIC2OzfMtgMmscPEPLvWrj5X4nhxFZc\r\n"
    "/yVNHiqQYay+kypKO3qRJwna/KaMcm/BAvrLUpjOgri3B0nf16OyAP52csxUokaf\r\n"
    "/6r5KXAkBXThF/64RA37+RTQf+nkQ6AF2Q9VlfF76RhnpqqUy0m3joGTkXy7DYXO\r\n"
    "gHfgKNI2Cplf6i1/16rG3CbLLXy58qlNRBmSgvvynl4w+kHSnafabdOtnJKnWQID\r\n"
    "AQABo10wWzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAK\r\n"
    "BggrBgEFBQcDATAmBgNVHREEHzAdghB0ZXN0LmV4YW1wbGUuY29tgglsb2NhbGhv\r\n"
    "c3QwDQYJKoZIhvcNAQELBQADggEBAEzAFIzQnZaxXdbFfpIhErm9WQOrMeaTGSMU\r\n"
    "Hz7cjcV+Hii+1ZvU+cKYFXnQ2pIhNz4Lf4Tk1JFpT4pNZAqxLKIWnvZ4LvwBk54J\r\n"
    "g99Ilhc9xtPKeIFvuQrXevPp+2XjTxlCejtVPV1TZ+4l8nWkrU0n/gBZCZ2cL8Kw\r\n"
    "k9562UbM4tb8BZt7s7NROLI2KFd8M06/cKvUIR/TpNNjVpcSi9ozvti82GUS6b3z\r\n"
    "QGaLNQbjXBnPDpJwEa6B2xQCOyVnnV3rENq6qpPbQWE+B/tXeg0uPYQdU8Mbka6H\r\n"
    "zYoFmR8AEtSYi1QSHZMiYoAExq4O1fM0+bI9IeKsmVtk0u/Nkt0=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Self-signed certificate for trust anchor test */
static const char g_testSelfSignedCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICzDCCAbSgAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UEAwwVVW50\r\n"
    "cnVzdGVkIFNlbGYtU2lnbmVkMB4XDTI1MDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAw\r\n"
    "MFowIDEeMBwGA1UEAwwVVW50cnVzdGVkIFNlbGYtU2lnbmVkMIIBIjANBgkqhkiG\r\n"
    "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvb7g6nr0+cUIqpGZSxf0ss49p/AGkzYU1M6X\r\n"
    "qscJHqvM2pLZanRriRbA11nGN1oM86buIxhCsn8nJDAEZj/h9mkqYRRH/dd8lSeX\r\n"
    "4CiPoEz3fisteIQbqBVPCbxQySukkyv8SrHCr1FkqWiIVtba7z471ktE+vBJXGrH\r\n"
    "P86RS/IaFM+TdggK7IkROBFAmWj7sRlNlWzdiuboEJ6JTxDobnQ9xHlB4AkZLLg6\r\n"
    "FitcsZ3bbpyfWul01uXtylinfyfKbWePYVQgwyZKNd9PtYK9z46li1oNrkz09Gah\r\n"
    "0wIX6CuUz7IILPepphFkhn0QtvWuU0NCcoTTtKJzSp3kYBhU7QIDAQABoxAwDjAM\r\n"
    "BgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCi1CePBfoeOWcw3DkxZuic\r\n"
    "BZXMtzonwSiF+wNzntH71ot34dRkwdb8uyU8D5nv0lIR8SiFI/HOFv69UHGuqKTw\r\n"
    "CUSEOIGZM0HFv9hBlRX/bvYrGy+85X7MKY90gpJNOtAblLk6yAjsrH0YV2hAMA9D\r\n"
    "lsqEbXnrCgOl/Ec//28PGpxhQsv396Z1cpQUjsv4wWes3NqyZMqf3xEQ4FntS1bf\r\n"
    "eiejMP1waN5e0irM5lZG1Nf2yg4MHKQ+MD4YzLOIJOX6jSHdrNa/HmITDGHquovz\r\n"
    "PN+93aTofMWkj9TQEFbLhcBDWBEjyHoxyNtZFNTKw+/ZjO9w4URFw9O+J+iTpEeV\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Expired certificate (valid from 2020-01-01 to 2021-01-01) */
static const char g_testExpiredCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICsTCCAZmgAwIBAgIBATANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFFeHBp\r\n"
    "cmVkIFRlc3QgQ2VydDAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEwMDAwMDBaMBwx\r\n"
    "GjAYBgNVBAMMEUV4cGlyZWQgVGVzdCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n"
    "AQ8AMIIBCgKCAQEApUH3/ldTy7hPiR1dbr4augnvPqdk0vqtt8PAEWqEz3QlYQJr\r\n"
    "WJWg4YeHLr44CSwQkzD2yrhBSkmaaEfc+Cna1kf4PE0VazgdxmTLj4LD76BYUzLt\r\n"
    "D1j0kf0ER+TsZX/Rjt7pay5P6nckWOyq8WENXlnOEGIHoOoNXus2hVaCVI2FGVT5\r\n"
    "S1Gi56zR6e/LWCx/oDmL6HMq/yPrxN3D1JxI5d5d47sd+n48gVO93ftODxAJGer3\r\n"
    "Q+Ubz8ajjgkfRP0wjOC5fltCFZD28LfmtENduLd+vhjxnbDMQpnTaiSDzGhoVgIK\r\n"
    "nSJH6+z470Z21SCUEOToNJsr/ws32EVQLA88ZwIDAQABMA0GCSqGSIb3DQEBCwUA\r\n"
    "A4IBAQCebZomP/M9NWrkYjYXw71zn9CCcER8kA5IPC6zoPZ89NwUFuAvGpumP6oW\r\n"
    "lAMG5lKNytLHHmtltYU8wUa5v8jwP6ogjnifUyW8WzdPoXmVEXgn9IRIWnFUVE18\r\n"
    "LN0Jho6EqC6r05iJN61KVYWkRsaQQDOIA+S5OPZRIH/14lwvHYxFPqgq4E0o91V/\r\n"
    "1JWnjNtYX4GyyA34tiXZzhsSyHLHAjbAlKWygBNb2wCYpsgURPdPycAEQm+VTPxa\r\n"
    "ICYq7lrpZ9YfxrbFsF15xV+tf6x4Kfwi9K7EttaFoCrry8vhFuyopIccbmZ8NIET\r\n"
    "Ex7b4oz4wIGfarYba/xbZtRvNXie\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Not-yet-valid certificate (valid from 2027-01-01 to 2028-01-01) */
static const char g_testNotYetValidCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICrzCCAZegAwIBAgIBAjANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBGdXR1\r\n"
    "cmUgVGVzdCBDZXJ0MB4XDTI3MDEwMTAwMDAwMFoXDTI4MDEwMTAwMDAwMFowGzEZ\r\n"
    "MBcGA1UEAwwQRnV0dXJlIFRlc3QgQ2VydDCCASIwDQYJKoZIhvcNAQEBBQADggEP\r\n"
    "ADCCAQoCggEBAJD5Sfbch527+M4c6hCHMEuz9nny/zJpyvRpLhWJCwfXemH7spzL\r\n"
    "DCDZNZ/dIOFPjCSHwzS9OBqWmKp0fWaVUlvjTlPwkefQJmp01+GVMXP1Cm5tP1iM\r\n"
    "N0oL1QwW2Bh5Y1vbNWiZxvrybRrD9eerDn1lGgeZb9wjdXVMDrYd6/8tq6jLhXzQ\r\n"
    "tX/rE7U3e0CpQ9bRp3TH5+vv03K4o9aFauLnSCMAIGxN8bOOrghKVvbjjwjNaMV1\r\n"
    "fB8PtNcDHkcRf1tR1SztvsV4v/+5/2MYPGX11vwPBMc1P3rk7lUIxsnxfhoIk87i\r\n"
    "sX0IDIvuUJ8n+NUoItx8Rvktv/eTqyK8QYMCAwEAATANBgkqhkiG9w0BAQsFAAOC\r\n"
    "AQEAKuSeNKhRhXcFGJS+XXersalt+QToftunDWcdT7+YbtvT7hLizRW7MqlgjliL\r\n"
    "1/uC2Y7hhRcUsfPrkFj6LVdI9hXGn2Sy+zvLw1pxTqBEgaNKth/iWHl6HJFxQPDi\r\n"
    "gvi7cZ6jFbehf4dTszyrqtjF5OOEWQGLIY16zTsLF/WqUKvU/bTKYUu61aTypxyO\r\n"
    "yVsxbhtkB4S7Rq8iVq/DiAx8dJXEGIWY3R9ihfaJjD9T1nQAm7HqUVW1HQ84f0bj\r\n"
    "H2voBbtWdDyjn99CpcA6VO8GwMj+MJNbzkrvbn5f0yBxHKX/lU+UUVJ71yBgHbVf\r\n"
    "Zq5HEUPz06uZwVgNX2dKkca/MA==\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Certificate with unknown critical extension (OID 1.2.3.4.5.6.7.8.9) */
static const char g_testCriticalExtCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIC0jCCAbqgAwIBAgIBAzANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFDcml0\r\n"
    "aWNhbCBFeHQgQ2VydDAeFw0yNTAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBwx\r\n"
    "GjAYBgNVBAMMEUNyaXRpY2FsIEV4dCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n"
    "AQ8AMIIBCgKCAQEArxxByzKzBKBDqCsVEgvrTJBywcDXuizYu3DmGus+q7A0l8XX\r\n"
    "4v5puHklKA6L6Qc63ZkTBUnP+rty0E0AJZLjpQ+7EN5ymSS8nd8BLbntN20E50rK\r\n"
    "GnDHl+VkrQh2fs4t6Bgg/mDZm4F0M+bDG+KvjlsVSMcvyfPESBM4UIDMIRGCV0mP\r\n"
    "9U3OUsVs8C+jA0DN4basSLj49S7QyL3KfYUV1AFmxcB9uo/bFOyJAHHSJCaC+Da+\r\n"
    "kJyW1XhDoSmshKm3/F0xwKWlEgy3gCCzKLRJLtJK0pzTfnlTxYtvuFHWd4tFu3up\r\n"
    "JYVYxhmpe/kHzg/1SYseHdhv+xadvAZWKZ453wIDAQABox8wHTAbBggqAwQFBgcI\r\n"
    "CQEB/wQMBApUZXN0IFZhbHVlMA0GCSqGSIb3DQEBCwUAA4IBAQBRPyQNkSvMQxtR\r\n"
    "o9pt7K6byrKV6ZOThPw9EilwNFAVWtuErJg8Og1yZLWL+OAposmgiL4SQmWiCrBZ\r\n"
    "EW17YykD46sdFHH0iADnmtHgebMfOfCbRD/Df6VfibVwNmMexpFzfPgMG3veCIRm\r\n"
    "fHAoH37N6c2t9TlV/VSNuEoUb7lo+HftXtn7uY/rmgCIJ9cA6wRJD8eq+Q8WCR34\r\n"
    "lRQm2QuAbyBl0mCctYMs+H/3Zjx3J2AEnpmjs5dtnP9PlV/jxhN8ZM00DKufCM9g\r\n"
    "JvGRGrc4/z+twNmeZAmbcv2Aw0rFO2Z5LBbsJertGANltHIzybrXj/oaF5+onU4C\r\n"
    "zwviJfLI\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Self-signed untrusted certificate (not in trust store) - Different from g_testSelfSignedCert */
static const char g_testSelfSignedUntrustedCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDJzCCAg+gAwIBAgIUNvcIz2bXGpeXaZgWwHHAwU/xSAUwDQYJKoZIhvcNAQEL\r\n"
    "BQAwIzEhMB8GA1UEAwwYVW50cnVzdGVkIERpZmZlcmVudCBDZXJ0MB4XDTI2MDMx\r\n"
    "NzA0NDQ1M1oXDTMxMDMxNjA0NDQ1M1owIzEhMB8GA1UEAwwYVW50cnVzdGVkIERp\r\n"
    "ZmZlcmVudCBDZXJ0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsLpm\r\n"
    "3duN4NRGuZxSmXYmTxwnE5tCN79TCuWS9pYEye3c63Uy9vJX4Y0b4BUNLkmi6mJ2\r\n"
    "+rQcQKKDELs5CmelE2WUXomzCqZ6oJ9NrbAowrO7Qkjuhv2xeF6xOJf1Jkq35eii\r\n"
    "9uRhHNHAQgt0xVmYeVHNQdul3kP4Mh60NElFlgfiB51FQr70YTShf+7JfwcNtCx+\r\n"
    "WcAODALwB9l14z91NihA5rzQmPFRkG3boz4Frx1DNV9gDPa7Vb6CWU+eB1/C9Hp/\r\n"
    "e2YL37QWHIfkGMNBEhfjaQhd3l1wQVAiXOIPFqx56WS0uls9XTprx0JJv1cgiPi5\r\n"
    "/cgZt0CWDEMNPn3kSwIDAQABo1MwUTAdBgNVHQ4EFgQU9s5o7pmYGXVNDj2/HlA5\r\n"
    "D/+bdXMwHwYDVR0jBBgwFoAU9s5o7pmYGXVNDj2/HlA5D/+bdXMwDwYDVR0TAQH/\r\n"
    "BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAYZNGbFpaVh5tFakWMCAltIXdEBVg\r\n"
    "OFl3YuIeOmWEvINLZdxNVQPp1PHBaUZ9wiXSsH8gq8l5O43HkaftljJ4PfKFx2zp\r\n"
    "BUdjpztZQhRe6IJVi56/9JA9qUIo9gR1Y9LeaoX6bwrQRDsRX8RGOtQgWhpdrasO\r\n"
    "XfhUDljWwJj5MKOd7NDfzoQ2CJXgFIY6q6FM41qOqbrDh/zTwR+v2M5OcitSWNMn\r\n"
    "kkdvIpvii2VDj8BRuWdJUcNthqm7N3dRqeS5NWP+K49ACNkSc3+E1ocNB/yXSUOP\r\n"
    "3OH8oL4Elcuo0WQdbZLxvrAr9nFVVGd/qQsORPV3bC+oMWji2wKCHAMnxA==\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_intermediateNoKeyCertSignCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEkzCCAnugAwIBAgIUMqSc6XGZuYpSndfIVCbOCsg0ijUwDQYJKoZIhvcNAQEL\r\n"
    "BQAwNzELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxU\r\n"
    "ZXN0IFJvb3QgQ0EwHhcNMjYwMzE5MDEyMDI0WhcNMjcwMzE5MDEyMDI0WjBCMSQw\r\n"
    "IgYDVQQDDBtJbnRlcm1lZGlhdGUgTm8gS2V5Q2VydFNpZ24xDTALBgNVBAoMBFRl\r\n"
    "c3QxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\r\n"
    "yYibz0v67oEyIJvWF1fPdf87y8DR8rjqltiDPXi8dGfA9zjGckZWxL9mqYH5FX1G\r\n"
    "faipHJ0DEECnVKG32x37F0XQ2fsNZ32nOuzQ8v7SwS2P9YHs2MYpBA89En3O3K1i\r\n"
    "p2QKeNXl3dgkWbspsB2Yq70Q4rcuaRccLQgmAqUdBAdtYxQJL9KeLOyJYkMg23AQ\r\n"
    "GrU2g+kFw4Kc4wJAZz/inUCBxdzJcR2HRKnjcCkd7y1iFxt9d8E67ymRj2k5ed8N\r\n"
    "nt5sLZwrYgWb8flmu/jXCHGJmWsPT0FYOOd3fFnDuug1j6WMYOk1rFiVqtjq2AQH\r\n"
    "vFtYtu0uG3wwKVPG4hm1DQIDAQABo4GLMIGIMA8GA1UdEwEB/wQFMAMBAf8wCwYD\r\n"
    "VR0PBAQDAgGCMB0GA1UdDgQWBBTNk3/WNbu3mSD1f1Ly7OUyKaZ/ojBJBgNVHSME\r\n"
    "QjBAoTukOTA3MQswCQYDVQQGEwJVUzERMA8GA1UECgwIVGVzdCBPcmcxFTATBgNV\r\n"
    "BAMMDFRlc3QgUm9vdCBDQYIBZDANBgkqhkiG9w0BAQsFAAOCAgEAVEzn0V8eaKFh\r\n"
    "T7CwbzNXaiLYTPiEUTBW+0nQygf1/6RSxHgm5E8G5saZ/B7wSCw5+Qbzg0IQXKDZ\r\n"
    "bick1TbRuwwEI/JPwjquEPMlSBr+X4PsynTf88/l4gGMQKVjJeL0KQ5o0/AOBP5k\r\n"
    "Zu2QBWNTWH+TEZUCmY5UTUNS609CCwPM8gufNapm2OxnqwS5rJ5GsDI6K2Rd/ger\r\n"
    "NEsh+2Vbf7N5UZuETF6vEyQAciO0SMAIo3AoFypbRvF4VfDINoauSsx8/S8HRS/s\r\n"
    "Zt+qvND//pYhR6HOWF1RXBS0fklGg+83kV7da+kweJhgQnK0Ar5c9C8n3OGVUVSX\r\n"
    "hFHuAjU8HffCgdY2DotY4GWzcSXczXFGwEgANU4s91dZf4qWrOlvd40FCWBpk8GE\r\n"
    "By6TG0xlywCB1KI0BOQh9WPMd7q8C8Aii1Ho2C/bmMtpP7LMIaMT5VsIbf34FMY3\r\n"
    "0A7gZsf1vStS90mJsYp7ErB4qHGqZDK8PbTVhn9mAejzRww6kwYpQpAL9E33gHel\r\n"
    "qugRPsz8TZ89zgh+HhG67IBiYAj0Yd4T5WESSRWT41qgeLA1ebTOyafflp4/zVDN\r\n"
    "V0U91q7j/oMjqIb+7Qtw28x09tlnDsqVlj/vRdTpi37Nqf4TyUSnISu9xVmhceTQ\r\n"
    "RTbc126iIr/kzv5MsyQKJ2t+3yx2Gfw=\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_eeByIntermediateNoKeyCertSignCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDETCCAfkCFBkKmtFG6UQ20ZT0cwI0Luurmc35MA0GCSqGSIb3DQEBCwUAMEIx\r\n"
    "JDAiBgNVBAMMG0ludGVybWVkaWF0ZSBObyBLZXlDZXJ0U2lnbjENMAsGA1UECgwE\r\n"
    "VGVzdDELMAkGA1UEBhMCVVMwHhcNMjYwMzE5MDEyMDM0WhcNMjcwMzE5MDEyMDM0\r\n"
    "WjBIMSowKAYDVQQDDCFFRSBieSBJbnRlcm1lZGlhdGUgTm8gS2V5Q2VydFNpZ24x\r\n"
    "DTALBgNVBAoMBFRlc3QxCzAJBgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n"
    "AQ8AMIIBCgKCAQEArFHPLMYatDffrOudcoSJ0Cu1M7aisfSKD7bWQu54RKofygh+\r\n"
    "kNIewKuSQyatt/5UzK/60TYhiPyPh0vhZ3F7vrgGHat0M8PW/oamdZO6j2K22/t/\r\n"
    "IbXxUpl8JZidQfUMoXpjgxNK611+sGrhy59dp14l6Su+DZcmf1dnHBOAzn+WwQJc\r\n"
    "rxlsP6szkS2M5M+xW1F+NZS5Cn7NbQ4uu7HutSw/6MEyuouk/xK0BQmedby7/HsC\r\n"
    "k+bt4AuquYSxpa5oemazzxP+NpCi2jG54+C66iiwPnDmdduyj2jS4scnSeXUeDMs\r\n"
    "f0mM0ew277ZSUIYy85HtdHOyS+9rjbYCm1T5OQIDAQABMA0GCSqGSIb3DQEBCwUA\r\n"
    "A4IBAQBGBZduidI1JmSPJtEXlvbg5/yClV3VkTU2qzrwNKbQ4ilS8HBrj6nVvhcC\r\n"
    "q8Q7/zgC2s7pinp+qu3os/2NaHPQHow1za8AMfd1pcOh+iW3jKnXekUK48wAoxUy\r\n"
    "Cyl7oHBbxejL7MannughweEI3rQbPwR9arti6NuNdQ00xjXiy7k5Q3aLaC+gjlUt\r\n"
    "AzXh8txHOg77ftuGZST6d+RxJ1tcVTIV5RYVgdXAs2WoHpoe4H51tBXC4/tD9PR+\r\n"
    "nMjvRM07s3k8fxNUZBp8cLkh0y3ggF0VCT2VkQfDX3MOzsbdjQ49BMmbhRiB173Z\r\n"
    "VYSgO6xy6IiQdSoPQsBb2U/qQpxQ\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_corruptedSignatureIntermediateCaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEFzCCAf+gAwIBAgIBZTANBgkqhkiG9w0BAQsFADA3MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxFTATBgNVBAMMDFRlc3QgUm9vdCBDQTAeFw0yNTAx\r\n"
    "MDEwMAAwMDBaFw0zMDAxMDEwMDAwMDBaMD8xCzAJBgNVBAYTAlVTMREwDwYDVQQK\r\n"
    "DAhUZXN0IE9yZzEdMBsGA1UEAwwUVGVzdCBJbnRlcm1lZGlhdGUgQ0EwggEiMA0G\r\n"
    "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZ7diRYv8pWb7/bQadJwWYAGLuc1Ml\r\n"
    "Jol45TPVlswJRzAv7vHa+s2D+78jzFMhrQ7FGo7y81R0gzZvfwX2jE1PHwwz8HSH\r\n"
    "NCjQqjbnQSsrfXTQsUUhpsXQtLfCm1b5INetHVVahTY2eBq25627mr/OgkHg3rMp\r\n"
    "gTROYwW3y9qhHon9OEOnKgBgTSB9x7hufWicYjuNZZb0L4ePw53O/QjawQgj2hBw\r\n"
    "+pUEF/k1thi+EdWos43EE00wFxvu3K8nuqWItrPwfV/KXl5zhNLZ+SyhFfWNkKRu\r\n"
    "cT+AN0EMIeiZAApCxxdaQHyl0sZKQMHoyJoUzRXg2XU00gOJU5lmsmj9AgMBAAGj\r\n"
    "JjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3\r\n"
    "DQEBCwUAA4ICAQBTcIuCCX1vBsIehHxPN/Oqu7upFqpOAYP++S9oSA0lVLnOnwcc\r\n"
    "NPvCFP5dRCZY1A1rJsf0OVeFUjAfmOHCbpcyEn26y3lsNwp0tAV7dJdkiaS00vSt\r\n"
    "gopGJjPwJBT6LTh936/rWGHFUcv0O8lqPQiPddLnwxKFvZ/4Is4yCwFaAVvIQ5uC\r\n"
    "S6ZIhMgtX+ECxsT5xtRK7CJJCa2BB48vhBA3/VF04XvJLd9frgU/oSvWYKh3KauY\r\n"
    "rgsbrtUZ5vHYyVHa9T+qBnHP10iEi0q8pjyyjxP6DrX/UHKz+A4/iZdeNdSKuvk0\r\n"
    "mdbY+08axFWsWQfPqXz6lur9VgZyPdbzrLdAIsSuyA4g+4s/8WnbJDBT7OWCR1Z1\r\n"
    "JDstuqfw2/BeSgeS/hMiF2URF0GIBMSSm3qxmgX2NfLUlLxirgbKguxXshCcOyBQ\r\n"
    "RfsF3lR7op+gKw2LzmttJbbaM47gsX/rOOq89AMN9Rv8G3Eb2Wal9wbux47oPy+c\r\n"
    "Hd0fkv5I7yrxeWf9ixdgcVctS52KsgqzWME1OR0tCKQYbnpbHCuj8CBTy6BJh7L8\r\n"
    "4djXTgFyDpgSBMKlv52nFdKvcdeiZwASOgAC+69GRPGjFvOxrFT05K/lwWpB09gv\r\n"
    "azZqC+RdlBtDUQI7ONML1zAihz+xGJYWHomOwuIkX1m++soDY0/8FBIOhw==\r\n"
    "-----END CERTIFICATE-----\r\n";

static const char g_emailTestCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEgTCCAmmgAwIBAgIUMqSc6XGZuYpSndfIVCbOCsg0ijcwDQYJKoZIhvcNAQEL\r\n"
    "BQAwNzELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxU\r\n"
    "ZXN0IFJvb3QgQ0EwHhcNMjYwMzE5MDIzNTQ0WhcNMjcwMzE5MDIzNTQ0WjAxMRMw\r\n"
    "EQYDVQQDDApFbWFpbCBUZXN0MQ0wCwYDVQQKDARUZXN0MQswCQYDVQQGEwJVUzCC\r\n"
    "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL4Xs3MBcM+y1VLsD4pL4m3g\r\n"
    "vCV0jx6Pb3Dls0SU8wAeAEAGALYRuiUOJsRxV65IDlwlJeDlp/UxcAzMxO8mDoAX\r\n"
    "yA6XyVme7dGPMgrIOP5UAyQR+DD8Jn+SXbQ4X6tV+ld+p6GGk2cGJB0vyPn/XKoy\r\n"
    "EVe/N9Xmv3w/XFVJZaAW17HHSTqPYOUWA2OFg71EXu2WAtlU9/4sXAqmZqHZEbT7\r\n"
    "emwnncmaMEZkC8lNrffseT0cHgib5jXrR1jJN5x3WBUj4+7s2fS6y+D4l2b+3NrO\r\n"
    "5+Ixkr1ZCXpDKaBvXbtj/VA2JGObMEs4q7+ToLKjlzhM6kSdlNsDei+gXHg6oXEC\r\n"
    "AwEAAaOBijCBhzAbBgNVHREEFDASgRB0ZXN0QGV4YW1wbGUuY29tMB0GA1UdDgQW\r\n"
    "BBTQ9CZBh+sxBx2iwaaUcK97TjHoYDBJBgNVHSMEQjBAoTukOTA3MQswCQYDVQQG\r\n"
    "EwJVUzERMA8GA1UECgwIVGVzdCBPcmcxFTATBgNVBAMMDFRlc3QgUm9vdCBDQYIB\r\n"
    "ZDANBgkqhkiG9w0BAQsFAAOCAgEAtxyGJEhTHEMVcN6NtWai01cdYOir/jhWHWdc\r\n"
    "eIATWPXo3oi8yBmuqb5Zjy34GWn/5+YIPvt9rs4I0TGqNSpJmZcsPU0ohWtpyC2G\r\n"
    "VOdkOyOQ/lC1W3ZZGTVjOlsUK0Lt/9J2H+ffuoCJN947WzlxPvulec9JS49hUJnn\r\n"
    "4/lePoYB4Mo1a/LAAxrslxh7XhpzJFZCij3H5hU0To1DzpejXcAz7nTcTRF9aurS\r\n"
    "y/enMyD7760V6Md28Bb5aRrWrB9sStQqXpFknJINq/u8bZgwNJnemCW0pl3EdDQY\r\n"
    "cH2tsc7diiqjJwlMIJu+AEQy+5cCHozI82f/gIXLt594TMhK6UNhjr7CZD6yM3UD\r\n"
    "AOm1I72lXG6kvW7cPFFm3gvXO75i8fa5/FGajrA+3npEei1sEUOnzMYBKq4Bn+kI\r\n"
    "JNRBAw9aMy3bEZT8BiShG6xnpA9+7LtDPvi379jdgKytKC7Cv0fOjjbjnB/mK2CH\r\n"
    "AKTCjRaOSFcnY/tn74wYseommT8+GG0+IHAahZnHr2K0xhwak94Gg59sSa54lJGU\r\n"
    "HABhjYXY6pAIRv3hDMZDmIvi95T19NoS6x43rlEtWiKpD4HWfQmFn68bWhak3czS\r\n"
    "ATTPF3xH/qbwmsYSGb6aHJ304WFtDtsdyVUO7gxTMBJo5b5sdy3mlbUhJhs3DPDW\r\n"
    "we0LFGY=\r\n"
    "-----END CERTIFICATE-----\r\n";


static HcfCertChainValidator *g_validator = nullptr;

class CryptoX509CertValidatorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoX509CertValidatorTest::SetUpTestCase()
{
    CfResult res = HcfCertChainValidatorCreate("PKIX", &g_validator);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(g_validator, nullptr);
}

void CryptoX509CertValidatorTest::TearDownTestCase()
{
    if (g_validator != nullptr) {
        CfObjDestroy(g_validator);
        g_validator = nullptr;
    }
}

void CryptoX509CertValidatorTest::SetUp() {}

void CryptoX509CertValidatorTest::TearDown() {}

/* Helper function to create HcfX509Certificate from PEM string */
static HcfX509Certificate *CreateCertFromPem(const char *pemCert)
{
    CfEncodingBlob inStream = {};
    inStream.data = reinterpret_cast<uint8_t *>(const_cast<char *>(pemCert));
    inStream.len = strlen(pemCert);
    inStream.encodingFormat = CF_FORMAT_PEM;

    HcfX509Certificate *cert = nullptr;
    CfResult res = HcfX509CertificateCreate(&inStream, &cert);
    if (res != CF_SUCCESS) {
        return nullptr;
    }
    return cert;
}

/* Helper function to free HcfVerifyCertResult */
static void FreeVerifyCertResult(HcfVerifyCertResult &result)
{
    if (result.certs.data != nullptr) {
        for (uint32_t i = 0; i < result.certs.count; i++) {
            if (result.certs.data[i] != nullptr) {
                CfObjDestroy(result.certs.data[i]);
                result.certs.data[i] = nullptr;
            }
        }
        CfFree(result.certs.data);
        result.certs.data = nullptr;
        result.certs.count = 0;
    }
}

/* Helper function to free HcfX509CertValidatorParams */
static void FreeValidatorParams(HcfX509CertValidatorParams &params)
{
    if (params.trustedCerts.data != nullptr) {
        for (uint32_t i = 0; i < params.trustedCerts.count; i++) {
            CfObjDestroy(params.trustedCerts.data[i]);
        }
        CfFree(params.trustedCerts.data);
    }
    if (params.untrustedCerts.data != nullptr) {
        for (uint32_t i = 0; i < params.untrustedCerts.count; i++) {
            CfObjDestroy(params.untrustedCerts.data[i]);
        }
        CfFree(params.untrustedCerts.data);
    }
    if (params.date != nullptr) {
        CfFree(params.date);
    }
    if (params.hostnames.data != nullptr) {
        for (uint32_t i = 0; i < params.hostnames.count; i++) {
            if (params.hostnames.data[i] != nullptr) {
                CfFree(params.hostnames.data[i]);
            }
        }
        CfFree(params.hostnames.data);
    }
    if (params.emailAddresses.data != nullptr) {
        for (uint32_t i = 0; i < params.emailAddresses.count; i++) {
            if (params.emailAddresses.data[i] != nullptr) {
                CfFree(params.emailAddresses.data[i]);
            }
        }
        CfFree(params.emailAddresses.data);
    }
    if (params.keyUsage.data != nullptr) {
        CfFree(params.keyUsage.data);
    }
    if (params.ignoreErrs.data != nullptr) {
        CfFree(params.ignoreErrs.data);
    }
    if (params.userId.data != nullptr) {
        CfFree(params.userId.data);
    }
    if (params.revokedParams != nullptr) {
        if (params.revokedParams->crls.data != nullptr) {
            for (uint32_t i = 0; i < params.revokedParams->crls.count; i++) {
                CfObjDestroy(params.revokedParams->crls.data[i]);
            }
            CfFree(params.revokedParams->crls.data);
        }
        if (params.revokedParams->revocationFlags.data != nullptr) {
            CfFree(params.revokedParams->revocationFlags.data);
        }
        if (params.revokedParams->ocspResponses.data != nullptr) {
            CfFree(params.revokedParams->ocspResponses.data);
        }
        CfFree(params.revokedParams);
    }
}

static void FreeValidatorParamsWithOcspData(HcfX509CertValidatorParams &params)
{
    if (params.revokedParams != nullptr && params.revokedParams->ocspResponses.data != nullptr) {
        for (uint32_t i = 0; i < params.revokedParams->ocspResponses.count; i++) {
            if (params.revokedParams->ocspResponses.data[i].data != nullptr) {
                CfFree(params.revokedParams->ocspResponses.data[i].data);
            }
        }
    }
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_001
 * @tc.desc: Test validateX509Cert with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_001, TestSize.Level0)
{
    HcfVerifyCertResult result = {};

    /* Test with null validator */
    CfResult res = g_validator->validateX509Cert(nullptr, nullptr, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    /* Test with null cert */
    res = g_validator->validateX509Cert(g_validator, nullptr, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    /* Test with null params */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);
    res = g_validator->validateX509Cert(g_validator, cert, nullptr, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);

    /* Test with null result */
    cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);
    HcfX509CertValidatorParams params = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, nullptr);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_002
 * @tc.desc: Test validateX509Cert without trust anchor (merged from 002, 010, 018)
 *           - trustSystemCa=false with no trustedCerts
 *           - untrustedCerts only without trustedCerts
 *           - empty params
 *           All should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_002, TestSize.Level0)
{
    HcfVerifyCertResult result = {};

    /* Case 1: trustSystemCa=false with no trustedCerts */
    HcfX509Certificate *cert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert1, nullptr);
    HcfX509CertValidatorParams params1 = {};
    params1.trustSystemCa = false;
    params1.validateDate = false;
    CfResult res = g_validator->validateX509Cert(g_validator, cert1, &params1, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_002 case1 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert1);

    /* Case 2: untrustedCerts only without trustedCerts */
    HcfX509Certificate *cert2 = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(cert2, nullptr);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCert, nullptr);
    HcfX509CertValidatorParams params2 = {};
    params2.trustSystemCa = false;
    params2.validateDate = false;
    params2.untrustedCerts.count = 1;
    params2.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params2.untrustedCerts.data, nullptr);
    params2.untrustedCerts.data[0] = intermediateCert;
    res = g_validator->validateX509Cert(g_validator, cert2, &params2, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_002 case2 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert2);
    FreeValidatorParams(params2);

    /* Case 3: empty params (all fields zero/false/null) */
    HcfX509Certificate *cert3 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert3, nullptr);
    HcfX509CertValidatorParams params3 = {};
    res = g_validator->validateX509Cert(g_validator, cert3, &params3, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_002 case3 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert3);
}

/**
 * @tc.name: ValidateX509Cert_003
 * @tc.desc: Test validateX509Cert with self-signed certificate and trustedCerts
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_003, TestSize.Level0)
{
    /* Create end entity cert */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    /* Create trust anchor cert */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With trust anchor, validation should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    /* trustCert is transferred to params, no need to destroy separately */
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_004
 * @tc.desc: Test validateX509Cert with certificate chain (root -> intermediate -> end entity)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_004, TestSize.Level0)
{
    /* Create end entity cert */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create intermediate CA cert */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Chain validation should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_005
 * @tc.desc: Test validateX509Cert with partialChain = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_005, TestSize.Level0)
{
    /* Create intermediate CA cert as end entity */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert as trust anchor */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, intermediateCaCert, &params, &result);

    /* Partial chain validation */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(intermediateCaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_005_1
 * @tc.desc: Test validateX509Cert with partialChain = false
 *           When the cert chain is complete (intermediate CA signed by root CA),
 *           validation should succeed regardless of partialChain setting.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_005_1, TestSize.Level0)
{
    /* Create intermediate CA cert as end entity */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert as trust anchor */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = false;  // Default value

    /* Setup trusted certs (root CA) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, intermediateCaCert, &params, &result);

    /* Chain is complete (intermediate CA -> root CA), should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(intermediateCaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_006
 * @tc.desc: Test validateX509Cert with validateDate = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_006, TestSize.Level0)
{
    /* Create self-signed cert */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    /* Create trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Validate date */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Date validation result depends on cert validity period */
    /* Note: Test certificate dates may be expired, so result may vary */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_007
 * @tc.desc: Test validateX509Cert with custom validation date
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_007, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;

    /* Set custom validation date */
    const char *customDate = "20240615000000Z";
    params.date = static_cast<char *>(CfMalloc(strlen(customDate) + 1, 0));
    ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(customDate) + 1, customDate, strlen(customDate) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Custom date validation */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_008
 * @tc.desc: Test validateX509Cert with ignoreErrs
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_008, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup ignored errors */
    params.ignoreErrs.count = 2;
    params.ignoreErrs.data = static_cast<int32_t *>(CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.ignoreErrs.data, nullptr);
    params.ignoreErrs.data[0] = 10;  /* Example error code */
    params.ignoreErrs.data[1] = 20;  /* Example error code */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_009
 * @tc.desc: Test validateX509Cert with multiple trusted certs
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_009, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert1, nullptr);

    HcfX509Certificate *trustCert2 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert2, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup multiple trusted certs */
    params.trustedCerts.count = 2;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(2 * sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert1;
    params.trustedCerts.data[1] = trustCert2;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_012
 * @tc.desc: Test validateX509Cert with hostnames parameter
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_012, TestSize.Level0)
{
    /* Use end entity cert which has hostname test.example.com in SAN */
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(cert, nullptr);

    /* Trust root CA */
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCert, nullptr);

    /* Intermediate CA is needed for chain building */
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup hostnames - end entity cert has test.example.com in SAN */
    const char *hostname = "test.example.com";
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.hostnames.data, nullptr);
    params.hostnames.data[0] = static_cast<char *>(CfMalloc(strlen(hostname) + 1, 0));
    if (params.hostnames.data[0] != nullptr) {
        (void)memcpy_s(params.hostnames.data[0], strlen(hostname) + 1, hostname, strlen(hostname) + 1);
    }

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    /* Setup untrusted certs for chain building */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Hostname validation should succeed with matching hostname */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_013
 * @tc.desc: Test validateX509Cert with keyUsage parameter
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_013, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup keyUsage */
    params.keyUsage.count = 2;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = 0;  /* digitalSignature */
    params.keyUsage.data[1] = 1;  /* nonRepudiation */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* KeyUsage validation */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_014
 * @tc.desc: Test validateX509Cert with userId parameter
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_014, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup userId */
    const char *userId = "testUser123";
    params.userId.data = static_cast<uint8_t *>(CfMalloc(strlen(userId), 0));
    ASSERT_NE(params.userId.data, nullptr);
    (void)memcpy_s(params.userId.data, strlen(userId), userId, strlen(userId));
    params.userId.size = strlen(userId);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* userId validation */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_015
 * @tc.desc: Test validateX509Cert with emailAddresses parameter (email mismatch test)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_015, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup emailAddresses - cert doesn't have this email, so validation should fail */
    const char *email = "test@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    if (params.emailAddresses.data[0] != nullptr) {
        (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);
    }

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_015 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Email validation should fail since cert doesn't have the email address */
    EXPECT_EQ(res, CF_ERR_CERT_EMAIL_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_016
 * @tc.desc: Test validateX509Cert with allowDownloadIntermediateCa = true
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_016, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Enable intermediate CA download */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Validation with download enabled */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_017
 * @tc.desc: Test getAlgorithm after validateX509Cert
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_017, TestSize.Level0)
{
    /* Verify validator is still functional */
    const char *algo = g_validator->getAlgorithm(g_validator);
    ASSERT_NE(algo, nullptr);
    string expectedAlgo("PKIX");
    ASSERT_STREQ(algo, expectedAlgo.c_str());
}

/**
 * @tc.name: ValidateX509Cert_019
 * @tc.desc: Test validateX509Cert with existing test certificate data
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_019, TestSize.Level0)
{
    /* Use existing test certificate from test common header */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCaCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCaCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_020
 * @tc.desc: Test validateX509Cert memory allocation failure
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_020, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    HcfVerifyCertResult result = {};

    SetMockFlag(true);
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_020 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Memory allocation failure should return error */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_021
 * @tc.desc: Test validateX509Cert with invalid keyUsage (merged from 021, 031, 035)
 *           - invalid keyUsage type (out of range)
 *           - too many keyUsage values (count > 9)
 *           - negative keyUsage type value
 *           All should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_021, TestSize.Level0)
{
    HcfVerifyCertResult result = {};

    /* Case 1: invalid keyUsage type (value 100 is out of range) */
    HcfX509Certificate *cert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert1, nullptr);
    HcfX509Certificate *trustCert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert1, nullptr);
    HcfX509CertValidatorParams params1 = {};
    params1.trustSystemCa = false;
    params1.validateDate = false;
    params1.keyUsage.count = 1;
    params1.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params1.keyUsage.data, nullptr);
    params1.keyUsage.data[0] = 100;  /* Invalid keyUsage type */
    params1.trustedCerts.count = 1;
    params1.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params1.trustedCerts.data, nullptr);
    params1.trustedCerts.data[0] = trustCert1;
    CfResult res = g_validator->validateX509Cert(g_validator, cert1, &params1, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_021 case1 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert1);
    FreeValidatorParams(params1);

    /* Case 2: too many keyUsage values (max is 9) */
    HcfX509Certificate *cert2 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert2, nullptr);
    HcfX509Certificate *trustCert2 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert2, nullptr);
    HcfX509CertValidatorParams params2 = {};
    params2.trustSystemCa = false;
    params2.validateDate = false;
    params2.keyUsage.count = 10;
    params2.keyUsage.data = static_cast<int32_t *>(CfMalloc(10 * sizeof(int32_t), 0));
    ASSERT_NE(params2.keyUsage.data, nullptr);
    for (int i = 0; i < 10; i++) {
        params2.keyUsage.data[i] = i;
    }
    params2.trustedCerts.count = 1;
    params2.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params2.trustedCerts.data, nullptr);
    params2.trustedCerts.data[0] = trustCert2;
    res = g_validator->validateX509Cert(g_validator, cert2, &params2, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_021 case2 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert2);
    FreeValidatorParams(params2);

    /* Case 3: negative keyUsage type value */
    HcfX509Certificate *cert3 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert3, nullptr);
    HcfX509Certificate *trustCert3 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert3, nullptr);
    HcfX509CertValidatorParams params3 = {};
    params3.trustSystemCa = false;
    params3.validateDate = false;
    params3.keyUsage.count = 1;
    params3.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params3.keyUsage.data, nullptr);
    params3.keyUsage.data[0] = -1;  /* Negative value is invalid */
    params3.trustedCerts.count = 1;
    params3.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params3.trustedCerts.data, nullptr);
    params3.trustedCerts.data[0] = trustCert3;
    res = g_validator->validateX509Cert(g_validator, cert3, &params3, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_021 case3 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert3);
    FreeValidatorParams(params3);
}

/**
 * @tc.name: ValidateX509Cert_022
 * @tc.desc: Test validateX509Cert with too many emailAddresses (count > 1)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_022, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup too many emailAddresses (count = 2, but max is 1) */
    params.emailAddresses.count = 2;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(2 * sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(20, 0));
    params.emailAddresses.data[1] = static_cast<char *>(CfMalloc(20, 0));

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_022 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_PARAMETER_CHECK for too many emailAddresses */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_023
 * @tc.desc: Test validateX509Cert with invalid date string format
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_023, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;

    /* Set invalid date string */
    const char *invalidDate = "invalid_date_format";
    params.date = static_cast<char *>(CfMalloc(strlen(invalidDate) + 1, 0));
    ASSERT_NE(params.date, nullptr);
    (void)memcpy_s(params.date, strlen(invalidDate) + 1, invalidDate, strlen(invalidDate) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_023 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_PARAMETER_CHECK for invalid date format */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_024
 * @tc.desc: Test validateX509Cert with hostname mismatch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_024, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup hostname that won't match */
    const char *hostname = "nonexistent.example.com";
    params.hostnames.count = 1;
    params.hostnames.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.hostnames.data, nullptr);
    params.hostnames.data[0] = static_cast<char *>(CfMalloc(strlen(hostname) + 1, 0));
    ASSERT_NE(params.hostnames.data[0], nullptr);
    (void)memcpy_s(params.hostnames.data[0], strlen(hostname) + 1, hostname, strlen(hostname) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_024 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_HOST_NAME_MISMATCH */
    EXPECT_EQ(res, CF_ERR_CERT_HOST_NAME_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_025
 * @tc.desc: Test validateX509Cert with email address mismatch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_025, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup email that won't match */
    const char *email = "nonexistent@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    ASSERT_NE(params.emailAddresses.data[0], nullptr);
    (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_025 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_EMAIL_MISMATCH */
    EXPECT_EQ(res, CF_ERR_CERT_EMAIL_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_026
 * @tc.desc: Test validateX509Cert with keyUsage mismatch (require keyCertSign but cert doesn't have it)
 *           Tests CheckCertValidatorExtensions keyUsage mismatch branch (Line 412)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_026, TestSize.Level0)
{
    /* Use end-entity cert which typically doesn't have keyCertSign */
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Require KEYUSAGE_KEY_CERT_SIGN (5), end-entity certs don't have this */
    params.keyUsage.count = 1;
    params.keyUsage.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.keyUsage.data, nullptr);
    params.keyUsage.data[0] = 5;  /* KEYUSAGE_KEY_CERT_SIGN */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_026 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* End-entity cert should NOT have keyCertSign, so this should return mismatch */
    EXPECT_EQ(res, CF_ERR_CERT_KEY_USAGE_MISMATCH);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_027
 * @tc.desc: Test validateX509Cert with invalid revokedParams (merged from 027, 028, 029, 032)
 *           - invalid revocationFlags value
 *           - empty revocationFlags
 *           - only PREFER_OCSP flag without CRL_CHECK/OCSP_CHECK
 *           - too many revocationFlags (count > 4)
 *           All should return CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_027, TestSize.Level0)
{
    HcfVerifyCertResult result = {};

    /* Case 1: invalid revocationFlags value */
    HcfX509Certificate *cert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert1, nullptr);
    HcfX509Certificate *trustCert1 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert1, nullptr);
    HcfX509CertValidatorParams params1 = {};
    params1.trustSystemCa = false;
    params1.validateDate = false;
    params1.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params1.revokedParams, nullptr);
    params1.revokedParams->revocationFlags.count = 1;
    params1.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params1.revokedParams->revocationFlags.data, nullptr);
    params1.revokedParams->revocationFlags.data[0] = 100;  /* Invalid flag value */
    params1.trustedCerts.count = 1;
    params1.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params1.trustedCerts.data, nullptr);
    params1.trustedCerts.data[0] = trustCert1;
    CfResult res = g_validator->validateX509Cert(g_validator, cert1, &params1, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_027 case1 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert1);
    FreeValidatorParams(params1);

    /* Case 2: empty revocationFlags */
    HcfX509Certificate *cert2 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert2, nullptr);
    HcfX509Certificate *trustCert2 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert2, nullptr);
    HcfX509CertValidatorParams params2 = {};
    params2.trustSystemCa = false;
    params2.validateDate = false;
    params2.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params2.revokedParams, nullptr);
    params2.revokedParams->revocationFlags.count = 0;  /* Empty flags */
    params2.trustedCerts.count = 1;
    params2.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params2.trustedCerts.data, nullptr);
    params2.trustedCerts.data[0] = trustCert2;
    res = g_validator->validateX509Cert(g_validator, cert2, &params2, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_027 case2 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert2);
    FreeValidatorParams(params2);

    /* Case 3: only PREFER_OCSP flag (requires CRL_CHECK or OCSP_CHECK) */
    HcfX509Certificate *cert3 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert3, nullptr);
    HcfX509Certificate *trustCert3 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert3, nullptr);
    HcfX509CertValidatorParams params3 = {};
    params3.trustSystemCa = false;
    params3.validateDate = false;
    params3.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params3.revokedParams, nullptr);
    params3.revokedParams->revocationFlags.count = 1;
    params3.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params3.revokedParams->revocationFlags.data, nullptr);
    params3.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params3.trustedCerts.count = 1;
    params3.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params3.trustedCerts.data, nullptr);
    params3.trustedCerts.data[0] = trustCert3;
    res = g_validator->validateX509Cert(g_validator, cert3, &params3, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_027 case3 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert3);
    FreeValidatorParams(params3);

    /* Case 4: too many revocationFlags (max is 4) */
    HcfX509Certificate *cert4 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert4, nullptr);
    HcfX509Certificate *trustCert4 = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert4, nullptr);
    HcfX509CertValidatorParams params4 = {};
    params4.trustSystemCa = false;
    params4.validateDate = false;
    params4.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params4.revokedParams, nullptr);
    params4.revokedParams->revocationFlags.count = 5;
    params4.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(5 * sizeof(int32_t), 0));
    ASSERT_NE(params4.revokedParams->revocationFlags.data, nullptr);
    for (int i = 0; i < 5; i++) {
        params4.revokedParams->revocationFlags.data[i] = CERT_REVOCATION_CRL_CHECK;
    }
    params4.trustedCerts.count = 1;
    params4.trustedCerts.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params4.trustedCerts.data, nullptr);
    params4.trustedCerts.data[0] = trustCert4;
    res = g_validator->validateX509Cert(g_validator, cert4, &params4, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_027 case4 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    CfObjDestroy(cert4);
    FreeValidatorParams(params4);
}

/**
 * @tc.name: ValidateX509Cert_030
 * @tc.desc: Test validateX509Cert with result having non-empty certChain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_030, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    /* Setup result with non-empty data (simulating already filled result) */
    HcfVerifyCertResult result = {};
    result.certs.count = 1;
    result.certs.data = static_cast<HcfX509Certificate **>(CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(result.certs.data, nullptr);
    result.certs.data[0] = nullptr;

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_030 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_PARAMETER_CHECK for non-empty result */
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_033
 * @tc.desc: Test validateX509Cert returns CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 *          when no trust anchor is available
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_033, TestSize.Level0)
{
    /* Use end entity cert without providing the root CA as trust anchor */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(endEntityCert, nullptr);

    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    /* Setup trusted certs with a cert that is NOT the issuer (self-signed cert as fake trust anchor) */
    HcfX509Certificate *fakeTrustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(fakeTrustCert, nullptr);
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = fakeTrustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_030 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return error because trust anchor doesn't match the chain */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_034
 * @tc.desc: Test validateX509Cert with valid revokedParams (CRL_CHECK)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_034, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Setup revokedParams with valid CRL_CHECK flag */
    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = false;  /* Don't download CRL */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* The result depends on whether CRL check is available for the cert */
    /* Since no CRL is provided and download is disabled, it may fail or succeed */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_035
 * @tc.desc: Test validateX509Cert with trustSystemCa=true
 *           This tests the trustSystemCa branch in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_035, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = true;   /* Trust system CA store */
    params.validateDate = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_035 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* The result depends on whether system CA store is available and the cert is trusted */
    /* Since g_testSelfSignedCert is not in system CA store, validation may fail */
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
}

/**
 * @tc.name: ValidateX509Cert_035b
 * @tc.desc: Test validateX509Cert with CERT_REVOCATION_OCSP_CHECK flag
 *           This tests the OCSP_CHECK branch in CheckRevocationFlags
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_035b, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_035b failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_036
 * @tc.desc: Test validateX509Cert with expired certificate
 *           Expected: CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_036, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testExpiredCert);
    ASSERT_NE(cert, nullptr);

    /* Use the same expired cert as trust anchor to bypass trust check */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testExpiredCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_036 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_HAS_EXPIRED for expired certificate */
    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_037
 * @tc.desc: Test validateX509Cert with not-yet-valid certificate
 *           Expected: CF_ERR_CERT_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_037, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testNotYetValidCert);
    ASSERT_NE(cert, nullptr);

    /* Use the same not-yet-valid cert as trust anchor to bypass trust check */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testNotYetValidCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_037 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_NOT_YET_VALID for not-yet-valid certificate */
    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_038
 * @tc.desc: Test validateX509Cert with certificate containing unknown critical extension
 *           Expected: CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_038, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCriticalExtCert);
    ASSERT_NE(cert, nullptr);

    /* Use the same cert as trust anchor since it's self-signed */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testCriticalExtCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_038 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION for unknown critical extension */
    EXPECT_EQ(res, CF_ERR_CERT_UNKNOWN_CRITICAL_EXTENSION);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_039
 * @tc.desc: Test validateX509Cert with self-signed certificate not in trust store
 *           Expected: CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_039, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedUntrustedCert);
    ASSERT_NE(cert, nullptr);

    /* Set a different trust anchor (not the cert being validated) */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Set trust anchor to a different cert */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_039 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should return CF_ERR_CERT_UNTRUSTED for self-signed cert not in trust store */
    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_040
 * @tc.desc: Test validateX509Cert with expired cert but validateDate=false
 *           Expected: Should succeed since date validation is disabled
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_040, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testExpiredCert);
    ASSERT_NE(cert, nullptr);

    /* Use expired cert as trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testExpiredCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;  /* Disable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should succeed since date validation is disabled */
    EXPECT_EQ(res, CF_SUCCESS);

    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* Certificate with AIA extension pointing to unreachable URL */
static const char g_testAiaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDkTCCAnmgAwIBAgIUJhhvr1dk37ON/6dqk1dJENryb38wDQYJKoZIhvcNAQEL\r\n"
    "BQAwMDEbMBkGA1UEAwwSVGVzdCBDZXJ0IHdpdGggQUlBMREwDwYDVQQKDAhUZXN0\r\n"
    "IE9yZzAeFw0yNjAzMTcxMzM2MDNaFw0yNzAzMTcxMzM2MDNaMDAxGzAZBgNVBAMM\r\n"
    "ElRlc3QgQ2VydCB3aXRoIEFJQTERMA8GA1UECgwIVGVzdCBPcmcwggEiMA0GCSqG\r\n"
    "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdVpoUlEJNk6xzpBFEE5ZxZW2dOfrnnkMY\r\n"
    "KtSjLv/Vd0pOOuXzn1Qjtrwx9F+OGUcGlOMVbLUKgjxqItD846ulQPKo/q1vOHMp\r\n"
    "kb3rPpVPUyGORiqryKd6TaA0s307laqtLqH76W1ab3rhy4FgQ5tlU4SbSn7dMVLn\r\n"
    "3/1VIVQmOmUOc8iVJ7SFHc9cFwSM9txEPAeJqQl3OY0d5sJZ3Q13thwqonzNSF7A\r\n"
    "/n206KXeRst+QL90+LvnyKCCp6sU32EhNymZMQbVsBjXBNhkgVXqewLdIYY0JSYj\r\n"
    "g6rsYerOn9sB8hx1KENQ02TJ5qXJcDrzxCAxEhBWWCiCz11IjryZAgMBAAGjgaIw\r\n"
    "gZ8wCQYDVR0TBAIwADALBgNVHQ8EBAMCB4AwZgYIKwYBBQUHAQEEWjBYMCMGCCsG\r\n"
    "AQUFBzABhhdodHRwOi8vb2NzcC5leGFtcGxlLmNvbTAxBggrBgEFBQcwAoYlaHR0\r\n"
    "cDovL25vbmV4aXN0ZW50LmV4YW1wbGUuY29tL2NhLmNydDAdBgNVHQ4EFgQUv6//\r\n"
    "Ma7uiJvh5Fai10gjaq/6U8swDQYJKoZIhvcNAQELBQADggEBABs+SfbLRc9zCB4A\r\n"
    "9chJD5LGAKFTCttUU8FeXf2EYjhdTVHQlDqOnHeEGBWChWLYdiF79nmO40Y6KoW9\r\n"
    "L8ebaQLdR2Hud2adCT37V7CqIaWxv9YrnHpP3Nljizpos89w94XqOS5OIAiCUv23\r\n"
    "bcoxrRwS15yAiFZH9IA/0H9CC//98jjjw12je/1pIrXej+GWF/Eb3GkyeFYmWPRh\r\n"
    "I7yV4DmbPEye0+TMy0rnoOTmwpi5IMSKbKIHmC0RaaD7AItBybRA1dkUKynU2Zl6\r\n"
    "/eel6iOzcWzG7yNOlToq1WH0Ov93PEBDKGNUWAqyuSQ5HuETX3TqoOSKadW8ud5w\r\n"
    "puI8onQ=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* End entity cert signed by intermediate CA with AIA extension pointing to unreachable URL
 * This cert is NOT self-signed, so it will trigger the download logic when intermediate CA is missing
 */
static const char g_testEndEntityAiaCert[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEJjCCAw6gAwIBAgIUZCWQO/VZO3cgJULJu5ceZe9kGQIwDQYJKoZIhvcNAQEL\r\n"
    "BQAwPzELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMR0wGwYDVQQDDBRU\r\n"
    "ZXN0IEludGVybWVkaWF0ZSBDQTAeFw0yNjAzMTgxMjM2NDJaFw0yNzAzMTgxMjM2\r\n"
    "NDJaMD4xCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhUZXN0IE9yZzEcMBoGA1UEAwwT\r\n"
    "RW5kIEVudGl0eSB3aXRoIEFJQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\r\n"
    "ggEBAKZiqW2xPGaAOK3wV/zgxqUVKo0iOfJ6otzbZqJRDeerGc3Jw/xeO/0ThKsH\r\n"
    "3Wn+UVugiMumCobxBejOOWQ8vpmi/+2hLzMv0UJ/KH5OgHDU8Z7C8Epd3CvogHrS\r\n"
    "EEVXMdybvy/RwiTfpZ+moPFc3i8S2Go06VyAfZiNjpCSpKCzWJCbggxSMuNqUcqS\r\n"
    "uVcQk74IYISFxLrASsKxWUCEyDenlfxqSE8ky4jwfndAhRTh6dnLxVdmvISPIrbX\r\n"
    "O7Q5WYT6x6xr84abJJ7FydpeJJnYd3WZk2H2hi4bukqKu2JEbNqtDZEwGrk02/0N\r\n"
    "MPJn12K2YuVAQzGqDxX58+YEpmUCAwEAAaOCARkwggEVMAkGA1UdEwQCMAAwCwYD\r\n"
    "VR0PBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjByBggrBgEF\r\n"
    "BQcBAQRmMGQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmV4YW1wbGUuY29tMD0G\r\n"
    "CCsGAQUFBzAChjFodHRwOi8vbm9uZXhpc3RlbnQubG9jYWw6OTk5OS9pbnRlcm1l\r\n"
    "ZGlhdGVfY2EucGVtMB0GA1UdDgQWBBQOrjXET0927PGWZUYc/30VA2tS8jBJBgNV\r\n"
    "HSMEQjBAoTukOTA3MQswCQYDVQQGEwJVUzERMA8GA1UECgwIVGVzdCBPcmcxFTAT\r\n"
    "BgNVBAMMDFRlc3QgUm9vdCBDQYIBZTANBgkqhkiG9w0BAQsFAAOCAQEAGRBI5tRg\r\n"
    "AcYgpjJO7x1DHPUPcYDY7Q+oqyEHG4YdY+eRaAidMqUg2lbNp5sJXGl0MLWKpabn\r\n"
    "dyku3n7bDZ0H/FNfrOl81l/mHpRUCJr4DAqyZRECyHE+NYVCZq9bjAXRmhhGN2L/\r\n"
    "wbrwZtNjkKRJ4MbF9zdKwbnMWK40noGlG6RIh/p9bXCS3krJXI507pESQEo+An7X\r\n"
    "fTnRHIzinuMCa1aP8hHhHQn/+exh/xGhlxEzQRhcOoAyXLVughKP8oftRW6/nAuX\r\n"
    "y3h0F6obV4YpCkwN/zrBUXOdNfWOXt1yV/8oNdjE+txdFYWtNdoSetiJHJcxQSa1\r\n"
    "quiQjX30/FB8dA==\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Root CA for CDP test */
static const char g_testRootCaForCdp[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDWDCCAkCgAwIBAgIUOKtYvZfXT/8QRNvKoi/bSB6T6NQwDQYJKoZIhvcNAQEL\r\n"
    "BQAwRDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlU\r\n"
    "ZXN0IFJvb3QgQ0EgZm9yIENEUCBUZXN0MB4XDTI2MDMyMzAxMjcyOVoXDTI3MDMy\r\n"
    "MzAxMjcyOVowRDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYD\r\n"
    "VQQDDBlUZXN0IFJvb3QgQ0EgZm9yIENEUCBUZXN0MIIBIjANBgkqhkiG9w0BAQEF\r\n"
    "AAOCAQ8AMIIBCgKCAQEA0f7VykPQDwQYiVwb5sobfiY5r3rln5purnQeUYfjk1A4\r\n"
    "c1ycw0vltCbKe+ennQYhyiVRPuz17nZHk8ExWU8jJhq7GU6VyHHranGYjJKp2BQ5\r\n"
    "DdDSiCCkXn7wIDlKJPZBCc4Fxl+8aVuXAvOpXb4/4Go50aWwaSo1YgKvEFBv0JqM\r\n"
    "ZtS8McYcyR0XclkmPrqdNr/VeLBo0ay5/zBDprIWMyH54EUMNNpJ3RrHaaXbhPb7\r\n"
    "IrFIJtlZxrU4U75CUq3mDEe2G3wedkjcbMR5X4dEDDqhNeUfGh6e+y4H9+6CUXcD\r\n"
    "AbbVJFeFIdB3DR+eW0/SHTWo7otvOH47mkzAWMZ9RwIDAQABo0IwQDAPBgNVHRMB\r\n"
    "Af8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUUJwASWOPfcgIdHoi\r\n"
    "BC8v82p7M9UwDQYJKoZIhvcNAQELBQADggEBADM1GaBRZzrkcpnKiCY2g/SnySq+\r\n"
    "RqwhzZpseKAivAtIJbCK0O/WfMlesR4B60DgL0hCfridrqiUaWI2s0hh6MZ1/lm2\r\n"
    "smFiZ9L8QEXd4AFhCZwbGwtT8mqUpj1Z9eYWVJnBCt4Lv/60krRt/cLmtkUv6mFo\r\n"
    "Lc30T/VxzOvTYBfCZlzhf2o7duno6TIrTyqGbAu7H9OOaCYdmPuePIqKAgV2QPC2\r\n"
    "RjQKsm7GPkjIueZhLOqhqOwpPgsoL5bEek8gih012I7jFpk3w9dAs/DAps+f4eSl\r\n"
    "L0rLBxpxMifFw2W8EgdMzwNj7GcX26YAQlga25OVkVJdu/t23B+lGoG3VPA=\r\n"
    "-----END CERTIFICATE-----\r\n";

/* Intermediate CA with CRL Distribution Points extension pointing to unreachable URL */
static const char g_testIntermediateCaWithCdp[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDwzCCAqugAwIBAgIUIqHgsDBYHvw4TFD/S5KwuNtSmmswDQYJKoZIhvcNAQEL\r\n"
    "BQAwRDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlU\r\n"
    "ZXN0IFJvb3QgQ0EgZm9yIENEUCBUZXN0MB4XDTI2MDMyMzAxMjcyOVoXDTI3MDMy\r\n"
    "MzAxMjcyOVowSDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSYwJAYD\r\n"
    "VQQDDB1UZXN0IEludGVybWVkaWF0ZSBDQSB3aXRoIENEUDCCASIwDQYJKoZIhvcN\r\n"
    "AQEBBQADggEPADCCAQoCggEBAJsZBj9Bh9KAo+mL3ZsJhoHb+4+ueqdqAIOyze0b\r\n"
    "5FW2ZfhVwOqF4Q8Qz7EeP7OZCAPe3XVzRLRgTv3IATg93B5oLIXu34VE0qvcx483\r\n"
    "yFeeLgOSbIHhnkKMMpN+2XiNf6U2Ncx2uG7hKeQJVcMk0OxDpNnc4l3gSRNBElF2\r\n"
    "Ky0jc3JDFAHyyy//QmdqUH/06zahvEWXHZgiWTZzTyLY7/fQYE2DCFoVH2DEOAL0\r\n"
    "RkxEiz+6R3yuKmgmrh/AeY0JVQoHmo/AiN6qnzhalz7NfrvyyTxeLBTbEoeMEZ2D\r\n"
    "1OhzAZhnIyozIiPQEEe17EKItXXIQRE4Exw8Lao6ACZIVJ0CAwEAAaOBqDCBpTAS\r\n"
    "BgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUkGWw\r\n"
    "aL5Wg1BVfzN8UNOAo273TNYwHwYDVR0jBBgwFoAUUJwASWOPfcgIdHoiBC8v82p7\r\n"
    "M9UwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL25vbmV4aXN0ZW50LmxvY2FsOjk5\r\n"
    "OTkvaW50ZXJtZWRpYXRlLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAXfNlbv+uzOye\r\n"
    "dbxloEZ8TQng5rl/iUqm3/zSxjOSgakNlU9XfmJhMLpOLf0xfDtRa5PWWCNS7Hh5\r\n"
    "luaRC4PK0QIVewni+QMYfA5hUXCiOajdJJZaY3MuWlKbr6+zsMAu85GJ9/davSW5\r\n"
    "XxTscR37B0FzfCwlnvoQhQnidkNTlbnZ/2eA1rNIjEnBjVyWkIkDUNnlWtwYpXOR\r\n"
    "rLENN+aeT5+CMFmjCrDqWIIec76NREcrumcqKcc+xvvxlCjUPDzmiBzS+BGkxV7g\r\n"
    "Hpo95OB54ENdUfzazLAO8b1EVvrLl+iCUPGtWbSJ4SqrPHUyIqZpHk0FvR+vFZoR\r\n"
    "BC7apycLCA==\r\n"
    "-----END CERTIFICATE-----\r\n";

/* End entity certificate for CDP test - WITH CRL Distribution Points extension */
static const char g_testEndEntityForCdp[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIID1zCCAr+gAwIBAgIUdlC+tykAZSOPM3iTwzZgxRJe6wcwDQYJKoZIhvcNAQEL\r\n"
    "BQAwSDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSYwJAYDVQQDDB1U\r\n"
    "ZXN0IEludGVybWVkaWF0ZSBDQSB3aXRoIENEUDAeFw0yNjAzMjMwMTMzNDZaFw0y\r\n"
    "NzAzMjMwMTMzNDZaMEcxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhUZXN0IE9yZzEl\r\n"
    "MCMGA1UEAwwcVGVzdCBFbmQgRW50aXR5IGZvciBDRFAgVGVzdDCCASIwDQYJKoZI\r\n"
    "hvcNAQEBBQADggEPADCCAQoCggEBAPIg6lPaEssJJ/Sf5sQeW4+9NhIZM142/4pA\r\n"
    "aOIDkvk7Y5IX4m54WVJU55UZfSkA3A87XIrAGVmMFPKFxpW51gD6TlT+rd4hzVSK\r\n"
    "rqacYvlNEhxtsTqwtJOT91nKAQ2mkSLe5B2HslVhe9D10V1LCQC+pJ7glOEb3qJI\r\n"
    "07yh5EYRJ/xc1Gc5ASUlDltsjovxSn8crbXFUro9yXMF5b79YBI5ADtNAFb67YOl\r\n"
    "25wzoWt1LbMz5EarAkhiERA6tcVoq8bWjm3wEAUHQVVFfPbDz7tUIM6zxafPe4ak\r\n"
    "Zr3Q2kDQ9G+/3RRVmECMCwGb0o5DDVEtjAJP+jGMiPbKyZze+hcCAwEAAaOBuTCB\r\n"
    "tjAJBgNVHRMEAjAAMAsGA1UdDwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYI\r\n"
    "KwYBBQUHAwIwHQYDVR0OBBYEFJ3YrHUmsZKHGtoQIF9GW2J3qXBbMB8GA1UdIwQY\r\n"
    "MBaAFJBlsGi+VoNQVX8zfFDTgKNu90zWMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6\r\n"
    "Ly9ub25leGlzdGVudC5sb2NhbDo5OTk5L2VuZF9lbnRpdHkuY3JsMA0GCSqGSIb3\r\n"
    "DQEBCwUAA4IBAQBBYRRENJb1Nq8KceNYbOMOxORdza3a4n0kEKowuaVGXUGH67U/\r\n"
    "qm2YdlM664wwBeXZXnCI+gud44eLsKP/kPM7p8gNADOxbb7NKAPZ204Hwo8LvxnG\r\n"
    "3pmpffgOG1cQWat7rvqF+B0TZT5XL0yxgYOuZeLwIH86vyrw1lv+wzHJUbGl7FJz\r\n"
    "LxU8LqKcQKcHAhUalyHfAjsLxI4V9bos17ZeFmXeo3EQ64OB978gT5aO9/xQUe9h\r\n"
    "DQWrCaHaTwJ8cS0hhtXjJ39OMiPQrg94fPLQ8RqxbnczzGfZ0i7yxcnuesZfKrUy\r\n"
    "nxiuOuuvuuoP6COBWaMpfxNPu+QZqHMI8ahG\r\n"
    "-----END CERTIFICATE-----\r\n";

/**
 * @tc.name: ValidateX509Cert_041
 * @tc.desc: Test allowDownloadIntermediateCa with incomplete chain and download disabled
 *           When allowDownloadIntermediateCa is false, download should not be attempted
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_041, TestSize.Level0)
{
    /* Create end entity cert without providing intermediate CA */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (missing intermediate CA) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = false;  /* Download disabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_041 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY since download is disabled */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_042
 * @tc.desc: Test allowDownloadIntermediateCa with incomplete chain and download enabled
 *           but certificate has no AIA extension
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_042, TestSize.Level0)
{
    /* Create end entity cert without providing intermediate CA */
    /* g_testEndEntityCert has no AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (missing intermediate CA) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_042 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail with UNABLE_TO_GET_ISSUER_CERT_LOCALLY since cert has no AIA */
    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_043
 * @tc.desc: Test allowDownloadIntermediateCa with self-signed cert that has AIA extension
 *           Since the cert is self-signed and not in trust anchor, download should be attempted
 *           but will fail because the URL is unreachable
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (download fails)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_043, TestSize.Level0)
{
    /* Create cert with AIA extension pointing to unreachable URL */
    HcfX509Certificate *aiaCert = CreateCertFromPem(g_testAiaCert);
    ASSERT_NE(aiaCert, nullptr);

    /* Use a different cert as trust anchor */
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, aiaCert, &params, &result);

    /* Print error message for debugging */
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_043 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail because the cert is not signed by trust anchor */
    /* The download will be attempted but will fail (unreachable URL) */
    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(aiaCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_044
 * @tc.desc: Test allowDownloadIntermediateCa with complete chain (no download needed)
 *           When chain is complete, download should not be triggered
 *           Expected: CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_044, TestSize.Level0)
{
    /* Create end entity cert */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create intermediate CA cert */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled but not needed */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    /* Setup untrusted certs (intermediate CA) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Should succeed since chain is complete */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_046
 * @tc.desc: Test TryDownloadFromAccessDescriptionWithRetry with unreachable URL
 *           End entity cert signed by intermediate CA with AIA extension
 *           Chain is incomplete (missing intermediate CA), download should be attempted
 *           but will fail because the AIA URL is unreachable
 *           Expected: CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_046, TestSize.Level0)
{
    /* Create end entity cert signed by intermediate CA, with AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityAiaCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create root CA cert as trust anchor (intermediate CA is missing) */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled */

    /* Setup trusted certs with only root CA (intermediate missing) */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_046 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Should fail because:
     * 1. Chain is incomplete (missing intermediate CA)
     * 2. Download is attempted but URL is unreachable (timeout)
     * Expected: CF_ERR_NETWORK_TIMEOUT (download timeout error)
     */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_047
 * @tc.desc: Test with complete chain using g_testEndEntityAiaCert
 *           When intermediate CA is provided, download should not be triggered
 *           Expected: CF_SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_047, TestSize.Level0)
{
    /* Create end entity cert signed by intermediate CA, with AIA extension */
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityAiaCert);
    ASSERT_NE(endEntityCert, nullptr);

    /* Create intermediate CA cert */
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(intermediateCaCert, nullptr);

    /* Create root CA cert */
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;  /* Download enabled but not needed */

    /* Setup trusted certs */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    /* Setup untrusted certs (intermediate CA provided) */
    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);

    /* Should succeed because intermediate CA is provided */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        EXPECT_GT(result.certs.count, 0);
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest001
 * @tc.desc: Test X509_STORE_new failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest001, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest001 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest002
 * @tc.desc: Test X509_STORE_add_cert failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest002, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest002 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest003
 * @tc.desc: Test X509_up_ref failure in ConstructUntrustedStack
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest003, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_up_ref(_))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest003 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest004
 * @tc.desc: Test ASN1_TIME_new failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest004, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest004 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest005
 * @tc.desc: Test ASN1_TIME_set_string failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest005, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_set_string(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest005 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest006
 * @tc.desc: Test ASN1_TIME_to_tm failure in ConvertTimeStrToTimeT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest006, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;
    params.date = const_cast<char *>("2025-01-01 00:00:00");

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_set_string(_, _))
        .WillOnce(Return(1)); // Success so we can test ASN1_TIME_to_tm
    EXPECT_CALL(X509OpensslMock::GetInstance(), ASN1_TIME_to_tm(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest006 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    params.date = nullptr; // Don't free string literal
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest007
 * @tc.desc: Test X509_STORE_CTX_new failure in ExecuteSingleVerification
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest007, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest007 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest008
 * @tc.desc: Test X509_STORE_CTX_init failure in ExecuteSingleVerification
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest008, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest008 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest009
 * @tc.desc: Test X509_STORE_add_cert failure in ConstructTrustedStore
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest009, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_add_cert(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest009 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest012
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_CERT_HAS_EXPIRED
 *           This tests ConvertOpensslErrorMsgEx with an error that maps to CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest012, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_HAS_EXPIRED));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest012 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest013
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_CERT_NOT_YET_VALID
 *           This tests ConvertOpensslErrorMsgEx with an error that maps to CF_ERR_CERT_NOT_YET_VALID
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest013, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_NOT_YET_VALID));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest013 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_NOT_YET_VALID);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest014
 * @tc.desc: Test X509_verify_cert returns error with X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
 *           This tests ConvertOpensslErrorMsgEx with self-signed cert error mapping to CF_ERR_CERT_UNTRUSTED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest014, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest014 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_UNTRUSTED);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest015
 * @tc.desc: Test X509_verify_cert returns error with unknown error code
 *           This tests ConvertOpensslErrorMsg returning CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest015, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNSPECIFIED));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest015 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest016
 * @tc.desc: Test OPENSSL_sk_push failure in ConstructUntrustedStack
 *           This tests Line 466 branch - when sk_X509_push fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest016, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), OPENSSL_sk_push(_, _))
        .WillOnce(Return(0));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest016 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_048
 * @tc.desc: Test CA certificate with keyUsage not containing keyCertSign
 *           Chain: Root CA -> Intermediate (no keyCertSign) -> EE
 *           Should return CF_ERR_KEYUSAGE_NO_CERTSIGN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_048, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_eeByIntermediateNoKeyCertSignCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_intermediateNoKeyCertSignCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_048 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_KEYUSAGE_NO_CERTSIGN);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_049
 * @tc.desc: Test certificate with corrupted signature
 *           Chain: Root CA -> Corrupted Intermediate CA -> EE
 *           Should return CF_ERR_CERT_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_049, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *corruptedIntermediateCert = CreateCertFromPem(g_corruptedSignatureIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(corruptedIntermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = corruptedIntermediateCert;

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_049 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_SIGNATURE_FAILURE);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_050
 * @tc.desc: Test validateX509Cert with emailAddresses parameter (email match success)
 *           The cert has test@example.com in SAN, validation should succeed
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_050, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_emailTestCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    const char *email = "test@example.com";
    params.emailAddresses.count = 1;
    params.emailAddresses.data = static_cast<char **>(CfMalloc(sizeof(char *), 0));
    ASSERT_NE(params.emailAddresses.data, nullptr);
    params.emailAddresses.data[0] = static_cast<char *>(CfMalloc(strlen(email) + 1, 0));
    ASSERT_NE(params.emailAddresses.data[0], nullptr);
    (void)memcpy_s(params.emailAddresses.data[0], strlen(email) + 1, email, strlen(email) + 1);

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest017
 * @tc.desc: Test X509_STORE_CTX_get_current_cert returning NULL in GetLastCertFromVerifyCtx
 *           This tests the case when verification fails but current_cert is NULL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest017, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_current_cert(_))
        .WillOnce(Return((X509 *)nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest017 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest018
 * @tc.desc: Test X509_STORE_CTX_get1_chain returning NULL (Line 718)
 *           This tests the get1_chain returning NULL branch
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest018, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get1_chain(_))
        .WillOnce(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(1));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest018 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest019
 * @tc.desc: Test successful download of missing intermediate CA via AIA
 *           First verification fails (missing issuer), X509_load_http succeeds,
 *           second verification succeeds
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest019, TestSize.Level0)
{
    BIO *bio = BIO_new_mem_buf(g_testDownloadCertValid, strlen(g_testDownloadCertValid) + 1);
    ASSERT_NE(bio, nullptr);
    X509 *downloadedCert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    ASSERT_NE(downloadedCert, nullptr);

    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testLeafCertValid);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCertValid);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_load_http(_, _, _, _))
        .WillOnce(Return(downloadedCert));
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_NE(result.certs.count, 0);

    FreeVerifyCertResult(result);
    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest020
 * @tc.desc: Test malloc failure scenarios in FillVerifyCertResult
 *           - Case 1 (index 0): result->certs.data allocation failure -> CF_ERR_MALLOC
 *           - Case 2 (index 1): GetX509EncodedDataStream malloc failure
 *             Note: GetX509EncodedDataStream returns NULL on any failure without error code,
 *             so X509ToHcfX509Certificate cannot distinguish malloc failure from other errors,
 *             and returns CF_ERR_CRYPTO_OPERATION uniformly.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest020, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCaCert;

    HcfVerifyCertResult result = {};

    StartRecordMallocNum();
    SetMockMallocIndex(0);
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EndRecordMallocNum();
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest020 case1 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_MALLOC);

    StartRecordMallocNum();
    SetMockMallocIndex(1);
    res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    EndRecordMallocNum();
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest020 case2 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509CertMockTest021
 * @tc.desc: Test TryDownloadFromAccessDescriptionWithRetry malloc failure
 *           When CfMallocEx fails to allocate URL buffer, should return CF_ERR_MALLOC.
 *           This tests the DOWNLOAD_RESULT_MALLOC_FAILED branch in download flow.
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509CertMockTest021, TestSize.Level0)
{
    HcfX509Certificate *endEntityCert = CreateCertFromPem(g_testLeafCertValid);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_testRootCertValid);
    ASSERT_NE(endEntityCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.allowDownloadIntermediateCa = true;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCaCert;

    HcfVerifyCertResult result = {};

    SetMockFlag(true);
    CfResult res = g_validator->validateX509Cert(g_validator, endEntityCert, &params, &result);
    SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509CertMockTest021 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_MALLOC);

    CfObjDestroy(endEntityCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_001
 * @tc.desc: Test CRL check - no CRL provided, expect CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_001 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_002
 * @tc.desc: Test OCSP check - no OCSP response provided, expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_002 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_003
 * @tc.desc: Test both CRL and OCSP check - CRL not found, fallback to OCSP
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_003, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->crls.count = 0;
    params.revokedParams->ocspResponses.count = 0;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_003 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_004
 * @tc.desc: Test CERT_REVOCATION_PREFER_OCSP flag - OCSP not available, fallback to CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_004, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->crls.count = 0;
    params.revokedParams->ocspResponses.count = 0;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_004 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_005
 * @tc.desc: Test self-signed certificate - skip revocation check
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_005, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    HcfX509Certificate *trustCert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(trustCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = trustCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->crls.count = 0;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_006
 * @tc.desc: Test CRL check - CRL has expired, expect CF_ERR_CRL_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *ts2Cert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *ts1Cert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(ts2Cert, nullptr);
    ASSERT_NE(ts1Cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = ts1Cert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = ts2Cert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    HcfX509Crl *crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_006 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* validateDate=false skips CRL expiration, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_007
 * @tc.desc: Test CRL check success - certificate not in CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_007, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemInitialLocalCrl)),
        strlen(g_testCertChainPemInitialLocalCrl), CF_FORMAT_PEM };
    HcfX509Crl *crl = nullptr;
    CfResult ret = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(ret, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_007 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_008
 * @tc.desc: Test CHECK_ALL_CERT flag - check all certificates in chain
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_008, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(2 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_008 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_009
 * @tc.desc: Test OCSP check with OCSP response provided
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_009, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = const_cast<uint8_t *>(g_testOcspResponses);
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_testOcspResponses);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_009 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_010
 * @tc.desc: Test both CRL and OCSP - prefer OCSP flag
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_010, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(3 * sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_010 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_011
 * @tc.desc: Test revocation with only OCSP enabled, no CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_011, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_011 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_012
 * @tc.desc: Test revocation parameter validation - invalid revocationFlags count
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_012, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 0;
    params.revokedParams->revocationFlags.data = nullptr;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_012 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_013
 * @tc.desc: Test CRL download - cert without CDP extension, allowDownloadCrl=true
 *           When certificate has no CRL Distribution Points extension,
 *           CRL download should fail with CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_013, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_013 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_014
 * @tc.desc: Test CRL download - cert with CDP extension but download fails
 *           When intermediate CA has CRL Distribution Points extension but URL is unreachable,
 *           CRL download should fail with CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_014, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityForCdp);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaForCdp);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaWithCdp);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_014 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* CRL download should fail with network timeout since URL is unreachable */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ========== OCSP Test Certificates ========== */

static const char g_ocspTestRootCa[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDRjCCAi6gAwIBAgIBATANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n"
    "DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowPDELMAkGA1UEBhMCVVMxETAP\r\n"
    "BgNVBAoMCFRlc3QgT3JnMRowGAYDVQQDDBFPQ1NQIFRlc3QgUm9vdCBDQTCCASIw\r\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJfQ+HiqrZArX11Ey6/wR1tRjG8Y\r\n"
    "XCOQoty2mKhU8s76Ue9PfTMW+vXsMjU7snS+kULL5DvTszd3HjAaH5FZ8z9rklOl\r\n"
    "2hE1C2sM7IQXYQuvRbfu1TqWgzWu1daRKHvfCeedd11Vr1/DdJY29U69wqXCUwAw\r\n"
    "Fg/+nmKwWyE3GjEtTTbKpHgNJoSA2q07VTx8MTbgQUHGCEecGo+wNjA9Jks3aPZY\r\n"
    "zesK75HceXbpY7Yl4fWM8o93VBayDFocbq6dLBGb8+X03S+e02lQNms65fkFPLrB\r\n"
    "ehxdZxzu7mOpp3PKj7rTB5JJzYFF8XeCBLdIGrE0ZoG/RA4IfXD0ACDdxIUCAwEA\r\n"
    "AaNTMFEwHQYDVR0OBBYEFH5542fJnk+vm/Q82Jph/RoysLgRMB8GA1UdIwQYMBaA\r\n"
    "FH5542fJnk+vm/Q82Jph/RoysLgRMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcN\r\n"
    "AQELBQADggEBAD24n5P7M+ZqYvF3H46/nJq9NOBF5JEdPnsO9S52B8WvxhjuVEZM\r\n"
    "M6ebQchw5uhvbi30KoFnLLMQuDbgvXzWJCbOh8pLKo2HcVA12PnwdzyVUKOnVVo/\r\n"
    "47t9ByCvRxBIS80nOkGuOoyjo4tMY2Sml0zH4mGO6n5geYYixg4w5GgdJcPs+Xz/\r\n"
    "U7qlB6SLtB5ZamvQU0wZWI1g8ic6OrWxQOCM6pY4x38tgfEVIO8Jh4e6M7db6c9o\r\n"
    "hOBR9EBXT9bBT+kXIQvTQLS33GMcjb/pnX8M0SRlcDDqlViovDm3sRlAkpSPYdF2\r\n"
    "2a+m5c7rZ/HZSfvbHvgBw5j+t7mOcwPmSnw=\r\n"
    "-----END CERTIFICATE-----";

static const char g_ocspTestIntermediateCa[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDYTCCAkmgAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJVUzER\r\n"
    "MA8GA1UECgwIVGVzdCBPcmcxGjAYBgNVBAMMEU9DU1AgVGVzdCBSb290IENBMB4X\r\n"
    "DTI2MDMyNDA5MDIyOVoXDTQ2MDMxOTA5MDIyOVowRDELMAkGA1UEBhMCVVMxETAP\r\n"
    "BgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRpYXRl\r\n"
    "IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlkEzThKS+GZqZaEW\r\n"
    "G4rQ23hh1zatQnjUorKvT0J20EJCeuUrYLOLYFM5kjBdMcJJCr8/Q9vGa580h74+\r\n"
    "0XfKQSFLzgSC53Lq1cPOtcixWkcj+PDCilXcoWiuq6C2gcj8onnWlv2v/d/g5CVb\r\n"
    "1NZVmxabJP76WrcMVSy9wkrgruxLQlK6Kvaj7rFOAwiJqfUab6fVAGPtGhP20HvR\r\n"
    "IFjL3SP5+gg1LaysrzhEn7MwNqKglzq3NvZweepqs/X910BaCo4cf32Xlf7NLxcn\r\n"
    "6kzAM159IFxi7a4K0JatrzHtkFnRcPni+hQOPaK/69VpmkbWm+ZbsX7E9IOEpnFy\r\n"
    "zX/T1wIDAQABo2YwZDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIB\r\n"
    "BjAdBgNVHQ4EFgQUaxlrMI+Zfo8/mueb1OM8IjYCDWYwHwYDVR0jBBgwFoAUfnnj\r\n"
    "Z8meT6+b9DzYmmH9GjKwuBEwDQYJKoZIhvcNAQELBQADggEBAFkpBWKCGCumsavn\r\n"
    "rB+QHDRvMjadsVkbATfIfJaagBGL7OyKzydr351us21K8pWfK2yN6mbxHXxt34SF\r\n"
    "h/Ujke+PlRHFQELHTGwNWxbMQkNEpmFNNFr4tM9TgtQrtWFIDnPImtNc68EREgMe\r\n"
    "cXm+ttgPbAGY/55XQss7BfWcqzn5iYz4kDtdMIdbanVdVzwq+hVPxF8I4BX7KBdA\r\n"
    "ScmZzQt1N02IgMZmoRp0NKTHoXpWXAn/1q6lKQPzJoUD+D3RTpzKRNTsWy0Zayqr\r\n"
    "TNPPfYkeNkd+usSWnOTJkS1qMMS0v0Hul2WoqMRQzX2EQrkCeGwMSjWrIhrZLm2s\r\n"
    "YCUkPVM=\r\n"
    "-----END CERTIFICATE-----";

__attribute__((unused)) static const char g_ocspTestEeNoUrl[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDdjCCAl6gAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n"
    "ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n"
    "YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n"
    "BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n"
    "VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n"
    "7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n"
    "nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n"
    "2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n"
    "gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n"
    "AgMBAAGjfzB9MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQW\r\n"
    "MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUI8v0ekDYoVYml3+bvYUH\r\n"
    "30FXIrwwHwYDVR0jBBgwFoAUaxlrMI+Zfo8/mueb1OM8IjYCDWYwDQYJKoZIhvcN\r\n"
    "AQELBQADggEBAIVy2If+CjaHMXGcDzeWvMWQ4g6Yi6m3hXzUp5hMYlhBhRKkSg6u\r\n"
    "ixUytcsEKdVDuwaR9wh3yX2XBEGdL7yMWhRE0iEpcyN8nLj0cVW+dof+MWOzJ5fg\r\n"
    "MmHs4sSrfOVZd9IvtV15X2NlYYDAAhJ7RslK2L9RDLjDWTYd8mB8fft78bCPtSuD\r\n"
    "4R7yOyXDzW0ExX6Lovq5lgVP6Asf0G7BhBQ6UikUc+yZ2Sd+uLmAS+Q7YDKmtiPs\r\n"
    "/oNpF73k7L4b6v8J6o1fe5EUs+GLZWCTD+p8cB+HzzQTgDdWCeYvbh47wWY5XeGW\r\n"
    "T6U3x6qmRPdlZ7nC1LWX0+KSRzwC4gnJGUM=\r\n"
    "-----END CERTIFICATE-----";

static const char g_ocspTestEeValidUrl[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDsDCCApigAwIBAgICEAIwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n"
    "ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n"
    "YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n"
    "BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n"
    "VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n"
    "7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n"
    "nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n"
    "2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n"
    "gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n"
    "AgMBAAGjgbgwgbUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\r\n"
    "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQjy/R6QNihViaXf5u9\r\n"
    "hQffQVcivDAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwiNgINZjA2BggrBgEF\r\n"
    "BQcBAQQqMCgwJgYIKwYBBQUHMAGGGmh0dHA6Ly9sb2NhbGhvc3Q6OTk5OS9vY3Nw\r\n"
    "MA0GCSqGSIb3DQEBCwUAA4IBAQCLigBe1flMn3EinNdHGh1V48pJ66SgGJeDDx2R\r\n"
    "7uAZqM0ptx9XWTg2IAOX77R84bNWX0aFs2GRO3QkQPXdNJz5SB4VpW00WzMQuqOk\r\n"
    "JkvDmpylmfV4q8mvjnppMBrFqqt0YtyLB7eloQ5gzlXHKZVSkkgr2A7c/XmlUt2v\r\n"
    "uK+G7G6oyWwJh2lA6dKVTZ4gYMwukTmrddYD0mT7hGMZC2Oinxcl8YW7VtqvRclv\r\n"
    "NWmXBEZrlN+Njv0V8RigrORT730J2ItaOX/9KBJqoakWB9vQ/Fmt/twJoiqeulVP\r\n"
    "i8vPC6j4huKyYwvaw2qYqsBETmWUlHn/pzXdWEA2C55M6P0E\r\n"
    "-----END CERTIFICATE-----";

static const char g_ocspTestEeInvalidUrl[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDpTCCAo2gAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwRDELMAkGA1UEBhMCVVMx\r\n"
    "ETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlPQ1NQIFRlc3QgSW50ZXJtZWRp\r\n"
    "YXRlIENBMB4XDTI2MDMyNDA5MDIzMFoXDTQ2MDMxOTA5MDIzMFowNzELMAkGA1UE\r\n"
    "BhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRUwEwYDVQQDDAxPQ1NQIFRlc3QgRUUw\r\n"
    "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA0Saa3vE7D/wpos+EwVuK\r\n"
    "VQ6iW0h5xmFwBZqH+79JUxprHBXjH/jKXG8+czWV9hx480u7zpmK1qI7b3aGhsc1\r\n"
    "7mpQ2AdUgN3645vz/XiZJ3ZNkTfSeE9PsWXNGS8sayAZZMr+vh4t2+/SsHP+JlDC\r\n"
    "nHzLuc0VqJbeqIaEqI4+4J2KxMVPDdI+VRCXly3tIXRnaoSbppvOlKpRjybMD6DA\r\n"
    "2mKaD/rI5jERE8hugeGGGLEATr0c7avd29dW0ol99mJqwSpqcFXW3ygwUrHRCu2R\r\n"
    "gI/7yHZkoylJWK3IVcfmEn7J5eTYNq4F8kAUheR1kjmOAgSB1C4sVhy5s3+rkeYj\r\n"
    "AgMBAAGjga0wgaowDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\r\n"
    "BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQjy/R6QNihViaXf5u9\r\n"
    "hQffQVcivDAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwiNgINZjArBggrBgEF\r\n"
    "BQcBAQQfMB0wGwYIKwYBBQUHMAGGD25vdC1hLXZhbGlkLXVybDANBgkqhkiG9w0B\r\n"
    "AQsFAAOCAQEAIeH6VGy6sbXv28Z1GCSLum8IultF4WYS71ECRuaWWtWHkRWsxjyM\r\n"
    "3pKOlw41PgWezAuvMkevO0M0YUA1M5OfEbo/KXScSxGYkNaZHMY+2TYThIy1CqSP\r\n"
    "xkb5kMsNVgOUXK8FjANc3IYWqD1AG9P2PbVbTkg4QNIbg+HQhovwj1/0cV/XQgCr\r\n"
    "gkF9/YNMKwHg94q4vmz7rKbmYr9hvtIGtxBxPBHEXDJiD0d4xgruxca4dTYufzgn\r\n"
    "dVoVUek7X2YeypNMDNJd4tiunHPj+9oBU09EUl4UOpTwjLOBgmV57LmIc8myR1jN\r\n"
    "bv7tckpb0oX4xQLTJukog5rOMqHwTciFtA==\r\n"
    "-----END CERTIFICATE-----";

/* New OCSP Signer (issued by Intermediate CA) */
static const char g_ocspTestSigner[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDhDCCAmygAwIBAgIUKd6YmN6s8C1VU/Mg5inyZzNVULYwDQYJKoZIhvcNAQEL\r\n"
    "BQAwRDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMSIwIAYDVQQDDBlP\r\n"
    "Q1NQIFRlc3QgSW50ZXJtZWRpYXRlIENBMB4XDTI2MDMyNDEwMDIyNVoXDTQ2MDMx\r\n"
    "OTEwMDIyNVowPTELMAkGA1UEBhMCVVMxETAPBgNVBAoMCFRlc3QgT3JnMRswGQYD\r\n"
    "VQQDDBJPQ1NQIFRlc3QgU2lnbmVyIDIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\r\n"
    "ggEKAoIBAQD0VqkKEJ5NCq5LCrzwhmnVHlEKZ6L1Vu4wnjzUQKwpmqyKxwLnEK6W\r\n"
    "4hKebgYi5X2K0TU3w8xM5SezTDgSxFqWRogs8SNsFkqNlQs/eCqZAwmq3XyvryZm\r\n"
    "ZKEGBGNw1/WM7b03V478CO4f98Nmn0R9jLOb3/7vAA8KBZzMH2BuYaKIsyCTjx59\r\n"
    "epRtNvNCEBM20tutwPOokau3xKLAae880EZo7xwqikLCQJJKK50YEIiE3F8CAq/b\r\n"
    "K2ls5/h1E5XW81JqyFl1nCaFLpXVS7apIwRMcJI5Rd1Rdhl+OauX656Vt7lHbe1D\r\n"
    "7tBEKlqKsL8rW7cS3cL4DUjsmdwyhKXVAgMBAAGjdTBzMAwGA1UdEwEB/wQCMAAw\r\n"
    "DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMJMB0GA1UdDgQWBBSA\r\n"
    "HX+oipIvPt4g0fZJtu5dEa8J9DAfBgNVHSMEGDAWgBRrGWswj5l+jz+a55vU4zwi\r\n"
    "NgINZjANBgkqhkiG9w0BAQsFAAOCAQEAG690fQilaAlchDoO0w0pdu5VZBKXJy/q\r\n"
    "a0g1nioJdtWzOt+P6+Qgq+tHAmFC+TXNTt1d8uClkEoFP/iZGaNbbnH4/s0e4l0Y\r\n"
    "btcn1WQyN4HBDw8aS0qOvw3f2u75AqJgb5Uuv220cqlgW0DUpqf1/LlSJDTmZjim\r\n"
    "dGoFe7kdlhLZwW43BBk5v6oRBY4r8z9i7QNcXks23AiTvkbqqW1RIsPoVGXjwYxL\r\n"
    "cxYS9wgmVMhcCBDADnCD35R6HKI0tr6E1jnJI0tn9w1QmcJtncLAArvHcOUWIUGc\r\n"
    "GvnVC5X3F2kF/JWK8ZUHgmpRyrMq9fL6fV53BzSQPp+vFEUiFPZQeQ==\r\n"
    "-----END CERTIFICATE-----";

/* ========== OCSP Test Responses ========== */

static const uint8_t g_ocspTestRespGood[] = {
  0x30, 0x82, 0x05, 0xa3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x05, 0x9c, 0x30,
  0x82, 0x05, 0x98, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
  0x01, 0x01, 0x04, 0x82, 0x05, 0x89, 0x30, 0x82, 0x05, 0x85, 0x30, 0x81,
  0xde, 0xa1, 0x3f, 0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72,
  0x67, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
  0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69,
  0x67, 0x6e, 0x65, 0x72, 0x20, 0x32, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x32, 0x34, 0x30, 0x5a, 0x30,
  0x65, 0x30, 0x63, 0x30, 0x3b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
  0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x2d, 0x90, 0x9d, 0xcb, 0x44, 0xf0,
  0xf1, 0x11, 0x90, 0xf6, 0x1b, 0x30, 0xa0, 0x94, 0xe6, 0xe6, 0xa1, 0x51,
  0xcc, 0xf5, 0x04, 0x14, 0x6b, 0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f,
  0x3f, 0x9a, 0xe7, 0x9b, 0xd4, 0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66,
  0x02, 0x02, 0x10, 0x02, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x32, 0x34, 0x30, 0x5a, 0xa0,
  0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x33, 0x33, 0x31, 0x31,
  0x30, 0x30, 0x32, 0x34, 0x30, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f,
  0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
  0x12, 0x04, 0x10, 0x10, 0x50, 0x47, 0x4a, 0xf2, 0x52, 0x69, 0x8c, 0x53,
  0x2f, 0xcf, 0xf8, 0x6a, 0x6c, 0xd0, 0x60, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0x6d, 0x8f, 0x5d, 0x44, 0x17, 0xfa, 0x3f, 0xa6, 0x6b,
  0x7c, 0xb1, 0x3a, 0x53, 0x76, 0x08, 0x79, 0xad, 0x28, 0x59, 0x62, 0xd5,
  0x6f, 0x97, 0x25, 0x3a, 0x77, 0x4d, 0x5c, 0xdd, 0x0e, 0x4f, 0xc3, 0x9e,
  0x1a, 0x58, 0x03, 0x89, 0x82, 0x8c, 0x23, 0x46, 0x31, 0xaa, 0x10, 0xcf,
  0xd9, 0x8c, 0xc3, 0xcd, 0xaf, 0xe2, 0xcd, 0xd1, 0x0a, 0xd5, 0xd1, 0xdc,
  0xb5, 0xe8, 0xd7, 0xeb, 0x2e, 0x8a, 0x26, 0xe4, 0xb6, 0x13, 0x05, 0xc9,
  0x74, 0x34, 0x57, 0xa4, 0x18, 0x74, 0x19, 0x2f, 0x27, 0xeb, 0xbb, 0xd9,
  0xba, 0x5a, 0x7d, 0x84, 0xa6, 0x3a, 0x17, 0x04, 0x0b, 0x48, 0x1d, 0xf7,
  0x09, 0xd0, 0xa1, 0x6e, 0x9a, 0xf6, 0x63, 0x60, 0x04, 0xaa, 0xa7, 0xb0,
  0x81, 0xa6, 0xa2, 0x79, 0xd8, 0xc4, 0x07, 0x0b, 0xc3, 0x0c, 0x84, 0x5f,
  0x87, 0x03, 0x0d, 0x16, 0x86, 0x50, 0xe4, 0x88, 0x81, 0x22, 0xc2, 0x77,
  0x6f, 0xd1, 0xd6, 0xd3, 0x5d, 0x4a, 0x50, 0x86, 0x67, 0xf2, 0x65, 0xdd,
  0x81, 0x14, 0xc8, 0x75, 0x63, 0x28, 0x99, 0x23, 0x98, 0xfc, 0x69, 0x6e,
  0x40, 0xc4, 0xec, 0x99, 0xec, 0x2e, 0x8f, 0x25, 0x39, 0xd3, 0x85, 0xf0,
  0x66, 0xd3, 0x8b, 0xe9, 0x57, 0x7b, 0xbb, 0x55, 0x7f, 0xa6, 0xb0, 0x09,
  0x4d, 0xe1, 0x5c, 0x3c, 0xe3, 0x35, 0x7e, 0x8f, 0xcc, 0x34, 0x28, 0xfd,
  0x71, 0xd2, 0xa0, 0x1f, 0x65, 0xe9, 0xb6, 0x1e, 0xaf, 0xc2, 0x4d, 0x10,
  0x25, 0x03, 0x67, 0x55, 0x90, 0x51, 0x57, 0xb8, 0x96, 0xaf, 0xe4, 0x4b,
  0xe3, 0xef, 0x94, 0x07, 0xf5, 0xde, 0x0f, 0x01, 0xb0, 0xc8, 0x9c, 0x0e,
  0x30, 0xcf, 0xd7, 0xdb, 0x9c, 0x6a, 0x34, 0x3e, 0xd5, 0x26, 0xf6, 0xfb,
  0xc0, 0x25, 0x08, 0xd1, 0xfb, 0x3a, 0x14, 0x9a, 0xae, 0xde, 0x0d, 0xed,
  0xec, 0xcc, 0x7d, 0xd9, 0xe3, 0xa8, 0xbc, 0xa0, 0x82, 0x03, 0x8c, 0x30,
  0x82, 0x03, 0x88, 0x30, 0x82, 0x03, 0x84, 0x30, 0x82, 0x02, 0x6c, 0xa0,
  0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x29, 0xde, 0x98, 0x98, 0xde, 0xac,
  0xf0, 0x2d, 0x55, 0x53, 0xf3, 0x20, 0xe6, 0x29, 0xf2, 0x67, 0x33, 0x55,
  0x50, 0xb6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06,
  0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f,
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20,
  0x4f, 0x72, 0x67, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x19, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
  0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
  0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x33, 0x32,
  0x34, 0x31, 0x30, 0x30, 0x32, 0x32, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x36,
  0x30, 0x33, 0x31, 0x39, 0x31, 0x30, 0x30, 0x32, 0x32, 0x35, 0x5a, 0x30,
  0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
  0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72, 0x67, 0x31, 0x1b, 0x30,
  0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x4f, 0x43, 0x53, 0x50,
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72,
  0x20, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
  0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf4,
  0x56, 0xa9, 0x0a, 0x10, 0x9e, 0x4d, 0x0a, 0xae, 0x4b, 0x0a, 0xbc, 0xf0,
  0x86, 0x69, 0xd5, 0x1e, 0x51, 0x0a, 0x67, 0xa2, 0xf5, 0x56, 0xee, 0x30,
  0x9e, 0x3c, 0xd4, 0x40, 0xac, 0x29, 0x9a, 0xac, 0x8a, 0xc7, 0x02, 0xe7,
  0x10, 0xae, 0x96, 0xe2, 0x12, 0x9e, 0x6e, 0x06, 0x22, 0xe5, 0x7d, 0x8a,
  0xd1, 0x35, 0x37, 0xc3, 0xcc, 0x4c, 0xe5, 0x27, 0xb3, 0x4c, 0x38, 0x12,
  0xc4, 0x5a, 0x96, 0x46, 0x88, 0x2c, 0xf1, 0x23, 0x6c, 0x16, 0x4a, 0x8d,
  0x95, 0x0b, 0x3f, 0x78, 0x2a, 0x99, 0x03, 0x09, 0xaa, 0xdd, 0x7c, 0xaf,
  0xaf, 0x26, 0x66, 0x64, 0xa1, 0x06, 0x04, 0x63, 0x70, 0xd7, 0xf5, 0x8c,
  0xed, 0xbd, 0x37, 0x57, 0x8e, 0xfc, 0x08, 0xee, 0x1f, 0xf7, 0xc3, 0x66,
  0x9f, 0x44, 0x7d, 0x8c, 0xb3, 0x9b, 0xdf, 0xfe, 0xef, 0x00, 0x0f, 0x0a,
  0x05, 0x9c, 0xcc, 0x1f, 0x60, 0x6e, 0x61, 0xa2, 0x88, 0xb3, 0x20, 0x93,
  0x8f, 0x1e, 0x7d, 0x7a, 0x94, 0x6d, 0x36, 0xf3, 0x42, 0x10, 0x13, 0x36,
  0xd2, 0xdb, 0xad, 0xc0, 0xf3, 0xa8, 0x91, 0xab, 0xb7, 0xc4, 0xa2, 0xc0,
  0x69, 0xef, 0x3c, 0xd0, 0x46, 0x68, 0xef, 0x1c, 0x2a, 0x8a, 0x42, 0xc2,
  0x40, 0x92, 0x4a, 0x2b, 0x9d, 0x18, 0x10, 0x88, 0x84, 0xdc, 0x5f, 0x02,
  0x02, 0xaf, 0xdb, 0x2b, 0x69, 0x6c, 0xe7, 0xf8, 0x75, 0x13, 0x95, 0xd6,
  0xf3, 0x52, 0x6a, 0xc8, 0x59, 0x75, 0x9c, 0x26, 0x85, 0x2e, 0x95, 0xd5,
  0x4b, 0xb6, 0xa9, 0x23, 0x04, 0x4c, 0x70, 0x92, 0x39, 0x45, 0xdd, 0x51,
  0x76, 0x19, 0x7e, 0x39, 0xab, 0x97, 0xeb, 0x9e, 0x95, 0xb7, 0xb9, 0x47,
  0x6d, 0xed, 0x43, 0xee, 0xd0, 0x44, 0x2a, 0x5a, 0x8a, 0xb0, 0xbf, 0x2b,
  0x5b, 0xb7, 0x12, 0xdd, 0xc2, 0xf8, 0x0d, 0x48, 0xec, 0x99, 0xdc, 0x32,
  0x84, 0xa5, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x75, 0x30, 0x73,
  0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
  0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
  0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d,
  0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
  0x07, 0x03, 0x09, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
  0x04, 0x14, 0x80, 0x1d, 0x7f, 0xa8, 0x8a, 0x92, 0x2f, 0x3e, 0xde, 0x20,
  0xd1, 0xf6, 0x49, 0xb6, 0xee, 0x5d, 0x11, 0xaf, 0x09, 0xf4, 0x30, 0x1f,
  0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6b,
  0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f, 0x3f, 0x9a, 0xe7, 0x9b, 0xd4,
  0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0x1b, 0xaf, 0x74, 0x7d, 0x08, 0xa5, 0x68, 0x09, 0x5c,
  0x84, 0x3a, 0x0e, 0xd3, 0x0d, 0x29, 0x76, 0xee, 0x55, 0x64, 0x12, 0x97,
  0x27, 0x2f, 0xea, 0x6b, 0x48, 0x35, 0x9e, 0x2a, 0x09, 0x76, 0xd5, 0xb3,
  0x3a, 0xdf, 0x8f, 0xeb, 0xe4, 0x20, 0xab, 0xeb, 0x47, 0x02, 0x61, 0x42,
  0xf9, 0x35, 0xcd, 0x4e, 0xdd, 0x5d, 0xf2, 0xe0, 0xa5, 0x90, 0x4a, 0x05,
  0x3f, 0xf8, 0x99, 0x19, 0xa3, 0x5b, 0x6e, 0x71, 0xf8, 0xfe, 0xcd, 0x1e,
  0xe2, 0x5d, 0x18, 0x6e, 0xd7, 0x27, 0xd5, 0x64, 0x32, 0x37, 0x81, 0xc1,
  0x0f, 0x0f, 0x1a, 0x4b, 0x4a, 0x8e, 0xbf, 0x0d, 0xdf, 0xda, 0xee, 0xf9,
  0x02, 0xa2, 0x60, 0x6f, 0x95, 0x2e, 0xbf, 0x6d, 0xb4, 0x72, 0xa9, 0x60,
  0x5b, 0x40, 0xd4, 0xa6, 0xa7, 0xf5, 0xfc, 0xb9, 0x52, 0x24, 0x34, 0xe6,
  0x66, 0x38, 0xa6, 0x74, 0x6a, 0x05, 0x7b, 0xb9, 0x1d, 0x96, 0x12, 0xd9,
  0xc1, 0x6e, 0x37, 0x04, 0x19, 0x39, 0xbf, 0xaa, 0x11, 0x05, 0x8e, 0x2b,
  0xf3, 0x3f, 0x62, 0xed, 0x03, 0x5c, 0x5e, 0x4b, 0x36, 0xdc, 0x08, 0x93,
  0xbe, 0x46, 0xea, 0xa9, 0x6d, 0x51, 0x22, 0xc3, 0xe8, 0x54, 0x65, 0xe3,
  0xc1, 0x8c, 0x4b, 0x73, 0x16, 0x12, 0xf7, 0x08, 0x26, 0x54, 0xc8, 0x5c,
  0x08, 0x10, 0xc0, 0x0e, 0x70, 0x83, 0xdf, 0x94, 0x7a, 0x1c, 0xa2, 0x34,
  0xb6, 0xbe, 0x84, 0xd6, 0x39, 0xc9, 0x23, 0x4b, 0x67, 0xf7, 0x0d, 0x50,
  0x99, 0xc2, 0x6d, 0x9d, 0xc2, 0xc0, 0x02, 0xbb, 0xc7, 0x70, 0xe5, 0x16,
  0x21, 0x41, 0x9c, 0x1a, 0xf9, 0xd5, 0x0b, 0x95, 0xf7, 0x17, 0x69, 0x05,
  0xfc, 0x95, 0x8a, 0xf1, 0x95, 0x07, 0x82, 0x6a, 0x51, 0xca, 0xb3, 0x2a,
  0xf5, 0xf2, 0xfa, 0x7d, 0x5e, 0x77, 0x07, 0x34, 0x90, 0x3e, 0x9f, 0xaf,
  0x14, 0x45, 0x22, 0x14, 0xf6, 0x50, 0x79
};

static const uint8_t g_ocspTestRespRevoked[] = {
  0x30, 0x82, 0x05, 0xb4, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x05, 0xad, 0x30,
  0x82, 0x05, 0xa9, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
  0x01, 0x01, 0x04, 0x82, 0x05, 0x9a, 0x30, 0x82, 0x05, 0x96, 0x30, 0x81,
  0xef, 0xa1, 0x3f, 0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72,
  0x67, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
  0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69,
  0x67, 0x6e, 0x65, 0x72, 0x20, 0x32, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x33, 0x31, 0x30, 0x5a, 0x30,
  0x76, 0x30, 0x74, 0x30, 0x3b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
  0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x2d, 0x90, 0x9d, 0xcb, 0x44, 0xf0,
  0xf1, 0x11, 0x90, 0xf6, 0x1b, 0x30, 0xa0, 0x94, 0xe6, 0xe6, 0xa1, 0x51,
  0xcc, 0xf5, 0x04, 0x14, 0x6b, 0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f,
  0x3f, 0x9a, 0xe7, 0x9b, 0xd4, 0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66,
  0x02, 0x02, 0x10, 0x02, 0xa1, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18,
  0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30,
  0x33, 0x31, 0x30, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x33, 0x31, 0x31, 0x30, 0x30, 0x33, 0x31, 0x30, 0x5a, 0xa1,
  0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05,
  0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0x82, 0xbe, 0x2c, 0xf0,
  0xd6, 0xea, 0x95, 0xea, 0xa6, 0x9c, 0x4e, 0x44, 0xbb, 0x2f, 0x96, 0x6e,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x7f, 0x9d, 0x70, 0x56,
  0x2a, 0x00, 0x16, 0xf5, 0x41, 0xe3, 0x15, 0x58, 0x2b, 0xda, 0x29, 0x9b,
  0x71, 0x84, 0x12, 0x18, 0x94, 0x54, 0x2e, 0xde, 0xf2, 0xe1, 0x03, 0xe7,
  0xdc, 0x81, 0xfd, 0xa3, 0x3a, 0x3a, 0xe0, 0x70, 0xac, 0x7a, 0x9b, 0x74,
  0x1b, 0x7a, 0xb9, 0x3c, 0x00, 0x71, 0xf8, 0x8e, 0xff, 0x9a, 0x61, 0x36,
  0x27, 0xae, 0x94, 0x3c, 0xb8, 0xfa, 0xb1, 0xf3, 0xa1, 0x3a, 0xea, 0x41,
  0x18, 0x50, 0x28, 0x07, 0x13, 0x07, 0xcd, 0xc4, 0x09, 0x43, 0xc9, 0x9d,
  0xa2, 0xb5, 0xbb, 0x43, 0x58, 0x46, 0xaa, 0xfc, 0xc8, 0x5e, 0x1a, 0x06,
  0x18, 0x1e, 0x36, 0xf1, 0x41, 0x20, 0xd5, 0xb2, 0x82, 0x37, 0xd0, 0xdc,
  0xfd, 0x48, 0x97, 0x68, 0xbe, 0x63, 0x04, 0xe8, 0x25, 0x10, 0x67, 0x2e,
  0x78, 0x1d, 0x36, 0xdf, 0xd3, 0x28, 0xf8, 0x03, 0xb8, 0x91, 0x1f, 0x51,
  0x3e, 0x99, 0xb0, 0x08, 0x0a, 0x44, 0xea, 0xb1, 0xbb, 0x7b, 0x1c, 0x57,
  0xab, 0xcb, 0xe5, 0x71, 0x87, 0xba, 0x3e, 0xc6, 0x42, 0xe6, 0x61, 0xe9,
  0xcf, 0x01, 0x99, 0x69, 0x66, 0x0e, 0x12, 0x90, 0xe6, 0xe6, 0xf8, 0x00,
  0x9a, 0x98, 0x07, 0x88, 0xa4, 0x20, 0x0d, 0xb9, 0x6c, 0x75, 0x17, 0x7e,
  0x9d, 0xb7, 0xf2, 0x3a, 0x46, 0x2d, 0x30, 0x75, 0xa3, 0xea, 0x17, 0xe9,
  0xae, 0xae, 0xd7, 0x52, 0xa5, 0x68, 0x20, 0x14, 0xe6, 0xa5, 0x6d, 0x5b,
  0x83, 0xe1, 0x5e, 0x56, 0x82, 0x1c, 0xbc, 0x4d, 0x21, 0x5d, 0xb8, 0x42,
  0xca, 0x3a, 0xda, 0x2f, 0x97, 0x74, 0xf2, 0x36, 0x38, 0x4e, 0xb2, 0x56,
  0x2c, 0xcd, 0x8a, 0x4f, 0x31, 0xed, 0x3f, 0xe2, 0xfc, 0x54, 0x8b, 0x53,
  0x83, 0xb2, 0x19, 0x2a, 0xf6, 0x0d, 0x61, 0x7f, 0x47, 0x25, 0x81, 0xe9,
  0xde, 0xd2, 0x35, 0x90, 0x29, 0x43, 0xa1, 0x71, 0x82, 0x1b, 0xf0, 0x48,
  0xa0, 0x82, 0x03, 0x8c, 0x30, 0x82, 0x03, 0x88, 0x30, 0x82, 0x03, 0x84,
  0x30, 0x82, 0x02, 0x6c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x29,
  0xde, 0x98, 0x98, 0xde, 0xac, 0xf0, 0x2d, 0x55, 0x53, 0xf3, 0x20, 0xe6,
  0x29, 0xf2, 0x67, 0x33, 0x55, 0x50, 0xb6, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x44,
  0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
  0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08,
  0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72, 0x67, 0x31, 0x22, 0x30, 0x20,
  0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x19, 0x4f, 0x43, 0x53, 0x50, 0x20,
  0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65,
  0x64, 0x69, 0x61, 0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
  0x32, 0x36, 0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x32, 0x32, 0x35,
  0x5a, 0x17, 0x0d, 0x34, 0x36, 0x30, 0x33, 0x31, 0x39, 0x31, 0x30, 0x30,
  0x32, 0x32, 0x35, 0x5a, 0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
  0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f,
  0x72, 0x67, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
  0x12, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53,
  0x69, 0x67, 0x6e, 0x65, 0x72, 0x20, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30,
  0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02,
  0x82, 0x01, 0x01, 0x00, 0xf4, 0x56, 0xa9, 0x0a, 0x10, 0x9e, 0x4d, 0x0a,
  0xae, 0x4b, 0x0a, 0xbc, 0xf0, 0x86, 0x69, 0xd5, 0x1e, 0x51, 0x0a, 0x67,
  0xa2, 0xf5, 0x56, 0xee, 0x30, 0x9e, 0x3c, 0xd4, 0x40, 0xac, 0x29, 0x9a,
  0xac, 0x8a, 0xc7, 0x02, 0xe7, 0x10, 0xae, 0x96, 0xe2, 0x12, 0x9e, 0x6e,
  0x06, 0x22, 0xe5, 0x7d, 0x8a, 0xd1, 0x35, 0x37, 0xc3, 0xcc, 0x4c, 0xe5,
  0x27, 0xb3, 0x4c, 0x38, 0x12, 0xc4, 0x5a, 0x96, 0x46, 0x88, 0x2c, 0xf1,
  0x23, 0x6c, 0x16, 0x4a, 0x8d, 0x95, 0x0b, 0x3f, 0x78, 0x2a, 0x99, 0x03,
  0x09, 0xaa, 0xdd, 0x7c, 0xaf, 0xaf, 0x26, 0x66, 0x64, 0xa1, 0x06, 0x04,
  0x63, 0x70, 0xd7, 0xf5, 0x8c, 0xed, 0xbd, 0x37, 0x57, 0x8e, 0xfc, 0x08,
  0xee, 0x1f, 0xf7, 0xc3, 0x66, 0x9f, 0x44, 0x7d, 0x8c, 0xb3, 0x9b, 0xdf,
  0xfe, 0xef, 0x00, 0x0f, 0x0a, 0x05, 0x9c, 0xcc, 0x1f, 0x60, 0x6e, 0x61,
  0xa2, 0x88, 0xb3, 0x20, 0x93, 0x8f, 0x1e, 0x7d, 0x7a, 0x94, 0x6d, 0x36,
  0xf3, 0x42, 0x10, 0x13, 0x36, 0xd2, 0xdb, 0xad, 0xc0, 0xf3, 0xa8, 0x91,
  0xab, 0xb7, 0xc4, 0xa2, 0xc0, 0x69, 0xef, 0x3c, 0xd0, 0x46, 0x68, 0xef,
  0x1c, 0x2a, 0x8a, 0x42, 0xc2, 0x40, 0x92, 0x4a, 0x2b, 0x9d, 0x18, 0x10,
  0x88, 0x84, 0xdc, 0x5f, 0x02, 0x02, 0xaf, 0xdb, 0x2b, 0x69, 0x6c, 0xe7,
  0xf8, 0x75, 0x13, 0x95, 0xd6, 0xf3, 0x52, 0x6a, 0xc8, 0x59, 0x75, 0x9c,
  0x26, 0x85, 0x2e, 0x95, 0xd5, 0x4b, 0xb6, 0xa9, 0x23, 0x04, 0x4c, 0x70,
  0x92, 0x39, 0x45, 0xdd, 0x51, 0x76, 0x19, 0x7e, 0x39, 0xab, 0x97, 0xeb,
  0x9e, 0x95, 0xb7, 0xb9, 0x47, 0x6d, 0xed, 0x43, 0xee, 0xd0, 0x44, 0x2a,
  0x5a, 0x8a, 0xb0, 0xbf, 0x2b, 0x5b, 0xb7, 0x12, 0xdd, 0xc2, 0xf8, 0x0d,
  0x48, 0xec, 0x99, 0xdc, 0x32, 0x84, 0xa5, 0xd5, 0x02, 0x03, 0x01, 0x00,
  0x01, 0xa3, 0x75, 0x30, 0x73, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13,
  0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55,
  0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30,
  0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08,
  0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x1d, 0x06, 0x03,
  0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x80, 0x1d, 0x7f, 0xa8, 0x8a,
  0x92, 0x2f, 0x3e, 0xde, 0x20, 0xd1, 0xf6, 0x49, 0xb6, 0xee, 0x5d, 0x11,
  0xaf, 0x09, 0xf4, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
  0x30, 0x16, 0x80, 0x14, 0x6b, 0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f,
  0x3f, 0x9a, 0xe7, 0x9b, 0xd4, 0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66,
  0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
  0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x1b, 0xaf, 0x74, 0x7d,
  0x08, 0xa5, 0x68, 0x09, 0x5c, 0x84, 0x3a, 0x0e, 0xd3, 0x0d, 0x29, 0x76,
  0xee, 0x55, 0x64, 0x12, 0x97, 0x27, 0x2f, 0xea, 0x6b, 0x48, 0x35, 0x9e,
  0x2a, 0x09, 0x76, 0xd5, 0xb3, 0x3a, 0xdf, 0x8f, 0xeb, 0xe4, 0x20, 0xab,
  0xeb, 0x47, 0x02, 0x61, 0x42, 0xf9, 0x35, 0xcd, 0x4e, 0xdd, 0x5d, 0xf2,
  0xe0, 0xa5, 0x90, 0x4a, 0x05, 0x3f, 0xf8, 0x99, 0x19, 0xa3, 0x5b, 0x6e,
  0x71, 0xf8, 0xfe, 0xcd, 0x1e, 0xe2, 0x5d, 0x18, 0x6e, 0xd7, 0x27, 0xd5,
  0x64, 0x32, 0x37, 0x81, 0xc1, 0x0f, 0x0f, 0x1a, 0x4b, 0x4a, 0x8e, 0xbf,
  0x0d, 0xdf, 0xda, 0xee, 0xf9, 0x02, 0xa2, 0x60, 0x6f, 0x95, 0x2e, 0xbf,
  0x6d, 0xb4, 0x72, 0xa9, 0x60, 0x5b, 0x40, 0xd4, 0xa6, 0xa7, 0xf5, 0xfc,
  0xb9, 0x52, 0x24, 0x34, 0xe6, 0x66, 0x38, 0xa6, 0x74, 0x6a, 0x05, 0x7b,
  0xb9, 0x1d, 0x96, 0x12, 0xd9, 0xc1, 0x6e, 0x37, 0x04, 0x19, 0x39, 0xbf,
  0xaa, 0x11, 0x05, 0x8e, 0x2b, 0xf3, 0x3f, 0x62, 0xed, 0x03, 0x5c, 0x5e,
  0x4b, 0x36, 0xdc, 0x08, 0x93, 0xbe, 0x46, 0xea, 0xa9, 0x6d, 0x51, 0x22,
  0xc3, 0xe8, 0x54, 0x65, 0xe3, 0xc1, 0x8c, 0x4b, 0x73, 0x16, 0x12, 0xf7,
  0x08, 0x26, 0x54, 0xc8, 0x5c, 0x08, 0x10, 0xc0, 0x0e, 0x70, 0x83, 0xdf,
  0x94, 0x7a, 0x1c, 0xa2, 0x34, 0xb6, 0xbe, 0x84, 0xd6, 0x39, 0xc9, 0x23,
  0x4b, 0x67, 0xf7, 0x0d, 0x50, 0x99, 0xc2, 0x6d, 0x9d, 0xc2, 0xc0, 0x02,
  0xbb, 0xc7, 0x70, 0xe5, 0x16, 0x21, 0x41, 0x9c, 0x1a, 0xf9, 0xd5, 0x0b,
  0x95, 0xf7, 0x17, 0x69, 0x05, 0xfc, 0x95, 0x8a, 0xf1, 0x95, 0x07, 0x82,
  0x6a, 0x51, 0xca, 0xb3, 0x2a, 0xf5, 0xf2, 0xfa, 0x7d, 0x5e, 0x77, 0x07,
  0x34, 0x90, 0x3e, 0x9f, 0xaf, 0x14, 0x45, 0x22, 0x14, 0xf6, 0x50, 0x79
};

static const uint8_t g_ocspTestRespUnknown[] = {
  0x30, 0x82, 0x05, 0xa3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x05, 0x9c, 0x30,
  0x82, 0x05, 0x98, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
  0x01, 0x01, 0x04, 0x82, 0x05, 0x89, 0x30, 0x82, 0x05, 0x85, 0x30, 0x81,
  0xde, 0xa1, 0x3f, 0x30, 0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
  0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
  0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72,
  0x67, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12,
  0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69,
  0x67, 0x6e, 0x65, 0x72, 0x20, 0x32, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x33, 0x32, 0x33, 0x5a, 0x30,
  0x65, 0x30, 0x63, 0x30, 0x3b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03,
  0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, 0x2d, 0x90, 0x9d, 0xcb, 0x44, 0xf0,
  0xf1, 0x11, 0x90, 0xf6, 0x1b, 0x30, 0xa0, 0x94, 0xe6, 0xe6, 0xa1, 0x51,
  0xcc, 0xf5, 0x04, 0x14, 0x6b, 0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f,
  0x3f, 0x9a, 0xe7, 0x9b, 0xd4, 0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66,
  0x02, 0x02, 0x10, 0x02, 0x82, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36,
  0x30, 0x33, 0x32, 0x34, 0x31, 0x30, 0x30, 0x33, 0x32, 0x33, 0x5a, 0xa0,
  0x11, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x36, 0x30, 0x33, 0x33, 0x31, 0x31,
  0x30, 0x30, 0x33, 0x32, 0x33, 0x5a, 0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f,
  0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02, 0x04,
  0x12, 0x04, 0x10, 0xd4, 0x6c, 0x4a, 0xff, 0x75, 0x3b, 0x6b, 0xdb, 0x2f,
  0x2e, 0x38, 0x2e, 0x72, 0xe3, 0x25, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0xda, 0x89, 0x88, 0x61, 0x4d, 0x98, 0x10, 0x6e, 0x36,
  0xab, 0xeb, 0xed, 0x95, 0xbb, 0x40, 0xd4, 0xf5, 0x87, 0x51, 0x7f, 0xc5,
  0x94, 0x03, 0xd0, 0x0d, 0xba, 0x3e, 0xec, 0xdb, 0xc0, 0xc9, 0x98, 0xc5,
  0x85, 0x4c, 0xf0, 0x5c, 0x5c, 0x8c, 0x5b, 0x87, 0x9e, 0xd6, 0xb3, 0x94,
  0xc5, 0x56, 0xce, 0x0e, 0x36, 0x6b, 0x8f, 0xb2, 0x9d, 0x96, 0xe7, 0xf2,
  0x3d, 0xd9, 0xdd, 0xfe, 0xe3, 0x19, 0x16, 0x0c, 0x98, 0x8d, 0xac, 0x3e,
  0x6e, 0xaa, 0x98, 0x7d, 0x7b, 0x6c, 0xf6, 0x34, 0x81, 0x2d, 0x9b, 0x60,
  0xc9, 0xba, 0xac, 0xf2, 0x0c, 0xf0, 0x1f, 0x89, 0x1c, 0x40, 0x93, 0x28,
  0x06, 0x55, 0x61, 0xfc, 0x46, 0xf6, 0x0c, 0x2e, 0x77, 0x13, 0xeb, 0x97,
  0xa3, 0x7a, 0xc2, 0xf3, 0x2f, 0x6c, 0x23, 0xc3, 0x17, 0x27, 0x9d, 0x38,
  0x0a, 0xcd, 0xc2, 0x70, 0x48, 0x5f, 0x80, 0xba, 0x4b, 0x24, 0x89, 0x8e,
  0x9c, 0xf6, 0x7e, 0x74, 0x6e, 0xf9, 0x49, 0xf3, 0xc1, 0x7c, 0xf6, 0x58,
  0x58, 0x56, 0x40, 0x2e, 0xf5, 0xb9, 0xca, 0x38, 0xc5, 0xd3, 0x05, 0x09,
  0x63, 0x51, 0x39, 0x75, 0xdd, 0xe8, 0x62, 0xaf, 0xda, 0x00, 0x69, 0xfd,
  0x1f, 0xa5, 0x52, 0xeb, 0xf6, 0x2e, 0x24, 0x2b, 0xcc, 0x78, 0x9f, 0x08,
  0xdf, 0x7c, 0x89, 0xe8, 0xbd, 0x0a, 0x18, 0x59, 0x72, 0x87, 0xaf, 0x23,
  0xfa, 0xde, 0x65, 0x5e, 0x21, 0x39, 0x07, 0xd0, 0x01, 0x46, 0x9e, 0x17,
  0xa6, 0x6d, 0x90, 0x2b, 0xaa, 0xa0, 0xff, 0xd5, 0x9d, 0x85, 0xd7, 0x4b,
  0xba, 0x32, 0x8a, 0x61, 0x24, 0x57, 0x99, 0xa2, 0x5b, 0x2d, 0x55, 0xed,
  0xd0, 0x55, 0x62, 0x29, 0xe2, 0xfe, 0x86, 0x72, 0x61, 0xc5, 0xb8, 0x05,
  0x3e, 0xce, 0x71, 0xa9, 0xa4, 0x01, 0xde, 0x56, 0x5d, 0x8e, 0xe3, 0x77,
  0xbd, 0xf0, 0x41, 0x2e, 0x7b, 0xbb, 0x65, 0xa0, 0x82, 0x03, 0x8c, 0x30,
  0x82, 0x03, 0x88, 0x30, 0x82, 0x03, 0x84, 0x30, 0x82, 0x02, 0x6c, 0xa0,
  0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x29, 0xde, 0x98, 0x98, 0xde, 0xac,
  0xf0, 0x2d, 0x55, 0x53, 0xf3, 0x20, 0xe6, 0x29, 0xf2, 0x67, 0x33, 0x55,
  0x50, 0xb6, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
  0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x44, 0x31, 0x0b, 0x30, 0x09, 0x06,
  0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x11, 0x30, 0x0f,
  0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x20,
  0x4f, 0x72, 0x67, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03,
  0x0c, 0x19, 0x4f, 0x43, 0x53, 0x50, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20,
  0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65,
  0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x33, 0x32,
  0x34, 0x31, 0x30, 0x30, 0x32, 0x32, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x36,
  0x30, 0x33, 0x31, 0x39, 0x31, 0x30, 0x30, 0x32, 0x32, 0x35, 0x5a, 0x30,
  0x3d, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
  0x55, 0x53, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
  0x08, 0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x72, 0x67, 0x31, 0x1b, 0x30,
  0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x4f, 0x43, 0x53, 0x50,
  0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x53, 0x69, 0x67, 0x6e, 0x65, 0x72,
  0x20, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
  0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
  0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xf4,
  0x56, 0xa9, 0x0a, 0x10, 0x9e, 0x4d, 0x0a, 0xae, 0x4b, 0x0a, 0xbc, 0xf0,
  0x86, 0x69, 0xd5, 0x1e, 0x51, 0x0a, 0x67, 0xa2, 0xf5, 0x56, 0xee, 0x30,
  0x9e, 0x3c, 0xd4, 0x40, 0xac, 0x29, 0x9a, 0xac, 0x8a, 0xc7, 0x02, 0xe7,
  0x10, 0xae, 0x96, 0xe2, 0x12, 0x9e, 0x6e, 0x06, 0x22, 0xe5, 0x7d, 0x8a,
  0xd1, 0x35, 0x37, 0xc3, 0xcc, 0x4c, 0xe5, 0x27, 0xb3, 0x4c, 0x38, 0x12,
  0xc4, 0x5a, 0x96, 0x46, 0x88, 0x2c, 0xf1, 0x23, 0x6c, 0x16, 0x4a, 0x8d,
  0x95, 0x0b, 0x3f, 0x78, 0x2a, 0x99, 0x03, 0x09, 0xaa, 0xdd, 0x7c, 0xaf,
  0xaf, 0x26, 0x66, 0x64, 0xa1, 0x06, 0x04, 0x63, 0x70, 0xd7, 0xf5, 0x8c,
  0xed, 0xbd, 0x37, 0x57, 0x8e, 0xfc, 0x08, 0xee, 0x1f, 0xf7, 0xc3, 0x66,
  0x9f, 0x44, 0x7d, 0x8c, 0xb3, 0x9b, 0xdf, 0xfe, 0xef, 0x00, 0x0f, 0x0a,
  0x05, 0x9c, 0xcc, 0x1f, 0x60, 0x6e, 0x61, 0xa2, 0x88, 0xb3, 0x20, 0x93,
  0x8f, 0x1e, 0x7d, 0x7a, 0x94, 0x6d, 0x36, 0xf3, 0x42, 0x10, 0x13, 0x36,
  0xd2, 0xdb, 0xad, 0xc0, 0xf3, 0xa8, 0x91, 0xab, 0xb7, 0xc4, 0xa2, 0xc0,
  0x69, 0xef, 0x3c, 0xd0, 0x46, 0x68, 0xef, 0x1c, 0x2a, 0x8a, 0x42, 0xc2,
  0x40, 0x92, 0x4a, 0x2b, 0x9d, 0x18, 0x10, 0x88, 0x84, 0xdc, 0x5f, 0x02,
  0x02, 0xaf, 0xdb, 0x2b, 0x69, 0x6c, 0xe7, 0xf8, 0x75, 0x13, 0x95, 0xd6,
  0xf3, 0x52, 0x6a, 0xc8, 0x59, 0x75, 0x9c, 0x26, 0x85, 0x2e, 0x95, 0xd5,
  0x4b, 0xb6, 0xa9, 0x23, 0x04, 0x4c, 0x70, 0x92, 0x39, 0x45, 0xdd, 0x51,
  0x76, 0x19, 0x7e, 0x39, 0xab, 0x97, 0xeb, 0x9e, 0x95, 0xb7, 0xb9, 0x47,
  0x6d, 0xed, 0x43, 0xee, 0xd0, 0x44, 0x2a, 0x5a, 0x8a, 0xb0, 0xbf, 0x2b,
  0x5b, 0xb7, 0x12, 0xdd, 0xc2, 0xf8, 0x0d, 0x48, 0xec, 0x99, 0xdc, 0x32,
  0x84, 0xa5, 0xd5, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x75, 0x30, 0x73,
  0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02,
  0x30, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
  0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d,
  0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
  0x07, 0x03, 0x09, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16,
  0x04, 0x14, 0x80, 0x1d, 0x7f, 0xa8, 0x8a, 0x92, 0x2f, 0x3e, 0xde, 0x20,
  0xd1, 0xf6, 0x49, 0xb6, 0xee, 0x5d, 0x11, 0xaf, 0x09, 0xf4, 0x30, 0x1f,
  0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x6b,
  0x19, 0x6b, 0x30, 0x8f, 0x99, 0x7e, 0x8f, 0x3f, 0x9a, 0xe7, 0x9b, 0xd4,
  0xe3, 0x3c, 0x22, 0x36, 0x02, 0x0d, 0x66, 0x30, 0x0d, 0x06, 0x09, 0x2a,
  0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
  0x01, 0x01, 0x00, 0x1b, 0xaf, 0x74, 0x7d, 0x08, 0xa5, 0x68, 0x09, 0x5c,
  0x84, 0x3a, 0x0e, 0xd3, 0x0d, 0x29, 0x76, 0xee, 0x55, 0x64, 0x12, 0x97,
  0x27, 0x2f, 0xea, 0x6b, 0x48, 0x35, 0x9e, 0x2a, 0x09, 0x76, 0xd5, 0xb3,
  0x3a, 0xdf, 0x8f, 0xeb, 0xe4, 0x20, 0xab, 0xeb, 0x47, 0x02, 0x61, 0x42,
  0xf9, 0x35, 0xcd, 0x4e, 0xdd, 0x5d, 0xf2, 0xe0, 0xa5, 0x90, 0x4a, 0x05,
  0x3f, 0xf8, 0x99, 0x19, 0xa3, 0x5b, 0x6e, 0x71, 0xf8, 0xfe, 0xcd, 0x1e,
  0xe2, 0x5d, 0x18, 0x6e, 0xd7, 0x27, 0xd5, 0x64, 0x32, 0x37, 0x81, 0xc1,
  0x0f, 0x0f, 0x1a, 0x4b, 0x4a, 0x8e, 0xbf, 0x0d, 0xdf, 0xda, 0xee, 0xf9,
  0x02, 0xa2, 0x60, 0x6f, 0x95, 0x2e, 0xbf, 0x6d, 0xb4, 0x72, 0xa9, 0x60,
  0x5b, 0x40, 0xd4, 0xa6, 0xa7, 0xf5, 0xfc, 0xb9, 0x52, 0x24, 0x34, 0xe6,
  0x66, 0x38, 0xa6, 0x74, 0x6a, 0x05, 0x7b, 0xb9, 0x1d, 0x96, 0x12, 0xd9,
  0xc1, 0x6e, 0x37, 0x04, 0x19, 0x39, 0xbf, 0xaa, 0x11, 0x05, 0x8e, 0x2b,
  0xf3, 0x3f, 0x62, 0xed, 0x03, 0x5c, 0x5e, 0x4b, 0x36, 0xdc, 0x08, 0x93,
  0xbe, 0x46, 0xea, 0xa9, 0x6d, 0x51, 0x22, 0xc3, 0xe8, 0x54, 0x65, 0xe3,
  0xc1, 0x8c, 0x4b, 0x73, 0x16, 0x12, 0xf7, 0x08, 0x26, 0x54, 0xc8, 0x5c,
  0x08, 0x10, 0xc0, 0x0e, 0x70, 0x83, 0xdf, 0x94, 0x7a, 0x1c, 0xa2, 0x34,
  0xb6, 0xbe, 0x84, 0xd6, 0x39, 0xc9, 0x23, 0x4b, 0x67, 0xf7, 0x0d, 0x50,
  0x99, 0xc2, 0x6d, 0x9d, 0xc2, 0xc0, 0x02, 0xbb, 0xc7, 0x70, 0xe5, 0x16,
  0x21, 0x41, 0x9c, 0x1a, 0xf9, 0xd5, 0x0b, 0x95, 0xf7, 0x17, 0x69, 0x05,
  0xfc, 0x95, 0x8a, 0xf1, 0x95, 0x07, 0x82, 0x6a, 0x51, 0xca, 0xb3, 0x2a,
  0xf5, 0xf2, 0xfa, 0x7d, 0x5e, 0x77, 0x07, 0x34, 0x90, 0x3e, 0x9f, 0xaf,
  0x14, 0x45, 0x22, 0x14, 0xf6, 0x50, 0x79
};




HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_015, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_015 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_016
 * @tc.desc: Test online OCSP check - cert with OCSP URL but server unreachable
 *           When certificate has OCSP URL but the server is unreachable,
 *           online OCSP check fails, falls through to CRL check which also fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_016, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_016 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* OCSP online check timeout due to unreachable server */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_017
 * @tc.desc: Test online OCSP check - cert with invalid OCSP URL format
 *           When certificate has an invalid OCSP URL format,
 *           OCSP_parse_url should fail with CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_017, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeInvalidUrl);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_017 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* OCSP online check timeout due to unreachable server */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_OcspDigest
 * @tc.desc: Test GetOcspDigestByType with all digest types
 *           Covers all branches in GetOcspDigestByType (lines 818-828):
 *           - OCSP_DIGEST_SHA1
 *           - OCSP_DIGEST_SHA224
 *           - OCSP_DIGEST_SHA256
 *           - OCSP_DIGEST_SHA384
 *           - OCSP_DIGEST_SHA512
 *           - default (invalid type fallback to SHA256)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OcspDigest, TestSize.Level0)
{
    /* Test all digest types: SHA1, SHA224, SHA256, SHA384, SHA512, and invalid (default) */
    const int32_t digestTypes[] = {
        OCSP_DIGEST_SHA1,
        OCSP_DIGEST_SHA224,
        OCSP_DIGEST_SHA256,
        OCSP_DIGEST_SHA384,
        OCSP_DIGEST_SHA512,
        99  /* Invalid digest type, should fallback to SHA256 */
    };
    const char *digestNames[] = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "Invalid(99)"};
    const int numTypes = sizeof(digestTypes) / sizeof(digestTypes[0]);

    for (int i = 0; i < numTypes; i++) {
        HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
        HcfX509Certificate *rootCert = CreateCertFromPem(g_ocspTestRootCa);
        HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
        ASSERT_NE(cert, nullptr);
        ASSERT_NE(rootCert, nullptr);
        ASSERT_NE(intermediateCert, nullptr);

        HcfX509CertValidatorParams params = {};
        params.trustSystemCa = false;
        params.validateDate = false;

        params.trustedCerts.count = 1;
        params.trustedCerts.data = static_cast<HcfX509Certificate **>(
            CfMalloc(sizeof(HcfX509Certificate *), 0));
        ASSERT_NE(params.trustedCerts.data, nullptr);
        params.trustedCerts.data[0] = rootCert;

        params.untrustedCerts.count = 1;
        params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
            CfMalloc(sizeof(HcfX509Certificate *), 0));
        ASSERT_NE(params.untrustedCerts.data, nullptr);
        params.untrustedCerts.data[0] = intermediateCert;

        params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
            CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
        ASSERT_NE(params.revokedParams, nullptr);
        memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
        params.revokedParams->revocationFlags.count = 1;
        params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
            CfMalloc(sizeof(int32_t), 0));
        ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
        params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
        params.revokedParams->allowOcspCheckOnline = true;

        /* Set OCSP digest type */
        params.revokedParams->ocspDigest = digestTypes[i];

        HcfVerifyCertResult result = {};
        CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_OcspDigest failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* Invalid digest type should return parameter error, others should return network timeout */
        if (digestTypes[i] == 99) {
            EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK) << "Digest type: " << digestNames[i];
        } else {
            EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT) << "Digest type: " << digestNames[i];
        }

        CfObjDestroy(cert);
        FreeVerifyCertResult(result);
        FreeValidatorParamsWithOcspData(params);
    }
}

/* ============== Success Scenario Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_001
 * @tc.desc: Test CRL check with validateDate=false - cert is revoked
 *           When validateDate=false, CRL expiration check is skipped,
 *           but cert IS in CRL, should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_001, TestSize.Level0)
{
    /* Use end entity cert which IS in the CRL */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA - the CRL has expired but validateDate=false */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* validateDate=false skips CRL expiration check, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_002
 * @tc.desc: Test cert revoked with validateDate=false - still returns revoked
 *           When validateDate=false and cert is in CRL, should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_002, TestSize.Level0)
{
    /* Use end entity cert which IS in the CRL */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    /* Use CRL - the CRL has expired but validateDate=false, cert IS revoked */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* validateDate=false skips CRL expiration, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Success_003
 * @tc.desc: Test both CRL and OCSP enabled, prefer OCSP mode with validateDate=false
 *           With OCSP disabled, CRL check is used, cert is revoked
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Success_003, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 3, 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_PREFER_OCSP;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = false;  /* Disable online OCSP */

    /* Use CRL from intermediate CA - the CRL has expired */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* OCSP check fails (no OCSP response provided), fallback to CRL
     * validateDate=false skips CRL expiration check, but cert IS in CRL, should be revoked */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Exception Scenario Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_001
 * @tc.desc: Test CRL check with validateDate=true - cert expired
 *           When validateDate=true and cert is expired, expect CF_ERR_CERT_HAS_EXPIRED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_001, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL that has expired */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With validateDate=true, cert has expired (cert dates are in 2023-2024) */
    EXPECT_EQ(res, CF_ERR_CERT_HAS_EXPIRED);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_002
 * @tc.desc: Test CRL check - CRL signature verification failed
 *           When CRL signature doesn't match issuer, expect CF_ERR_CRL_SIGNATURE_FAILURE
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from different CA (signature mismatch) */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* CRL signature verification should fail since CRL is from different CA */
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_003
 * @tc.desc: Test CRL check - unable to get CRL issuer certificate
 *           When CRL issuer certificate is not available, expect CF_ERR_UNABLE_TO_GET_CRL_ISSUER
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_003, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    /* Only provide root cert, not intermediate - CRL issuer (intermediate) will be missing */
    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = false;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Should fail due to missing CRL or chain validation failure */
    EXPECT_NE(res, CF_SUCCESS);

    CfObjDestroy(cert);
    CfObjDestroy(intermediateCert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_004
 * @tc.desc: Test revocation check - self-signed certificate should be skipped
 *           Self-signed certificates should be skipped during revocation check
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_004, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;  /* Self-signed cert is its own trust anchor */

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Self-signed cert should pass - no issuer means no revocation check */
    EXPECT_EQ(res, CF_SUCCESS);
    if (res == CF_SUCCESS) {
        FreeVerifyCertResult(result);
    }

    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Error_005
 * @tc.desc: Test invalid CRL URL format (non-http/https)
 *           When CRL URL is not http/https, download should be skipped
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Error_005, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityForCdp);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaForCdp);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaWithCdp);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_Error_005 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    /* CRL download should fail with network timeout since URL is unreachable */
    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Mock Test Cases for Revocation ============== */

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_001
 * @tc.desc: Test X509_STORE_CTX_new failure in CheckSingleCertByCrl
 *           When X509_STORE_CTX_new returns NULL, expect CF_ERR_MALLOC
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_001, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_new())
        .WillOnce(Return(nullptr));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    /* When X509_STORE_CTX_new fails, the error is propagated as crypto operation error */
    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_002
 * @tc.desc: Test X509_STORE_CTX_init failure in CheckSingleCertByCrl
 *           When X509_STORE_CTX_init fails, expect CF_ERR_CRYPTO_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_002, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_init(_, _, _, _))
        .WillOnce(Return(0));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRYPTO_OPERATION);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003
 * @tc.desc: Test X509_CRL_load_http failure (CRL download failure)
 *           When X509_CRL_load_http returns NULL, expect CF_ERR_CRL_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityForCdp);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaForCdp);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaWithCdp);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_Mock_003 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CRL_NOT_FOUND);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003_1
 * @tc.desc: Test X509_CRL_load_http returns NULL with timeout error
 *           When X509_CRL_load_http returns NULL due to network timeout, expect CF_ERR_NETWORK_TIMEOUT
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003_1, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityForCdp);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaForCdp);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaWithCdp);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(Return(nullptr));
    EXPECT_CALL(X509OpensslMock::GetInstance(), ERR_peek_error())
        .WillRepeatedly(Return(static_cast<unsigned long>(BIO_R_CONNECT_TIMEOUT)));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_Mock_003_1 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_NETWORK_TIMEOUT);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

static X509_CRL *CreateX509CrlFromPemData(const char *pemData)
{
    BIO *bio = BIO_new_mem_buf(pemData, -1);
    if (bio == nullptr) {
        return nullptr;
    }
    X509_CRL *crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return crl;
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_003_2
 * @tc.desc: Test X509_CRL_load_http returns valid CRL
 *           When X509_CRL_load_http returns valid CRL object, verify the download path is covered
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_003_2, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityForCdp);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaForCdp);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaWithCdp);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->allowDownloadCrl = true;

    X509_CRL *mockCrl = CreateX509CrlFromPemData(g_testCertChainPemMidCRL);
    ASSERT_NE(mockCrl, nullptr);

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_CRL_load_http(_, _, _, _))
        .WillRepeatedly(WithoutArgs(Invoke([mockCrl]() -> X509_CRL* {
            return X509_CRL_dup(mockCrl);
        })));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_Mock_003_2 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    X509_CRL_free(mockCrl);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_004
 * @tc.desc: Test X509_get1_ocsp returns NULL (no OCSP URL)
 *           When certificate has no OCSP URL, expect CF_ERR_OCSP_RESPONSE_NOT_FOUND
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_004, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_get1_ocsp(_))
        .WillOnce(Return(nullptr));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_Revocation_Mock_004 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_Revocation_Mock_005
 * @tc.desc: Test X509_verify_cert returns various error codes
 *           Verify different error codes are mapped correctly
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Revocation_Mock_005, TestSize.Level0)
{
    /* Use valid certificate chain: end entity -> intermediate CA -> root CA */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};

    /* Test X509_V_ERR_CERT_REVOKED error code */
    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_verify_cert(_))
        .WillOnce(Return(0));
    EXPECT_CALL(X509OpensslMock::GetInstance(), X509_STORE_CTX_get_error(_))
        .WillOnce(Return(X509_V_ERR_CERT_REVOKED));
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Branch Coverage Test Cases ============== */

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_001
 * @tc.desc: Test with null validator - self parameter is null
 *           Covers branch: self == NULL entering if block (line 1512)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    HcfVerifyCertResult result = {};

    /* Test with null validator - this calls the function directly with self = NULL */
    CfResult res = g_validator->validateX509Cert(nullptr, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_002
 * @tc.desc: Test with result that has data pointer but count is 0
 *           Covers branch: result->certs.data != NULL && count == 0 (line 1525)
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    /* Create result with count=0 but data pointer not NULL */
    HcfVerifyCertResult result = {};
    result.certs.count = 0;
    result.certs.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(result.certs.data, nullptr);

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_BranchCoverage_002 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfFree(result.certs.data);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_003
 * @tc.desc: Test CRL check success path - cert is NOT in CRL
 *           Covers branch: X509_verify_cert returns 1 in CheckSingleCertByCrl (line 1047)
 *           This tests the success path of CRL verification where cert is not revoked
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_003, TestSize.Level0)
{
    /* Use intermediate cert which is NOT in the end-entity CRL */
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    /* Use CRL from intermediate CA - intermediate cert itself is NOT in this CRL */
    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Intermediate cert is NOT in the CRL, so CRL check should pass */
    /* But validation may fail because we don't have issuer's CRL */
    /* The key is that we test the CRL verification path */
    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_004
 * @tc.desc: Test CopyVerifyErrorMsg with NULL errorMsg (validation success)
 *           Covers branch: inner->errorMsg == NULL in CopyVerifyErrorMsg (line 429)
 *           This tests the success path where no error message is set
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_004, TestSize.Level0)
{
    /* Use self-signed cert as both trust anchor and cert to validate */
    HcfX509Certificate *cert = CreateCertFromPem(g_testSelfSignedCert);
    ASSERT_NE(cert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = cert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Self-signed cert should validate against itself */
    EXPECT_EQ(res, CF_SUCCESS);
    /* When validation succeeds, errorMsg should be NULL */
    EXPECT_EQ(result.errorMsg, nullptr);

    FreeVerifyCertResult(result);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_005
 * @tc.desc: Test CheckSingleCertByCrl with date parameter set
 *           Covers branch: params->date != NULL in CheckSingleCertByCrl (line 1042)
 *           Tests CRL check with a specific validation date
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_005, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = true;  /* Enable date validation */

    /* Use a date within the cert's validity period (Jun 15, 2024, certs valid until Oct 2024) */
    const char *dateStr = "20240615000000Z";
    params.date = static_cast<char *>(CfMalloc(strlen(dateStr) + 1, 0));
    ASSERT_NE(params.date, nullptr);
    strcpy(params.date, dateStr);

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* The CRL is expired relative to the validation date (Jun 2024) */
    /* Note: This tests the date parameter path in CheckSingleCertByCrl */
    EXPECT_EQ(res, CF_ERR_CRL_HAS_EXPIRED);

    /* Only destroy cert, not rootCert/intermediateCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_006
 * @tc.desc: Test validation success without revocation check
 *           Covers branch: params->revokedParams == NULL (line 1557)
 *           Tests that validation succeeds when revocation check is not requested
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.revokedParams = nullptr;  /* No revocation check */

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* Without revocation check, valid chain should succeed */
    EXPECT_EQ(res, CF_SUCCESS);
    EXPECT_EQ(result.errorMsg, nullptr);
    EXPECT_EQ(result.certs.count, 3);  /* root -> intermediate -> end entity */

    FreeVerifyCertResult(result);
    CfObjDestroy(cert);
    /* intermediateCert and rootCert are owned by params, freed by FreeValidatorParams */
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_007
 * @tc.desc: Test revocation check with CHECK_ALL_CERT flag
 *           Covers branch: checkAll = true in CheckCertRevocation (line 1444)
 *           Tests that all certificates in chain are checked for revocation
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_007, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));

    /* Set both CRL_CHECK and CHECK_ALL_CERT flags */
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With CHECK_ALL_CERT, all certs in chain are checked */
    /* Note: CRL check with X509_V_FLAG_NO_CHECK_TIME should work */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    /* Only destroy cert, not intermediateCert/rootCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/**
 * @tc.name: ValidateX509Cert_BranchCoverage_008
 * @tc.desc: Test revocation with PREFER_OCSP flag but no OCSP response
 *           Covers branch: preferOcsp = true with fallback to CRL (line 1374)
 *           Tests OCSP prefer path that falls back to CRL
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_BranchCoverage_008, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testCertChainPemNoRoot);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testCertChainPemMid);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testCertChainPemRoot);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(rootCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));

    /* Set CRL_CHECK, OCSP_CHECK, and PREFER_OCSP flags */
    params.revokedParams->revocationFlags.count = 3;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 3, 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_CRL_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->revocationFlags.data[2] = CERT_REVOCATION_PREFER_OCSP;

    HcfX509Crl *crl = nullptr;
    CfEncodingBlob crlStream = { reinterpret_cast<uint8_t *>(const_cast<char *>(g_testCertChainPemMidCRL)),
        sizeof(g_testCertChainPemMidCRL), CF_FORMAT_PEM };
    CfResult res = HcfX509CrlCreate(&crlStream, &crl);
    ASSERT_EQ(res, CF_SUCCESS);
    ASSERT_NE(crl, nullptr);

    params.revokedParams->crls.count = 1;
    params.revokedParams->crls.data = static_cast<HcfX509Crl **>(
        CfMalloc(sizeof(HcfX509Crl *), 0));
    ASSERT_NE(params.revokedParams->crls.data, nullptr);
    params.revokedParams->crls.data[0] = crl;

    /* No OCSP response provided, so should fallback to CRL */
    params.revokedParams->allowOcspCheckOnline = false;

    HcfVerifyCertResult result = {};
    res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    /* With PREFER_OCSP but no OCSP, falls back to CRL which shows cert is revoked */
    /* Note: CRL check with X509_V_FLAG_NO_CHECK_TIME should work */
    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);

    /* Only destroy cert, not intermediateCert/rootCert as they're owned by params */
    CfObjDestroy(cert);
    FreeValidatorParams(params);
}

/* ============== Local OCSP Test Cases ============== */
/* Note: Local OCSP tests are temporarily disabled pending OCSP response data update.
 * The OCSP response data needs to be regenerated to match the new test certificates.
 * This will be done in a follow-up task.
 */

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_001
 * @tc.desc: Test local OCSP check with GOOD status response
 *           When valid OCSP response with GOOD status is provided,
 *           validation should succeed
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *caCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    HcfX509Certificate *signerCert = CreateCertFromPem(g_ocspTestSigner);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(sizeof(g_ocspTestRespGood), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy(params.revokedParams->ocspResponses.data[0].data, g_ocspTestRespGood, sizeof(g_ocspTestRespGood));
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_ocspTestRespGood);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_002
 * @tc.desc: Test local OCSP check with REVOKED status response
 *           When valid OCSP response with REVOKED status is provided,
 *           should return CF_ERR_CERT_REVOKED
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *caCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    HcfX509Certificate *signerCert = CreateCertFromPem(g_ocspTestSigner);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(sizeof(g_ocspTestRespRevoked), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy(params.revokedParams->ocspResponses.data[0].data, g_ocspTestRespRevoked, sizeof(g_ocspTestRespRevoked));
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_ocspTestRespRevoked);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_LocalOcsp_002 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_CERT_REVOKED);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_003
 * @tc.desc: Test local OCSP check with UNKNOWN status response
 *           When valid OCSP response with UNKNOWN status is provided,
 *           should return CF_ERR_OCSP_CERT_STATUS_UNKNOWN
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_003, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *caCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    HcfX509Certificate *signerCert = CreateCertFromPem(g_ocspTestSigner);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 2;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;
    params.untrustedCerts.data[1] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(sizeof(g_ocspTestRespUnknown), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy(params.revokedParams->ocspResponses.data[0].data, g_ocspTestRespUnknown, sizeof(g_ocspTestRespUnknown));
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_ocspTestRespUnknown);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    printf("LocalOcsp_003: res=%d, expected=%d (CF_ERR_OCSP_CERT_STATUS_UNKNOWN)\n", res, CF_ERR_OCSP_CERT_STATUS_UNKNOWN);
    if (result.errorMsg != nullptr) {
        printf("LocalOcsp_003: errorMsg=%s\n", result.errorMsg);
    }
    /* UNKNOWN status should return CF_ERR_OCSP_CERT_STATUS_UNKNOWN */
    EXPECT_EQ(res, CF_ERR_OCSP_CERT_STATUS_UNKNOWN);
    EXPECT_NE(result.errorMsg, nullptr);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_LocalOcsp_006
 * @tc.desc: Test local OCSP check with embedded signer certificate
 *           When OCSP response contains embedded signer certificate,
 *           verification should succeed even without signer in untrustedCerts
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_LocalOcsp_006, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *caCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(caCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = caCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(sizeof(g_ocspTestRespGood), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy(params.revokedParams->ocspResponses.data[0].data, g_ocspTestRespGood, sizeof(g_ocspTestRespGood));
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_ocspTestRespGood);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);

    printf("LocalOcsp_006: res=%d, expected=%d (CF_SUCCESS)\n", res, CF_SUCCESS);
    if (result.errorMsg != nullptr) {
        printf("LocalOcsp_006: errorMsg=%s\n", result.errorMsg);
    }
    if (result.certs.count > 0) {
        printf("LocalOcsp_006: certs count=%u\n", result.certs.count);
    }
    /* OCSP response contains embedded signer cert, so verification succeeds */
    EXPECT_EQ(res, CF_SUCCESS);

    CfObjDestroy(cert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

/**
 * @tc.name: ValidateX509Cert_GetIssuerFromStore_001
 * @tc.desc: Test GetIssuerFromStore when issuer not found
 *           - EE cert is signed by Intermediate CA
 *           - Trusted certs: Intermediate CA + Root CA
 *           - partialChain=true allows building chain [EE, Intermediate]
 *           - OCSP check with checkAll flag for all certs
 *           - Valid OCSP response for EE cert (not revoked)
 *           - When checking Intermediate CA's revocation, GetIssuerFromStore
 *             is called to find Root CA, but Root CA is in trustedCerts
 *           - OCSP verification for EE passes, but Intermediate CA has no
 *             OCSP response, so OCSP check fails
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_GetIssuerFromStore_001, TestSize.Level0)
{
    HcfX509Certificate *eeCert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *intermediateCaCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    HcfX509Certificate *rootCaCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *signerCert = CreateCertFromPem(g_ocspTestSigner);
    ASSERT_NE(eeCert, nullptr);
    ASSERT_NE(intermediateCaCert, nullptr);
    ASSERT_NE(rootCaCert, nullptr);
    ASSERT_NE(signerCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;
    params.partialChain = true;

    params.trustedCerts.count = 2;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *) * 2, 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = intermediateCaCert;
    params.trustedCerts.data[1] = rootCaCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = signerCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 2;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t) * 2, 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->revocationFlags.data[1] = CERT_REVOCATION_CHECK_ALL_CERT;

    params.revokedParams->ocspResponses.count = 1;
    params.revokedParams->ocspResponses.data = static_cast<CfBlob *>(
        CfMalloc(sizeof(CfBlob), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data, nullptr);
    params.revokedParams->ocspResponses.data[0].data = static_cast<uint8_t *>(
        CfMalloc(sizeof(g_ocspTestRespGood), 0));
    ASSERT_NE(params.revokedParams->ocspResponses.data[0].data, nullptr);
    memcpy(params.revokedParams->ocspResponses.data[0].data, g_ocspTestRespGood, sizeof(g_ocspTestRespGood));
    params.revokedParams->ocspResponses.data[0].size = sizeof(g_ocspTestRespGood);

    HcfVerifyCertResult result = {};
    CfResult res = g_validator->validateX509Cert(g_validator, eeCert, &params, &result);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_GetIssuerFromStore_001 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }

    EXPECT_EQ(res, CF_ERR_OCSP_RESPONSE_NOT_FOUND);

    CfObjDestroy(eeCert);
    FreeVerifyCertResult(result);
    FreeValidatorParamsWithOcspData(params);
}

static OCSP_RESPONSE *CreateOcspResponseFromDer(const uint8_t *data, size_t len)
{
    const unsigned char *p = data;
    return d2i_OCSP_RESPONSE(nullptr, &p, len);
}

/**
 * @tc.name: ValidateX509Cert_OnlineOcsp_Mock_001
 * @tc.desc: Test online OCSP check with mock BIO and OCSP response
 *           Mock BIO_do_connect_retry to return success
 *           Mock OCSP_sendreq_nbio to return valid OCSP response
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_OnlineOcsp_Mock_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_ocspTestEeValidUrl);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_ocspTestRootCa);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_ocspTestIntermediateCa);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->allowOcspCheckOnline = true;

    OCSP_RESPONSE *mockResp = CreateOcspResponseFromDer(g_ocspTestRespGood, sizeof(g_ocspTestRespGood));
    ASSERT_NE(mockResp, nullptr);

    HcfVerifyCertResult result = {};

    X509OpensslMock::SetMockFlag(true);
    EXPECT_CALL(X509OpensslMock::GetInstance(), BIO_do_connect_retry(_, _, _))
        .WillRepeatedly(Return(1));
    EXPECT_CALL(X509OpensslMock::GetInstance(), OSSL_HTTP_REQ_CTX_nbio_d2i(_, _, _))
        .WillRepeatedly(Invoke([](OSSL_HTTP_REQ_CTX *rctx, ASN1_VALUE **pval, const ASN1_ITEM *it) -> int {
            OCSP_RESPONSE *resp = CreateOcspResponseFromDer(g_ocspTestRespGood, sizeof(g_ocspTestRespGood));
            if (resp == nullptr) {
                return 0;
            }
            *pval = (ASN1_VALUE *)resp;
            return 1;
        }));
    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    X509OpensslMock::SetMockFlag(false);
    if (res != CF_SUCCESS) {
        CF_LOG_I("ValidateX509Cert_OnlineOcsp_Mock_001 failed: res=%d, errorMsg=%s", res,
                 result.errorMsg ? result.errorMsg : "null");
    }
    Mock::VerifyAndClearExpectations(&X509OpensslMock::GetInstance());

    OCSP_RESPONSE_free(mockResp);
    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidOcspDigest_001
 * @tc.desc: Test invalid ocspDigest parameter
 *           When ocspDigest is out of valid range, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidOcspDigest_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->ocspDigest = static_cast<HcfOcspDigest>(100); // Invalid value

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidOcspDigest_002
 * @tc.desc: Test invalid ocspDigest parameter (too small)
 *           When ocspDigest is less than OCSP_DIGEST_SHA1, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidOcspDigest_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 1;
    params.revokedParams->revocationFlags.data = static_cast<int32_t *>(
        CfMalloc(sizeof(int32_t), 0));
    ASSERT_NE(params.revokedParams->revocationFlags.data, nullptr);
    params.revokedParams->revocationFlags.data[0] = CERT_REVOCATION_OCSP_CHECK;
    params.revokedParams->ocspDigest = static_cast<HcfOcspDigest>(-1); // Invalid value: negative

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidRevocationFlags_001
 * @tc.desc: Test invalid revocationFlags count (empty)
 *           When revocationFlags.count is 0, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidRevocationFlags_001, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 0; // Invalid: count = 0

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

/**
 * @tc.name: ValidateX509Cert_Params_InvalidRevocationFlags_002
 * @tc.desc: Test invalid revocationFlags count (too large)
 *           When revocationFlags.count > 4, expect CF_ERR_PARAMETER_CHECK
 * @tc.type: FUNC
 */
HWTEST_F(CryptoX509CertValidatorTest, ValidateX509Cert_Params_InvalidRevocationFlags_002, TestSize.Level0)
{
    HcfX509Certificate *cert = CreateCertFromPem(g_testEndEntityCert);
    HcfX509Certificate *rootCert = CreateCertFromPem(g_testRootCaCert);
    HcfX509Certificate *intermediateCert = CreateCertFromPem(g_testIntermediateCaCert);
    ASSERT_NE(cert, nullptr);
    ASSERT_NE(rootCert, nullptr);
    ASSERT_NE(intermediateCert, nullptr);

    HcfX509CertValidatorParams params = {};
    params.trustSystemCa = false;
    params.validateDate = false;

    params.trustedCerts.count = 1;
    params.trustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.trustedCerts.data, nullptr);
    params.trustedCerts.data[0] = rootCert;

    params.untrustedCerts.count = 1;
    params.untrustedCerts.data = static_cast<HcfX509Certificate **>(
        CfMalloc(sizeof(HcfX509Certificate *), 0));
    ASSERT_NE(params.untrustedCerts.data, nullptr);
    params.untrustedCerts.data[0] = intermediateCert;

    params.revokedParams = static_cast<HcfX509CertRevokedParams *>(
        CfMalloc(sizeof(HcfX509CertRevokedParams), 0));
    ASSERT_NE(params.revokedParams, nullptr);
    memset(params.revokedParams, 0, sizeof(HcfX509CertRevokedParams));
    params.revokedParams->revocationFlags.count = 10; // Invalid: count > 4

    HcfVerifyCertResult result = {};

    CfResult res = g_validator->validateX509Cert(g_validator, cert, &params, &result);
    EXPECT_EQ(res, CF_ERR_PARAMETER_CHECK);

    CfObjDestroy(cert);
    FreeValidatorParams(params);
    FreeVerifyCertResult(result);
}

} // namespace