/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef X509_CERT_CHAIN_OEPNSSL_H
#define X509_CERT_CHAIN_OEPNSSL_H

#include "cf_result.h"
#include "x509_cert_chain_spi.h"
#include "x509_certificate.h"

#ifdef __cplusplus
extern "C" {
#endif

CfResult HcfX509CertChainByEncSpiCreate(const CfEncodingBlob *inStream, HcfX509CertChainSpi **spi);
CfResult HcfX509CertChainByArrSpiCreate(const HcfX509CertificateArray *inCerts, HcfX509CertChainSpi **spi);

#ifdef __cplusplus
}
#endif

#endif // X509_CERT_CHAIN_OEPNSSL_H