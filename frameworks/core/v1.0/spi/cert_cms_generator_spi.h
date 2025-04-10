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

#ifndef CERT_CMS_GENERATOR_SPI_H
#define CERT_CMS_GENERATOR_SPI_H

#include "cf_blob.h"
#include "cf_object_base.h"
#include "cf_result.h"
#include "x509_certificate.h"
#include "cert_cms_generator.h"

typedef struct HcfCmsGeneratorSpi HcfCmsGeneratorSpi;

struct HcfCmsGeneratorSpi {
    CfObjectBase base;
    /** add signer to cms generator. */
    CfResult (*engineAddSigner)(HcfCmsGeneratorSpi *self, const HcfCertificate *x509Cert,
                                const PrivateKeyInfo *privateKey, const HcfCmsSignerOptions *options);
    /** add other certificate to cms generator. */
    CfResult (*engineAddCert)(HcfCmsGeneratorSpi *self, const HcfCertificate *x509Cert);
    /** do final to cms generator. */
    CfResult (*engineDoFinal)(HcfCmsGeneratorSpi *self, const CfBlob *content, const HcfCmsGeneratorOptions *options,
                              CfBlob *out);
};

#endif // CERT_CMS_GENERATOR_SPI_H
