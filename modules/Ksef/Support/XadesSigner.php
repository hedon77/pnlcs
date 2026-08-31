<?php

namespace Modules\Ksef\Support;

use DOMDocument;
use DOMElement;
use DOMXPath;

/**
 * Produces an enveloped XAdES-BES signature for the KSeF 2.0 AuthTokenRequest.
 *
 * PHP's DOM C14N() provides inclusive XML canonicalization, which is one of the
 * transforms KSeF accepts. The signature is RSA-SHA256 over the canonicalized
 * SignedInfo; the certificate is embedded in KeyInfo and referenced from the
 * SigningCertificate qualifying property.
 */
class XadesSigner
{
    private const NS_DSIG = 'http://www.w3.org/2000/09/xmldsig#';
    private const NS_XADES = 'http://uri.etsi.org/01903/v1.3.2#';
    private const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    private const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
    private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    private const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';

    /**
     * Sign an AuthTokenRequest XML document with XAdES-BES.
     */
    public function sign(string $unsignedXml, string $privateKeyPem, ?string $passphrase, string $certificatePem): string
    {
        $key = $this->privateKey($privateKeyPem, $passphrase);
        $cert = $this->certificate($certificatePem);

        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = true;
        $doc->loadXML($unsignedXml);

        $root = $doc->documentElement;

        $signature = $doc->createElementNS(self::NS_DSIG, 'ds:Signature');
        $signature->setAttribute('Id', 'Signature');

        // QualifyingProperties is built first so its digest can be referenced.
        [$qualifyingProperties, $signedProperties] = $this->qualifyingProperties($doc, $cert);

        $signedInfo = $doc->createElementNS(self::NS_DSIG, 'ds:SignedInfo');

        $canonicalization = $doc->createElementNS(self::NS_DSIG, 'ds:CanonicalizationMethod');
        $canonicalization->setAttribute('Algorithm', self::C14N);
        $signedInfo->appendChild($canonicalization);

        $signatureMethod = $doc->createElementNS(self::NS_DSIG, 'ds:SignatureMethod');
        $signatureMethod->setAttribute('Algorithm', self::RSA_SHA256);
        $signedInfo->appendChild($signatureMethod);

        // Root reference (URI="") — enveloped, digest over the whole document
        // excluding the Signature element itself.
        $signedInfo->appendChild($this->reference($doc, '', [
            self::ENVELOPED,
            self::C14N,
        ], $this->digestOfDocumentWithoutSignature($root, $signature)));

        // SignedProperties reference.
        $signedInfo->appendChild($this->reference($doc, '#SignedProperties', [
            self::C14N,
        ], $this->digestOfNode($signedProperties)));

        $signature->appendChild($signedInfo);

        // Canonicalize SignedInfo and sign it.
        $signedInfoC14n = $signedInfo->C14N(false, false);
        openssl_sign($signedInfoC14n, $signatureValue, $key, OPENSSL_ALGO_SHA256);

        $sigValue = $doc->createElementNS(self::NS_DSIG, 'ds:SignatureValue');
        $sigValue->nodeValue = base64_encode($signatureValue);
        $signature->appendChild($sigValue);

        // KeyInfo with the X.509 certificate.
        $keyInfo = $doc->createElementNS(self::NS_DSIG, 'ds:KeyInfo');
        $x509Data = $doc->createElementNS(self::NS_DSIG, 'ds:X509Data');
        $x509Cert = $doc->createElementNS(self::NS_DSIG, 'ds:X509Certificate');
        $x509Cert->nodeValue = base64_encode($cert['der']);
        $x509Data->appendChild($x509Cert);
        $keyInfo->appendChild($x509Data);
        $signature->appendChild($keyInfo);

        // Object wrapping the QualifyingProperties.
        $object = $doc->createElementNS(self::NS_DSIG, 'ds:Object');
        $object->appendChild($qualifyingProperties);
        $signature->appendChild($object);

        $root->appendChild($signature);

        return $doc->saveXML();
    }

    /** @return array{der: string, digest: string, issuer: string, serial: string} */
    private function certificate(string $pem): array
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);
        $der = (string) base64_decode((string) $body);

        $parsed = openssl_x509_parse($pem);

        return [
            'der' => $der,
            'digest' => base64_encode(hash('sha256', $der, true)),
            'issuer' => $this->formatDn($parsed['issuer'] ?? []),
            'serial' => $this->hexToDec((string) ($parsed['serialNumber'] ?? '0')),
        ];
    }

    private function privateKey(string $pem, ?string $passphrase): \OpenSSLAsymmetricKey|string
    {
        $key = $passphrase !== null && $passphrase !== ''
            ? openssl_pkey_get_private($pem, $passphrase)
            : openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new \RuntimeException(__('messages.ksef.invalid_key'));
        }

        return $key;
    }

    /** @return array{0: DOMElement, 1: DOMElement} [QualifyingProperties, SignedProperties] */
    private function qualifyingProperties(DOMDocument $doc, array $cert): array
    {
        $qp = $doc->createElementNS(self::NS_XADES, 'xades:QualifyingProperties');
        $qp->setAttribute('Target', '#Signature');

        $signedProps = $doc->createElementNS(self::NS_XADES, 'xades:SignedProperties');
        $signedProps->setAttribute('Id', 'SignedProperties');
        $signedProps->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xades', self::NS_XADES);
        $signedProps->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', self::NS_DSIG);

        $signedSigProps = $doc->createElementNS(self::NS_XADES, 'xades:SignedSignatureProperties');

        $signingTime = $doc->createElementNS(self::NS_XADES, 'xades:SigningTime', gmdate('Y-m-d\TH:i:s\Z'));
        $signedSigProps->appendChild($signingTime);

        $signingCert = $doc->createElementNS(self::NS_XADES, 'xades:SigningCertificate');
        $certEl = $doc->createElementNS(self::NS_XADES, 'xades:Cert');

        $certDigest = $doc->createElementNS(self::NS_XADES, 'xades:CertDigest');
        $digestMethod = $doc->createElementNS(self::NS_DSIG, 'ds:DigestMethod');
        $digestMethod->setAttribute('Algorithm', self::SHA256);
        $digestValue = $doc->createElementNS(self::NS_DSIG, 'ds:DigestValue', $cert['digest']);
        $certDigest->appendChild($digestMethod);
        $certDigest->appendChild($digestValue);
        $certEl->appendChild($certDigest);

        $issuerSerial = $doc->createElementNS(self::NS_XADES, 'xades:IssuerSerial');
        $issuerName = $doc->createElementNS(self::NS_DSIG, 'ds:X509IssuerName', $cert['issuer']);
        $serial = $doc->createElementNS(self::NS_DSIG, 'ds:X509SerialNumber', $cert['serial']);
        $issuerSerial->appendChild($issuerName);
        $issuerSerial->appendChild($serial);
        $certEl->appendChild($issuerSerial);

        $signingCert->appendChild($certEl);
        $signedSigProps->appendChild($signingCert);

        $signedProps->appendChild($signedSigProps);
        $qp->appendChild($signedProps);

        return [$qp, $signedProps];
    }

    private function reference(DOMDocument $doc, string $uri, array $transforms, string $digest): DOMElement
    {
        $ref = $doc->createElementNS(self::NS_DSIG, 'ds:Reference');
        $ref->setAttribute('URI', $uri);
        if ($uri === '#SignedProperties') {
            $ref->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
        }

        $transformsEl = $doc->createElementNS(self::NS_DSIG, 'ds:Transforms');
        foreach ($transforms as $algorithm) {
            $t = $doc->createElementNS(self::NS_DSIG, 'ds:Transform');
            $t->setAttribute('Algorithm', $algorithm);
            $transformsEl->appendChild($t);
        }
        $ref->appendChild($transformsEl);

        $dm = $doc->createElementNS(self::NS_DSIG, 'ds:DigestMethod');
        $dm->setAttribute('Algorithm', self::SHA256);
        $ref->appendChild($dm);

        $dv = $doc->createElementNS(self::NS_DSIG, 'ds:DigestValue', $digest);
        $ref->appendChild($dv);

        return $ref;
    }

    /**
     * Digest of the document root, excluding the (not yet appended) Signature
     * element — this is the enveloped-signature transform applied by hand.
     */
    private function digestOfDocumentWithoutSignature(DOMElement $root, DOMElement $signature): string
    {
        $clone = $root->ownerDocument->cloneNode(true);
        $xpath = new DOMXPath($clone);
        $xpath->registerNamespace('ds', self::NS_DSIG);
        $nodes = $xpath->query('//ds:Signature');
        foreach ($nodes as $node) {
            $node->parentNode->removeChild($node);
        }
        $c14n = $clone->documentElement->C14N(false, false);

        return base64_encode(hash('sha256', $c14n, true));
    }

    private function digestOfNode(DOMElement $node): string
    {
        return base64_encode(hash('sha256', $node->C14N(false, false), true));
    }

    private function formatDn(array $issuer): string
    {
        $parts = [];
        foreach ($issuer as $k => $v) {
            $parts[] = $k.'='.$v;
        }

        return implode(', ', $parts);
    }

    private function hexToDec(string $hex): string
    {
        $hex = ltrim($hex, "0 \t\n\r\0\x0B");
        if ($hex === '') {
            return '0';
        }
        $hex = strtoupper($hex);

        $dec = '0';
        $map = '0123456789ABCDEF';
        $len = strlen($hex);
        for ($i = 0; $i < $len; $i++) {
            $dec = self::decMulAdd($dec, 16, strpos($map, $hex[$i]));
        }

        return $dec;
    }

    private static function decMulAdd(string $num, int $mul, int $add): string
    {
        $carry = $add;
        $result = '';
        for ($i = strlen($num) - 1; $i >= 0; $i--) {
            $digit = (int) $num[$i] * $mul + $carry;
            $result = ($digit % 10).$result;
            $carry = intdiv($digit, 10);
        }
        while ($carry > 0) {
            $result = ($carry % 10).$result;
            $carry = intdiv($carry, 10);
        }

        return ltrim($result, '0') ?: '0';
    }
}
