<?php

return [
    // Operator's NIP (TIN) — the taxpayer whose invoices are sent.
    'nip' => null,

    // KSeF 2.0 environment: 'integration', 'demo' or 'prod'.
    //   - integration: anonymised test data, no legal effect.
    //   - demo:        pre-production, real auth (MCU), no legal effect.
    //   - prod:        production, real invoices.
    'environment' => 'integration',

    // KSeF 2.0 API endpoints. Verify the exact hosts against the official
    // OpenAPI contract (ksef.podatki.gov.pl → wsparcie dla integratorów).
    'endpoints' => [
        'integration' => 'https://ksef-test.mf.gov.pl/api',
        'demo' => 'https://ksef-demo.mf.gov.pl/api',
        'prod' => 'https://ksef.mf.gov.pl/api',
    ],

    // KSeF 2.0 authenticates with a certificate issued by the MCU module
    // (qualified electronic seal / signature), NOT the KSeF 1.0 token. The
    // private key and certificate are pasted into the addon settings (stored
    // encrypted); the key signs the authorisation challenge.
    'private_key' => null,
    'certificate' => null,

    // HTTP tuning.
    'http' => [
        'connect_timeout' => 10,
        'request_timeout' => 60,
    ],

    // Only these invoice statuses are ever considered for KSeF submission.
    // Invoices are handed over once paid, so this is effectively ['paid'].
    'send_statuses' => ['paid'],
];
