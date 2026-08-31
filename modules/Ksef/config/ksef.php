<?php

return [
    // Operator's NIP (TIN) — the taxpayer whose invoices are sent.
    'nip' => null,

    // KSeF environment: 'demo' or 'prod'.
    'environment' => 'demo',

    // API endpoints. The demo/test environment is the official MF test box.
    'endpoints' => [
        'demo' => 'https://ksef-demo.mf.gov.pl/api',
        'prod' => 'https://ksef.mf.gov.pl/api',
    ],

    // Token / key material used to authenticate with KSeF.
    'token' => null,
    'key_path' => null,
    'cert_path' => null,

    // HTTP tuning.
    'http' => [
        'connect_timeout' => 10,
        'request_timeout' => 60,
    ],

    // Only these invoice statuses are ever considered for KSeF submission.
    // Invoices are handed over once paid, so this is effectively ['paid'].
    'send_statuses' => ['paid'],
];
