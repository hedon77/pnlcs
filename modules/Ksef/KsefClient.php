<?php

namespace Modules\Ksef;

use App\Models\Invoice;
use App\Models\KsefInvoice;
use Illuminate\Support\Facades\Http;
use Modules\Ksef\Support\InvoiceXmlBuilder;

/**
 * HTTP client for the KSeF 2.0 API.
 *
 * KSeF 2.0 authenticates with a certificate issued by the MCU module
 * (qualified electronic seal / signature), not the KSeF 1.0 token. The flow
 * is a challenge/response exchange:
 *
 *   1. AuthorisationChallenge  →  get a challenge + timestamp
 *   2. sign challenge|timestamp with the private key (RSA-SHA256)
 *   3. AuthorisationToken      →  exchange the signature for a session token
 *   4. Invoice/Send            →  send the FA XML with the session token
 *
 * Endpoints are configurable per environment; verify the exact hosts and
 * field names against the official OpenAPI contract (ksef.podatki.gov.pl).
 */
class KsefClient
{
    public function __construct(protected InvoiceXmlBuilder $xml) {}

    /**
     * Test the connection and credentials by running the KSeF 2.0
     * authentication exchange (challenge → sign → token).
     *
     * @return array{success: bool, message: string}
     */
    public function testConnection(): array
    {
        $settings = KsefSettings::resolve();

        if (! $this->hasCredentials($settings)) {
            return ['success' => false, 'message' => __('messages.ksef.missing_credentials')];
        }

        try {
            $token = $this->authenticate($settings);

            if ($token === '') {
                return ['success' => false, 'message' => __('messages.ksef.auth_failed')];
            }

            return ['success' => true, 'message' => __('messages.ksef.test_ok')];
        } catch (\Throwable $e) {
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }

    /**
     * @return array{success: bool, status?: string, ksef_number?: string, accepted?: bool, sent_at?: string, request_xml?: string, response_xml?: string, message?: string}
     */
    public function submit(Invoice $invoice, KsefInvoice $record): array
    {
        $settings = KsefSettings::resolve();

        $requestXml = $this->xml->build($invoice, (string) $settings['nip']);

        if (! $this->hasCredentials($settings)) {
            return [
                'success' => false,
                'request_xml' => $requestXml,
                'message' => __('messages.ksef.missing_credentials'),
            ];
        }

        try {
            $token = $this->authenticate($settings);
        } catch (\Throwable $e) {
            return [
                'success' => false,
                'request_xml' => $requestXml,
                'message' => $e->getMessage(),
            ];
        }

        $endpoint = rtrim((string) $settings['endpoint'], '/');

        $response = Http::withHeader('SessionToken', $token)
            ->accept('application/json')
            ->timeout((int) $settings['http']['request_timeout'])
            ->connectTimeout((int) $settings['http']['connect_timeout'])
            ->withBody(base64_encode($requestXml), 'application/octet-stream')
            ->post($endpoint.'/online/Invoice/Send');

        $responseXml = (string) $response->body();

        if (! $response->successful()) {
            return [
                'success' => false,
                'request_xml' => $requestXml,
                'response_xml' => $responseXml,
                'message' => __('messages.ksef.http_error', ['code' => $response->status()]),
            ];
        }

        $data = $response->json() ?? [];
        $ksefNumber = (string) ($data['referenceNumber'] ?? $data['ksefReferenceNumber'] ?? $data['elementReferenceNumber'] ?? '');

        return [
            'success' => true,
            'status' => 'sent',
            'ksef_number' => $ksefNumber ?: null,
            'accepted' => true,
            'sent_at' => now()->toDateTimeString(),
            'request_xml' => $requestXml,
            'response_xml' => $responseXml,
            'message' => __('messages.ksef.sent'),
        ];
    }

    /**
     * KSeF 2.0 challenge/response authentication.
     *
     * @param  array<string, mixed>  $settings
     */
    protected function authenticate(array $settings): string
    {
        $endpoint = rtrim((string) $settings['endpoint'], '/');
        $nip = (string) $settings['nip'];
        $key = $this->privateKey($settings);

        $context = ['contextIdentifier' => ['type' => 'onip', 'identifier' => $nip]];

        // 1. Challenge.
        $challenge = Http::accept('application/json')
            ->timeout((int) $settings['http']['request_timeout'])
            ->connectTimeout((int) $settings['http']['connect_timeout'])
            ->post($endpoint.'/online/Session/AuthorisationChallenge', $context)
            ->throw()
            ->json();

        $challengeValue = (string) ($challenge['challenge'] ?? '');
        $timestamp = (string) ($challenge['timestamp'] ?? '');

        // 2. Sign the challenge with the qualified seal's private key.
        $dataToSign = $challengeValue.'|'.$timestamp;
        $signature = '';
        if (! openssl_sign($dataToSign, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException(__('messages.ksef.sign_failed'));
        }

        // 3. Exchange the signature for a session token.
        $token = Http::accept('application/json')
            ->timeout((int) $settings['http']['request_timeout'])
            ->connectTimeout((int) $settings['http']['connect_timeout'])
            ->post($endpoint.'/online/Session/AuthorisationToken', $context + [
                'challenge' => $challengeValue,
                'timestamp' => $timestamp,
                'signature' => base64_encode($signature),
            ])
            ->throw()
            ->json();

        return (string) ($token['sessionToken']['token'] ?? $token['token'] ?? '');
    }

    /**
     * @param  array<string, mixed>  $settings
     */
    protected function privateKey(array $settings): \OpenSSLAsymmetricKey|string
    {
        $value = (string) ($settings['private_key'] ?? '');

        if ($value === '') {
            throw new \RuntimeException(__('messages.ksef.missing_credentials'));
        }

        // The setting holds the PEM text pasted into the addon config. If it
        // is not PEM, fall back to treating it as a file path on the server.
        $pem = str_contains($value, '-----BEGIN') ? $value : null;
        if ($pem === null && is_file($value)) {
            $pem = (string) file_get_contents($value);
        }

        if ($pem === null || $pem === '') {
            throw new \RuntimeException(__('messages.ksef.missing_key'));
        }

        $passphrase = (string) ($settings['private_key_passphrase'] ?? '');
        $key = $passphrase !== ''
            ? openssl_pkey_get_private($pem, $passphrase)
            : openssl_pkey_get_private($pem);

        if ($key === false) {
            // An encrypted key without (or with a wrong) passphrase is the
            // most common failure, so say so specifically.
            if (str_contains($pem, 'ENCRYPTED')) {
                throw new \RuntimeException(__('messages.ksef.key_passphrase'));
            }

            throw new \RuntimeException(__('messages.ksef.invalid_key'));
        }

        return $key;
    }

    /**
     * @param  array<string, mixed>  $settings
     */
    protected function hasCredentials(array $settings): bool
    {
        return filled($settings['nip'] ?? null) && filled($settings['private_key'] ?? null);
    }
}
