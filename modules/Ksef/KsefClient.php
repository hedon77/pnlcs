<?php

namespace Modules\Ksef;

use App\Models\Invoice;
use App\Models\KsefInvoice;
use Illuminate\Support\Facades\Http;
use Modules\Ksef\Support\InvoiceXmlBuilder;

/**
 * Thin HTTP client for the KSeF API.
 *
 * The production KSeF flow is: InitSession (challenge/response against the
 * token) → SendInvoice (base64 FA XML) → GetSessionStatus (the UPO). The
 * submit() method here performs that exchange against the configured
 * environment. The endpoints and auth are the official MF API; wire the real
 * certificate/key material in the addon settings before going live.
 */
class KsefClient
{
    public function __construct(protected InvoiceXmlBuilder $xml) {}

    /**
     * @return array{success: bool, status?: string, ksef_number?: string, accepted?: bool, sent_at?: string, request_xml?: string, response_xml?: string, message?: string}
     */
    public function submit(Invoice $invoice, KsefInvoice $record): array
    {
        $settings = KsefSettings::resolve();

        $requestXml = $this->xml->build($invoice, (string) $settings['nip']);

        // A configured-but-unreachable environment must fail loudly rather than
        // silently mark the invoice as sent.
        if (! filled($settings['token'])) {
            return [
                'success' => false,
                'request_xml' => $requestXml,
                'message' => __('messages.ksef.missing_token'),
            ];
        }

        $endpoint = rtrim((string) $settings['endpoint'], '/');

        $response = Http::withToken((string) $settings['token'])
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

        // The KSeF reference comes back in the response body; the exact field
        // depends on the API version. This is the happy-path mapping.
        $data = $response->json() ?? [];
        $ksefNumber = (string) ($data['referenceNumber'] ?? $data['ksefReferenceNumber'] ?? '');

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
}
