<?php

namespace Modules\Ksef\Support;

use App\Models\Invoice;

/**
 * Builds a minimal FA(2) invoice XML for KSeF.
 *
 * This covers the fields the panel holds: seller (operator NIP), buyer (from
 * the invoice's buyer snapshot), line items with VAT and the totals. The FA(2)
 * schema is far larger than a hosting invoice needs; the operator's taxpayer
 * data that is not stored here (bank account, legal form, etc.) would need to
 * be added before production use.
 */
class InvoiceXmlBuilder
{
    /**
     * @return string FA(2) XML document
     */
    public function build(Invoice $invoice, string $sellerNip): string
    {
        $invoice = $invoice->load('items');
        $buyerNip = $invoice->buyer('tax_id') ?: null;
        $issueDate = ($invoice->date ?? now())->format('Y-m-d');
        $dueDate = ($invoice->due_date ?? now())->format('Y-m-d');

        $lines = '';
        $number = 1;
        $netTotal = 0.0;
        $taxTotal = 0.0;

        foreach ($invoice->items as $item) {
            $qty = max(1, (int) ($item->qty ?? 1));
            $net = round((float) $item->amount * $qty, 2);
            $rate = $item->tax_rate !== null ? (float) $item->tax_rate : ($item->taxed ? (float) $invoice->tax_rate : 0.0);
            $vat = round($net * $rate / 100, 2);
            $netTotal += $net;
            $taxTotal += $vat;

            $lines .= $this->line($number, (string) ($item->description ?? ''), $qty, (float) $item->amount, $net, $rate, $vat);
            $number++;
        }

        $gross = round($netTotal + $taxTotal, 2);

        return $this->document(
            $issueDate,
            $dueDate,
            $sellerNip,
            $invoice->buyer('company_name'),
            $invoice->buyer('first_name').' '.$invoice->buyer('last_name'),
            $buyerNip,
            $invoice->buyer('address1'),
            $invoice->buyer('city'),
            $invoice->buyer('postcode'),
            $invoice->buyer('country'),
            $lines,
            round($netTotal, 2),
            round($taxTotal, 2),
            $gross,
            $invoice->invoice_num ?? (string) $invoice->id,
        );
    }

    protected function line(int $n, string $name, int $qty, float $unitNet, float $net, float $rate, float $vat): string
    {
        $netStr = number_format($net, 2, '.', '');
        $vatStr = number_format($vat, 2, '.', '');
        $unitStr = number_format($unitNet, 2, '.', '');
        $rateStr = number_format($rate, 2, '.', '');

        return '<FaWiersz>'
            .'<NrWiersza>'.$n.'</NrWiersza>'
            .'<NazwaTowaru>'.$this->x($name).'</NazwaTowaru>'
            .'<Ilosc>'.$qty.'</Ilosc>'
            .'<CenaJednostkowaNetto>'.$unitStr.'</CenaJednostkowaNetto>'
            .'<WartoscNetto>'.$netStr.'</WartoscNetto>'
            .'<StawkaVat>'.$rateStr.'</StawkaVat>'
            .'<KwotaVat>'.$vatStr.'</KwotaVat>'
            .'</FaWiersz>';
    }

    protected function document(
        string $issueDate,
        string $dueDate,
        string $sellerNip,
        ?string $buyerCompany,
        string $buyerName,
        ?string $buyerNip,
        ?string $address,
        ?string $city,
        ?string $postcode,
        ?string $country,
        string $lines,
        float $netTotal,
        float $taxTotal,
        float $gross,
        string $number,
    ): string {
        $buyerId = $buyerNip
            ? '<NrIdentyfikacjiPodatkowej><NIP>'.$this->x($buyerNip).'</NIP></NrIdentyfikacjiPodatkowej>'
            : '<BrakID><PrzyczynaBarkuID>2</PrzyczynaBarkuID></BrakID>';

        $buyerNameTag = $buyerCompany
            ? '<NazwaPelna>'.$this->x($buyerCompany).'</NazwaPelna>'
            : '<Imie>'.$this->x($buyerName).'</Imie>';

        $sellerName = $buyerCompany
            ? ($this->x($sellerNip))
            : '';

        return '<?xml version="1.0" encoding="UTF-8"?>'
            .'<Faktura xmlns="http://crd.gov.pl/wzor/2023/06/29/12648/" kodSystemowy="FA (2)" wersjaSchemy="1-0E">'
            .'<Naglowek>'
            .'<KodFormularza>FA2</KodFormularza>'
            .'<WariantFormularza>2</WariantFormularza>'
            .'<DataWytworzeniaFa>'.$issueDate.'T00:00:00</DataWytworzeniaFa>'
            .'<SystemInfo><DataWytworzeniaFa>'.$issueDate.'T00:00:00</DataWytworzeniaFa>'
            .'<NazwaSystemu>PNLCS</NazwaSystemu></SystemInfo>'
            .'</Naglowek>'
            .'<Podmiot1>'
            .'<DaneIdentyfikacyjne><NIP>'.$this->x($sellerNip).'</NIP></DaneIdentyfikacyjne>'
            .'<NazwaPelna>'.$this->x($sellerName).'</NazwaPelna>'
            .'</Podmiot1>'
            .'<Podmiot2>'
            .'<DaneIdentyfikacyjne>'.$buyerId.'</DaneIdentyfikacyjne>'
            .$buyerNameTag
            .'<Adres>'
            .'<AdresL1>'.$this->x((string) $address).'</AdresL1>'
            .'<Miejscowosc>'.$this->x((string) $city).'</Miejscowosc>'
            .'<KodPocztowy>'.$this->x((string) $postcode).'</KodPocztowy>'
            .'<Kraj>'.$this->x((string) $country).'</Kraj>'
            .'</Adres>'
            .'</Podmiot2>'
            .'<Fa>'
            .'<NrFa>'.$this->x($number).'</NrFa>'
            .'<DataWystawienia>'.$issueDate.'</DataWystawienia>'
            .'<DataSprzedazy>'.$issueDate.'</DataSprzedazy>'
            .'<TerminPlatnosci>'.$dueDate.'</TerminPlatnosci>'
            .$lines
            .'</Fa>'
            .'<FaWartosci>'
            .'<WartoscNetto>'.number_format($netTotal, 2, '.', '').'</WartoscNetto>'
            .'<KwotaVat>'.number_format($taxTotal, 2, '.', '').'</KwotaVat>'
            .'<WartoscBrutto>'.number_format($gross, 2, '.', '').'</WartoscBrutto>'
            .'</FaWartosci>'
            .'</Faktura>';
    }

    protected function x(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, 'UTF-8');
    }
}
