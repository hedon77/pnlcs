<?php

namespace Modules\Ksef\Http\Admin;

use App\Http\Controllers\Controller;
use App\Models\KsefInvoice;
use Modules\Ksef\KsefService;

class KsefController extends Controller
{
    public function __construct(protected KsefService $service) {}

    /**
     * Re-submit a failed or pending invoice to KSeF.
     */
    public function resend(KsefInvoice $record)
    {
        $record->update(['status' => 'pending', 'error_message' => null]);
        $result = $this->service->send($record);

        return back()->with(
            $result['success'] ? 'success' : 'error',
            $result['message'],
        );
    }

    /**
     * Mark an already-sent invoice as replaced by a correction (korekta).
     *
     * The correction itself is issued as a new invoice from the billing
     * screens; this records that link so the KSeF list shows the original as
     * corrected.
     */
    public function markCorrected(KsefInvoice $record)
    {
        $record->update(['status' => 'corrected']);

        return back()->with('success', __('messages.ksef.marked_corrected'));
    }
}
