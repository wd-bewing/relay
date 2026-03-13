use relay_crypto::hmac_sha256;
use relay_event_schema::processor::{
    self, ProcessValue, ProcessingResult, ProcessingState, Processor, ValueType,
};
use relay_event_schema::protocol::{AsPair, PairList};

pub fn process_pairlist<P: Processor, T: ProcessValue + AsPair>(
    slf: &mut P,
    value: &mut PairList<T>,
    state: &ProcessingState,
) -> ProcessingResult {
    // View pairlists as objects just for the purpose of PII stripping (e.g. `event.tags.mykey`
    // instead of `event.tags.42.0`). For other purposes such as trimming we would run into
    // problems:
    //
    // * tag keys need to be trimmed too and therefore need to have a path

    for (idx, annotated) in value.iter_mut().enumerate() {
        if let Some(pair) = annotated.value_mut() {
            let (key, value) = pair.as_pair_mut();
            let value_type = ValueType::for_field(value);

            if let Some(key_name) = key.as_str() {
                // if the pair has no key name, we skip over it for PII stripping. It is
                // still processed with index-based path in the invocation of
                // `process_child_values`.
                let entered = state.enter_borrowed(key_name, state.inner_attrs(), value_type);
                processor::process_value(value, slf, &entered)?;
            } else {
                let entered = state.enter_index(idx, state.inner_attrs(), value_type);
                processor::process_value(value, slf, &entered)?;
            }
        }
    }

    Ok(())
}

/// Returns an HMAC-SHA256-based hash of `data` (empty key) as uppercase hex.
/// Uses FIPS-approved HMAC-SHA256; output is 64 hex chars (32 bytes).
pub fn hash_value(data: &[u8]) -> String {
    let mac = hmac_sha256(&[], data);
    hex::encode_upper(mac)
}
