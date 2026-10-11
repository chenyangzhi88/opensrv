// Copyright 2021 Datafuse Labs.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::myc::constants::ColumnType;
use crate::{ErrorKind, StatementData, Value};
use std::collections::HashMap;
use std::io;
use std::sync::Arc;

/// Actual retained allocation owner supplied by the backend. This does not
/// cover the protocol's existing receive/decompression buffers.
pub trait CommandAllocationLease: Send + Sync {}
impl<T: Send + Sync> CommandAllocationLease for T {}
pub type CommandAllocation = Arc<dyn CommandAllocationLease>;
pub type CommandAllocationAdmission =
    Arc<dyn Fn(usize) -> io::Result<CommandAllocation> + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindErrorPhase {
    Framing,
    StatementCount,
    PlaceholderType,
    Admission,
}
#[derive(Debug)]
pub struct BindError {
    pub phase: BindErrorPhase,
    cause: io::Error,
}
impl BindError {
    pub fn error_kind(&self) -> Option<ErrorKind> {
        match self.phase {
            BindErrorPhase::Framing => Some(ErrorKind::ER_MALFORMED_PACKET),
            BindErrorPhase::StatementCount | BindErrorPhase::PlaceholderType => {
                Some(ErrorKind::ER_WRONG_ARGUMENTS)
            }
            BindErrorPhase::Admission => None,
        }
    }
    pub fn message(&self) -> &'static [u8] {
        match self.phase {
            BindErrorPhase::Framing => b"Malformed communication packet.",
            BindErrorPhase::StatementCount => b"Incorrect arguments to COM_STMT_EXECUTE",
            BindErrorPhase::PlaceholderType => b"Incorrect arguments to mysqld_stmt_execute",
            BindErrorPhase::Admission => b"command allocation admission failed",
        }
    }
    pub fn into_io(self) -> io::Error {
        if self.phase == BindErrorPhase::Admission {
            self.cause
        } else {
            io::Error::new(io::ErrorKind::InvalidData, self)
        }
    }
}
impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.phase, self.cause)
    }
}
impl std::error::Error for BindError {}
fn error(phase: BindErrorPhase, message: &'static str) -> BindError {
    BindError {
        phase,
        cause: io::Error::new(io::ErrorKind::InvalidData, message),
    }
}

/// One raw slot in packet order. Length prefixes are excluded. Names, temporal
/// displacement, complete fifteen-bit type code and signedness remain exact.
#[derive(Clone, Copy, Debug)]
pub struct RawParamValue<'a> {
    pub name: Option<&'a [u8]>,
    pub type_code: u16,
    pub unsigned: bool,
    pub is_null: bool,
    pub raw_value: &'a [u8],
    pub is_long_data: bool,
}
/// First P slots bind placeholders; an installed service can see all N slots,
/// including named placeholders. The permit lives with this actual collection.
pub struct ParsedBindings<'a> {
    slots: Vec<RawParamValue<'a>>,
    placeholder_count: u16,
    has_new_types: bool,
    query_attributes: bool,
    execute_flags: u8,
    suffix: &'a [u8],
    packet_owner: Option<bytes::Bytes>,
    long_data: Option<&'a HashMap<u16, Vec<u8>>>,
    bound_types: Option<&'a mut Vec<(u16, bool)>>,
    type_allocation: Option<&'a mut Option<CommandAllocation>>,
    admission: Option<CommandAllocationAdmission>,
    _allocation: Option<CommandAllocation>,
}
impl ParsedBindings<'_> {
    pub fn slots(&self) -> &[RawParamValue<'_>] {
        &self.slots
    }
    pub fn placeholder_count(&self) -> u16 {
        self.placeholder_count
    }
    pub fn has_new_types(&self) -> bool {
        self.has_new_types
    }
    pub fn query_attributes(&self) -> bool {
        self.query_attributes
    }
    pub fn execute_flags(&self) -> u8 {
        self.execute_flags
    }
    pub fn has_named_values(&self) -> bool {
        self.slots.iter().any(|slot| slot.name.is_some())
    }
}
impl<'a> ParsedBindings<'a> {
    pub fn suffix(&self) -> &'a [u8] {
        self.suffix
    }
    /// The dispatch-issued owner of this actual command-body allocation.
    /// Direct borrowed parsing has none. A downstream immutable command may
    /// clone this owner and retain checked ranges without copying/reparsing.
    pub fn packet_owner(&self) -> Option<&bytes::Bytes> {
        self.packet_owner.as_ref()
    }
    /// Long-data state is a different actual owner and has no packet range.
    pub fn packet_range(&self, value: &[u8]) -> Option<std::ops::Range<usize>> {
        let owner = self.packet_owner.as_ref()?;
        let start = (value.as_ptr() as usize).checked_sub(owner.as_ptr() as usize)?;
        let end = start.checked_add(value.len())?;
        (end <= owner.len()).then_some(start..end)
    }
    pub(crate) fn retain_packet(&mut self, owner: bytes::Bytes) {
        self.packet_owner = Some(owner);
    }
    /// Separate native placeholder source-type phase. Attribute metadata is
    /// never saved in StatementData. A later failure retains earlier setters.
    pub fn bind_placeholders(&mut self) -> Result<BoundParameters<'a>, BindError> {
        let count = usize::from(self.placeholder_count);
        let bytes = count
            .checked_mul(std::mem::size_of::<ParamValue<'_>>())
            .ok_or_else(|| error(BindErrorPhase::Admission, "placeholder capacity overflow"))?;
        let allocation = admit(&self.admission, bytes)?;
        let mut values = Vec::new();
        values.try_reserve_exact(count).map_err(allocation_error)?;
        if self.has_new_types && count > 0 {
            let bytes = count
                .checked_mul(std::mem::size_of::<(u16, bool)>())
                .ok_or_else(|| error(BindErrorPhase::Admission, "source type capacity overflow"))?;
            let lease = admit(&self.admission, bytes)?;
            let types = self
                .bound_types
                .as_deref_mut()
                .ok_or_else(|| error(BindErrorPhase::PlaceholderType, "missing statement"))?;
            if types.len() != count {
                types
                    .try_reserve_exact(count.saturating_sub(types.len()))
                    .map_err(allocation_error)?;
                types.resize(count, (243, false)); // MYSQL_TYPE_INVALID
            }
            if let Some(owner) = self.type_allocation.as_deref_mut() {
                *owner = lease;
            }
        }
        for (ordinal, slot) in self.slots.iter().take(count).enumerate() {
            if self.has_new_types {
                let types = self
                    .bound_types
                    .as_deref_mut()
                    .ok_or_else(|| error(BindErrorPhase::PlaceholderType, "missing statement"))?;
                types[ordinal] = if valid_placeholder_type(slot.type_code) {
                    (slot.type_code, slot.unsigned)
                } else {
                    (243, false)
                };
            }
            let types = self
                .bound_types
                .as_deref()
                .ok_or_else(|| error(BindErrorPhase::PlaceholderType, "missing statement"))?;
            let (code, unsigned) = types.get(ordinal).copied().unwrap_or((243, false));
            if self.has_new_types && !valid_placeholder_type(code) {
                return Err(error(
                    BindErrorPhase::PlaceholderType,
                    "invalid placeholder type",
                ));
            }
            if !slot.is_null && (!valid_placeholder_type(code) || matches!(code, 6 | 9)) {
                // Native source admission accepts NULL/INT24, but its actual
                // non-NULL setter has no value case; NO_VALUE fails 1210.
                return Err(error(
                    BindErrorPhase::PlaceholderType,
                    "parameter has no actual value",
                ));
            }
            let coltype = u8::try_from(code)
                .ok()
                .and_then(|code| ColumnType::try_from(code).ok())
                .ok_or_else(|| {
                    error(BindErrorPhase::PlaceholderType, "invalid placeholder type")
                })?;
            // The framing phase short-circuits NULL first. The subsequent
            // native Item setter instead honors the actual LONG_DATA_VALUE
            // state before the packet NULL bit, using the same statement.
            let long_data = self.long_data.and_then(|data| data.get(&(ordinal as u16)));
            if long_data.is_some() && !(249..=254).contains(&code) {
                return Err(error(
                    BindErrorPhase::PlaceholderType,
                    "invalid long-data source type",
                ));
            }
            let value = if let Some(data) = long_data {
                Value::bytes(data)
            } else if slot.is_null {
                Value::null()
            } else {
                Value::from_parameter_payload(slot.raw_value, coltype, unsigned).map_err(
                    |cause| BindError {
                        phase: BindErrorPhase::PlaceholderType,
                        cause,
                    },
                )?
            };
            values.push(ParamValue {
                value,
                coltype,
                is_long_data: long_data.is_some(),
            });
        }
        Ok(BoundParameters {
            values,
            _allocation: allocation,
        })
    }
}
/// Actual converted placeholder collection and its retained admission permit.
pub struct BoundParameters<'a> {
    values: Vec<ParamValue<'a>>,
    _allocation: Option<CommandAllocation>,
}
impl<'a> std::ops::Deref for BoundParameters<'a> {
    type Target = [ParamValue<'a>];
    fn deref(&self) -> &Self::Target {
        &self.values
    }
}
/// One fallible parser, with explicit QUERY or actual StatementData provenance.
pub struct ParamParser<'a> {
    decoded: Option<ParsedBindings<'a>>,
    params: u16,
    bytes: &'a [u8],
    long_data: Option<&'a HashMap<u16, Vec<u8>>>,
    bound_types: Option<&'a mut Vec<(u16, bool)>>,
    type_allocation: Option<&'a mut Option<CommandAllocation>>,
    named: bool,
    query: bool,
    flags: u8,
    admission: Option<CommandAllocationAdmission>,
}
impl<'a> ParamParser<'a> {
    pub(crate) fn execute(
        input: &'a [u8],
        stmt: &'a mut StatementData,
        named: bool,
        flags: u8,
        admission: Option<CommandAllocationAdmission>,
    ) -> Self {
        Self {
            decoded: None,
            params: stmt.params,
            bytes: input,
            long_data: Some(&stmt.long_data),
            bound_types: Some(&mut stmt.bound_types),
            type_allocation: Some(&mut stmt.type_allocation),
            named,
            query: false,
            flags,
            admission,
        }
    }
    pub fn query(
        input: &'a [u8],
        named: bool,
        admission: Option<CommandAllocationAdmission>,
    ) -> Self {
        Self {
            decoded: None,
            params: 0,
            bytes: input,
            long_data: None,
            bound_types: None,
            type_allocation: None,
            named,
            query: true,
            flags: 0,
            admission,
        }
    }
    pub(crate) fn decoded(bindings: ParsedBindings<'a>) -> Self {
        Self {
            params: bindings.placeholder_count,
            named: bindings.query_attributes,
            flags: bindings.execute_flags,
            decoded: Some(bindings),
            bytes: &[],
            long_data: None,
            bound_types: None,
            type_allocation: None,
            query: false,
            admission: None,
        }
    }
    /// Legacy backend entry; negotiated commands must keep their envelope/lease.
    pub fn parse(self) -> io::Result<Vec<ParamValue<'a>>> {
        if self.named || self.admission.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "negotiated bindings require parse_bindings and its retained owner",
            ));
        }
        let mut parsed = self.parse_bindings().map_err(BindError::into_io)?;
        if parsed.admission.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "admitted bindings require their retained collection owner",
            ));
        }
        parsed
            .bind_placeholders()
            .map(|values| values.values)
            .map_err(BindError::into_io)
    }
    pub fn parse_bindings(mut self) -> Result<ParsedBindings<'a>, BindError> {
        if let Some(bindings) = self.decoded.take() {
            return Ok(bindings);
        }
        let skip = !self.query && self.params == 0 && (!self.named || self.flags & 8 == 0);
        let mut input = self.bytes;
        let count = if skip || (self.query && !self.named) {
            0
        } else if self.named {
            let count = lenenc(&mut input, true)?;
            if self.query && lenenc(&mut input, true)? != 1 {
                return Err(error(
                    BindErrorPhase::Framing,
                    "parameter set count must be one",
                ));
            }
            if count > 65535 {
                return Err(error(
                    BindErrorPhase::Framing,
                    "parameter count exceeds 65535",
                ));
            }
            count as usize
        } else {
            usize::from(self.params)
        };
        let (nullmap, new_types, descriptors, values_input) = if count > 0 {
            let nullmap = take(&mut input, count.div_ceil(8))?;
            let new_types = take(&mut input, 1)?[0] != 0;
            if !new_types && self.query {
                return Err(error(
                    BindErrorPhase::Framing,
                    "query has no reusable source types",
                ));
            }
            let descriptors = input;
            // Same descriptor walker validates bounds without allocation first.
            if new_types {
                for _ in 0..count {
                    descriptor(&mut input, self.named)?;
                }
            }
            (nullmap, new_types, descriptors, input)
        } else {
            (&[][..], false, input, input)
        };
        let layout = SlotLayout {
            count,
            placeholders: self.params,
            named: self.named,
            new_types,
            nullmap,
            descriptors,
            input: values_input,
            long_data: self.long_data,
            types: self.bound_types.as_deref().map(|types| &types[..]),
        };
        // Whole packet framing is checked before any slot allocation/permit.
        layout.walk(|_| {})?;
        if !self.query && count < usize::from(self.params) {
            return Err(error(
                BindErrorPhase::StatementCount,
                "too few statement parameters",
            ));
        }
        if self.named && self.admission.is_none() {
            return Err(BindError {
                phase: BindErrorPhase::Admission,
                cause: io::Error::new(
                    io::ErrorKind::Unsupported,
                    "missing command allocation issuer",
                ),
            });
        }
        let capacity = count
            .checked_mul(std::mem::size_of::<RawParamValue<'_>>())
            .ok_or_else(|| error(BindErrorPhase::Admission, "binding capacity overflow"))?;
        let allocation = admit(&self.admission, capacity)?;
        let mut slots = Vec::new();
        slots.try_reserve_exact(count).map_err(allocation_error)?;
        input = layout.walk(|slot| slots.push(slot))?;
        Ok(ParsedBindings {
            slots,
            placeholder_count: self.params,
            has_new_types: new_types,
            query_attributes: self.named,
            execute_flags: self.flags,
            suffix: input,
            packet_owner: None,
            long_data: self.long_data,
            bound_types: self.bound_types.take(),
            type_allocation: self.type_allocation.take(),
            admission: self.admission,
            _allocation: allocation,
        })
    }
}
pub struct ParamValue<'a> {
    pub value: Value<'a>,
    pub coltype: ColumnType,
    pub is_long_data: bool,
}
/// Borrowed layout only. Validation and construction walk exactly the same
/// descriptors and framing; no alternate decoder or copied temporary map.
struct SlotLayout<'a, 'types> {
    count: usize,
    placeholders: u16,
    named: bool,
    new_types: bool,
    nullmap: &'a [u8],
    descriptors: &'a [u8],
    input: &'a [u8],
    long_data: Option<&'a HashMap<u16, Vec<u8>>>,
    types: Option<&'types [(u16, bool)]>,
}
impl<'a> SlotLayout<'a, '_> {
    fn walk(&self, mut visit: impl FnMut(RawParamValue<'a>)) -> Result<&'a [u8], BindError> {
        let mut descriptors = self.descriptors;
        let mut input = self.input;
        for ordinal in 0..self.count {
            let is_null = self.nullmap[ordinal / 8] & (1 << (ordinal & 7)) != 0;
            let (code, unsigned, name) = if self.new_types {
                descriptor(&mut descriptors, self.named)?
            } else {
                if ordinal >= usize::from(self.placeholders) && !is_null {
                    return Err(error(
                        BindErrorPhase::Framing,
                        "attribute has no reusable source type",
                    ));
                }
                match self.types.and_then(|types| types.get(ordinal)).copied() {
                    Some((code, unsigned)) => (code, unsigned, None),
                    // An actual newly prepared Item_param starts INVALID.
                    // NULL bypasses source lookup; non-NULL still goes
                    // through the native default length framing first.
                    None if ordinal < usize::from(self.placeholders) => (243, false, None),
                    None if is_null => (0, false, None),
                    None => {
                        return Err(error(
                            BindErrorPhase::Framing,
                            "missing reusable source type",
                        ))
                    }
                }
            };
            let data = self.long_data.and_then(|data| {
                (ordinal < usize::from(self.placeholders))
                    .then(|| data.get(&(ordinal as u16)))
                    .flatten()
            });
            let is_long_data = !is_null && data.is_some();
            let raw_value = if is_null {
                &[][..]
            } else {
                if code == 244 {
                    return Err(error(BindErrorPhase::Framing, "unsupported BOOL parameter"));
                }
                if let Some(data) = data {
                    if !(249..=254).contains(&code) {
                        return Err(error(
                            BindErrorPhase::Framing,
                            "invalid long-data source type",
                        ));
                    }
                    &data[..]
                } else {
                    raw_payload(&mut input, code)?
                }
            };
            visit(RawParamValue {
                name,
                type_code: code,
                unsigned,
                is_null,
                raw_value,
                is_long_data,
            });
        }
        Ok(input)
    }
}
fn admit(
    admission: &Option<CommandAllocationAdmission>,
    bytes: usize,
) -> Result<Option<CommandAllocation>, BindError> {
    admission
        .as_ref()
        .map(|admit| {
            admit(bytes).map_err(|cause| BindError {
                phase: BindErrorPhase::Admission,
                cause,
            })
        })
        .transpose()
}
fn allocation_error(cause: std::collections::TryReserveError) -> BindError {
    BindError {
        phase: BindErrorPhase::Admission,
        cause: io::Error::other(cause),
    }
}
fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], BindError> {
    if input.len() < length {
        return Err(error(BindErrorPhase::Framing, "truncated parameter"));
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}
// Fixed 8.0.46 callers use net_field_length for counts/names, and
// get_param_length for values. Both consume FE plus eight bytes but read the
// low uint32. Metadata also accepts FF; value FF is undefined/malformed, and
// value FB means 251 bytes rather than NULL_LENGTH. Do not use the LL helper.
fn lenenc(input: &mut &[u8], metadata: bool) -> Result<u64, BindError> {
    let first = take(input, 1)?[0];
    let size = match first {
        0..=250 => return Ok(u64::from(first)),
        251 => return Ok(if metadata { u64::MAX } else { 251 }),
        252 => 2,
        253 => 3,
        254 => 8,
        255 if metadata => 8,
        _ => return Err(error(BindErrorPhase::Framing, "invalid length prefix")),
    };
    let bytes = take(input, size)?;
    let mut value = [0; 8];
    let width = size.min(4);
    value[..width].copy_from_slice(&bytes[..width]);
    Ok(u64::from_le_bytes(value))
}
fn descriptor<'a>(
    input: &mut &'a [u8],
    named: bool,
) -> Result<(u16, bool, Option<&'a [u8]>), BindError> {
    let bytes = take(input, 2)?;
    let token = u16::from_le_bytes([bytes[0], bytes[1]]);
    let name = if named {
        let length = usize::try_from(lenenc(input, true)?)
            .map_err(|_| error(BindErrorPhase::Framing, "name length overflow"))?;
        let name = take(input, length)?;
        (!name.is_empty()).then_some(name)
    } else {
        None
    };
    Ok((token & 0x7fff, token & 0x8000 != 0, name))
}
fn raw_payload<'a>(input: &mut &'a [u8], code: u16) -> Result<&'a [u8], BindError> {
    let fixed = match code {
        1 => Some(1),
        2 => Some(2),
        3 | 4 => Some(4),
        5 | 8 => Some(8),
        _ => None,
    };
    if let Some(length) = fixed {
        return take(input, length);
    }
    let length = usize::try_from(lenenc(input, false)?)
        .map_err(|_| error(BindErrorPhase::Framing, "value length overflow"))?;
    let strict = matches!(code, 0 | 7 | 10 | 11 | 12 | 246);
    take(
        input,
        if strict {
            length
        } else {
            length.min(input.len())
        },
    )
}
fn valid_placeholder_type(code: u16) -> bool {
    matches!(code, 0..=12 | 15 | 245 | 246 | 249..=254)
}
