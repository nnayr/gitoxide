//! Blocking twin of the command-list writer (plan §3.4).

use std::io::Write;

use crate::push::{
    Error, RefUpdate,
    command::{SelectedCaps, command_line},
};

/// Write the command-list pkt-lines to the (binary-mode) request writer.
///
/// The capabilities ride on the **first** command line only, after a NUL, via
/// [`SelectedCaps::to_wire_bytes`]. Binary mode emits each `write_all` as exactly one pkt-line with
/// **no** trailing LF — byte-exact with `git send-pack` (§1.3). The caller writes the terminating
/// flush-pkt (the two exit paths terminate differently, F4).
pub(crate) fn write_command_list<W: Write>(
    w: &mut W,
    updates: &[RefUpdate],
    caps: &SelectedCaps,
) -> Result<(), Error> {
    let zero = gix_hash::ObjectId::null(caps.object_hash).to_hex().to_string();
    for (i, update) in updates.iter().enumerate() {
        let mut line = command_line(update, &zero);
        if i == 0 {
            line.push(0);
            line.extend_from_slice(caps.to_wire_bytes().as_slice());
        }
        w.write_all(&line)?;
    }
    Ok(())
}
