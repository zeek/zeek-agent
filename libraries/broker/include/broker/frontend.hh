#pragma once

namespace broker {

/// Distinguishes the two frontend types.
enum frontend {
  /// A clone of a master data store.  The clone automatically synchronizes to
  /// the master version by receiving updates made to the master and applying
  /// them locally.
  clone,
  /// This type of store is authoritative over its contents. A master directly
  /// applies mutable operations to its backend and then broadcasts the update
  /// to its clones.
  master
};

} // namespace broker
