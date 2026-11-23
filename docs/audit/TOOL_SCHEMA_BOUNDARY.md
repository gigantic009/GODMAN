# Tool argument schema boundary

**Status:** Implemented as a deliberately small, strict schema subset; CI verification for the newest commits is pending.

## Boundary behavior

GODMAN validates tool argument schemas at registration, snapshots the schema so callers cannot change the registered definition afterward, and returns defensive copies in model-facing tool definitions. The root must be an object with declared properties, a complete required-property list, and `additionalProperties=false`.

Supported schema types are object, array, string, integer, number and boolean. The subset supports nested properties/items, enum, string length bounds, array item/count bounds and numeric bounds. Unsupported keywords are rejected at registration rather than silently ignored.

Runtime validation enforces declared types (including rejecting booleans where integers/numbers are expected), finite and bounded numeric/integer magnitudes, payload/object/array/string limits, enum type equality and nested constraints. The EventBus and detection engine serialize concurrent publication and processing to keep stateful subscribers and retained findings bounded. This is not a general JSON Schema implementation.

## Design rationale

- Strict unknown-key rejection reduces the risk that a tool definition advertises constraints the local validator does not actually enforce.
- Schema snapshots prevent post-registration changes through the original definition or a model-facing schema export.
- Explicit object-root and required-key constraints keep tool arguments closed and predictable.
- The implementation is GODMAN-specific and uses no schema-validation dependency.

## Tests

The offline tests cover unsupported keywords, strict object closure, property/required mismatch, schema bounds, invalid enum typing, numeric and integer overflow, schema snapshot mutation, nested arrays/item types, and concurrent event publication/detection retention.

## Reference concepts

The implementation independently applies ideas from the JSON Schema documentation on `properties`, `required`, `additionalProperties`, `type`, array `items`, and validation constraints. No external implementation code was copied.

- [JSON Schema object reference](https://json-schema.org/understanding-json-schema/reference/object)
- [JSON Schema validation specification](https://json-schema.org/draft/2020-12/json-schema-validation.html)
