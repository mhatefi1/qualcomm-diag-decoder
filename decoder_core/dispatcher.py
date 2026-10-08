"""Generic dispatcher: no individual phone identities or detection logic."""
from decoder_profiles.base import DeviceProfile
from .diag import supported, require, routed_frames


class Dispatcher:
    def __init__(self, profile: DeviceProfile):
        self.profile = profile
        self.adapter = profile.adapter_factory(profile.schemas)

    def frames(self, payload):
        return self.adapter.frames(payload)

    def signal_name(self, log_id):
        return self.profile.signal_names.get(log_id, "Unclassified signal")

    def decode(self, frame, log_id):
        return self.adapter.decode(frame, log_id)


class RoutedSchemaDispatcher:
    """Version/wrapper/length gates shared by declarative routed profiles."""
    def __init__(self, schemas):
        self.routes = {}
        for schema in schemas:
            self.routes.setdefault(schema.log_id, []).append(schema)
        self.peripherals = {schema.router_peripheral for schema in schemas}

    def frames(self, payload):
        return routed_frames(payload, allowed_peripherals=self.peripherals)

    def decode(self, record, log_id):
        if record.failure:
            raise record.failure
        candidates = self.routes.get(log_id, [])
        supported(bool(candidates), "unsupported-log-id or selected-but-unobserved route")
        meta, body = record.metadata, record.body
        for field, attribute, reason in (
            ("wrapper", "wrapper", "unsupported-wrapper"),
            ("router_peripheral", "router_peripheral", "unsupported-router-peripheral"),
            ("record_version", "version", "unsupported-record-version"),
        ):
            candidates = [schema for schema in candidates if meta[field] == getattr(schema, attribute)]
            supported(bool(candidates), reason)
        if meta["wrapper"] == "multi-radio-v1":
            candidates = [schema for schema in candidates if meta.get("radio_id") == schema.radio_id]
            supported(bool(candidates), "unsupported-radio-id for selected schema")
        candidates = [schema for schema in candidates if len(body) in schema.lengths or (
            schema.variable_min is not None and schema.variable_min <= len(body) <= schema.variable_max)]
        require(bool(candidates), "invalid-body-length")
        require(len(candidates) == 1, "ambiguous-schema-declaration")
        schema = candidates[0]
        supported(schema.unsupported_reason is None, schema.unsupported_reason)
        supported(schema.decoder is not None, "unsupported-schema-decoder")
        fields, warnings = schema.decoder(schema, body)
        record.metadata["decode_warnings"] = warnings
        return schema.route_id, fields
