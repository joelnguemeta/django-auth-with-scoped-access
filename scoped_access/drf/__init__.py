"""DRF glue (optional extra `[drf]`) — SPEC §5 HTTP mapping, §10 /me/access/.

TODO (spec-first: conformance cases for the write guard and the /me/access/
payload must land before implementation):
- ScopedModelPermission (HTTP method → view_/add_/change_/delete_ permission)
- ScopeObjectPermission (object within the caller's scope)
- ScopeQuerySetMixin (list filtering via engine.scope_filter_q)
- assert_within_scope (write guard for perform_create/perform_update)
- MeAccessView (GET /me/access/)
"""
