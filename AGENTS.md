# Explorer API agent instructions

## New API administrator access

Before adding any new API endpoint, ask the user whether it may be used by Explorer administrators, Club administrators, or both. Do not infer the allowed audience from an existing endpoint or UI placement. Wait for the user's explicit answer before implementing or exposing the new endpoint, then enforce the approved audience in server-side authorization and tests.
