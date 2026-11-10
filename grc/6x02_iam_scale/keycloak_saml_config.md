# MedDefense SAML SSO Configuration Reference

## Realm Configuration Summary

The supplied export enables realm `meddefense`, displayed as **MedDefense Health Systems**. `ssoSessionIdleTimeout=1800` means 30 minutes of idle SSO time, not assertion lifetime. Brute-force protection is enabled with `failureFactor=5`; this is the failed-attempt threshold, not evidence of a particular permanent-lockout duration. Realm isolation separates this user/client configuration from other realms.

## Client Configuration Summary

`meddefense-portal` is enabled with protocol `saml`. Its POST assertion consumer service (ACS) is `http://localhost:5000/saml/acs`; redirects allow `http://localhost:5000/*`. Email NameID is forced. `saml.assertion.signature` and `saml.server.signature` are both `true`, expressing intended assertion and document signing. The `MedDefenseRole` mapper copies user attribute `MedDefenseRole` into a SAML attribute of that name using Basic name format. These are local lab addresses, not production HTTPS deployment recommendations.

## Test Users and Role Attributes

| Export username | Email NameID | MedDefenseRole |
| --- | --- | --- |
| d.walsh | d.walsh@meddefense.internal | clinical_staff |
| r.kim | r.kim@meddefense.internal | it_security |

The portal must map these attributes to approved permissions rather than accept arbitrary claimed roles. `r.kim` in the SSO export is not silently equated to `robert.kim` in the directory inventory.

## Annotated SAML Assertion: d.walsh

See [annotated XML](saml_assertion_d_walsh_annotated.xml), copied from the supplied response with explanatory comments. It preserves original values and the simulated signature. The reference example for r.kim differs in subject and role, not destination or validity window.

## Assertion Expiration and Replay Prevention

Conditions permit use from 2026-04-28 09:14:55 UTC until, but excluding, 09:20:00 UTC. Subject confirmation also expires at 09:20:00 and identifies the ACS recipient. The service provider checks issuer, audience `meddefense-portal`, recipient, time and signature before using the subject or attributes. Expired assertions must be rejected. Time limits reduce the replay window but do not prevent reuse within it: a production implementation also needs replay tracking of assertion IDs and request correlation. No such implementation or live replay test is supplied.

## Assertion Signing Risk Explanation

If accepted without a valid trusted signature, an altered subject or role could grant unauthorized access. Signing configuration alone does not prove validation works. The supplied XML contains a simulated SignatureValue, a signature reference to the assertion and no complete verifiable production signature; it does not demonstrate both document and assertion signing in operation. Comments in the annotated copy are educational and are not a new signed artifact.

## Off-Boarding and Centralized Identity Impact

SSO lets the portal trust an identity provider's assertion instead of receiving the user's password from it. Disabling the IdP identity prevents new authentication through connected federation paths, reducing separate account-removal work. Existing application sessions, local fallback accounts and disconnected systems still need termination or deprovisioning controls. The provided artifacts demonstrate a configuration reference, not a deployed MedDefense SSO service.

## Sources

All five supplied files in [sso](../opt/meddefense/materials/sso/) support this analysis: `keycloak_realm_export_meddefense.json`, `saml_assertion_d_walsh.xml`, `saml_assertion_r_kim.xml`, `saml_flow_notes.md`, `decoded_saml_response_reference.md`.
