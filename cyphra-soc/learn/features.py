"""Feature extraction from OCSF events — the input vector for the ML model.

The model consumes a *small fixed-length numeric vector* — not a free-form
OCSF event and not a high-dimensional hash encoding. Feature extraction is
the layer that maps an OCSF event to that vector and is therefore where
every modelling choice is documented:

* Which OCSF fields are read at all?
* How is each non-numeric field encoded?
* What is the feature vocabulary and what is its size?

The vocabulary is fixed at module load time — adding a feature requires
re-training. The vocabulary is small (≪ 100 features) and was chosen for
*coverage* of the ATT&CK techniques the platform cares about, not for
completeness. Adding a feature that is always zero on the training set
teaches the model nothing.

Features fall into three groups:

* **Class priors** — one-hot of the OCSF class. Many attacks are class-
  specific (process creation is suspicious in different ways from sign-in),
  and the model cannot learn "process vs sign-in" from a raw vector.
* **Vendor priors** — one-hot of the vendor / product combination the
  event came from. A Defender alert and an Okta sign-in have different
  prior attack rates regardless of the rest of the event.
* **Booleans** — direct flags from the event: ``is_mfa``, ``is_alert``,
  presence of an actor, presence of a source IP, presence of a public
  principal grant, presence of an ATT&CK technique label.

The feature extractor is deterministic: the same OCSF event produces the
same vector on every call. ``extract_features`` is the public surface;
``feature_names`` is the parallel list of feature names for model
inspection.

A previous version of this module hash-encoded each categorical field into
a 4 096-bucket slice. The vocabulary size grew to 24 000 features while
encoding nothing the model could not learn from a small embedding, and the
training step took minutes instead of seconds. The hash-encoded approach
is wrong here: the categorical fields have small vocabularies (a few dozen
distinct vendor names) and one-hot is exactly the right encoding for a
small fixed vocabulary.
"""

from __future__ import annotations

from typing import Any, Mapping


def _ocsf_classes() -> tuple[str, ...]:
    """The OCSF class names the model treats as priors."""
    return (
        "AUTHENTICATION",
        "API_ACTIVITY",
        "EMAIL_ACTIVITY",
        "NETWORK_ACTIVITY",
        "PROCESS_ACTIVITY",
        "FILE_SYSTEM_ACTIVITY",
        "REGISTRY_KEY_ACTIVITY",
        "REGISTRY_VALUE_ACTIVITY",
        "WINDOWS_SERVICE_ACTIVITY",
        "DNS_ACTIVITY",
        "HTTP_ACTIVITY",
    )


def _vendor_products() -> tuple[str, ...]:
    """The vendor:product tuples the model treats as priors.

    Tuples are read from ``metadata_product_vendor_name`` and
    ``metadata_product_name`` separated by ``:``. The list is hand-picked
    for the sources the platform actually ingests — adding a source
    requires adding its tuple here.
    """
    return (
        "Microsoft:Cloud Audit Logs",
        "Microsoft:Azure Activity Log",
        "Microsoft:Office 365 Management Activity API",
        "Microsoft:Entra ID Sign-in Logs",
        "Microsoft:Windows Security",
        "Microsoft:Sysmon",
        "Microsoft:Defender for Endpoint",
        "Google:Cloud Audit Logs",
        "Google:Google Workspace Audit Reports",
        "Amazon:CloudTrail",
        "Okta:System Log",
        "CrowdStrike:Falcon",
        "Cyphra SOC:Emulation Generator",
    )


def feature_names() -> tuple[str, ...]:
    """The names of every feature the model consumes, in order."""
    parts: list[str] = ["class_is_unseen"]
    parts.extend(f"class:{name}" for name in _ocsf_classes())
    parts.append("vendor:unknown")
    parts.extend(f"vendor:{vp}" for vp in _vendor_products())
    parts.extend(
        (
            "is_mfa",
            "is_alert",
            "actor_present",
            "src_endpoint_present",
            "has_attack_label",
            "public_principal_grant",
            "token_ip_mismatch",
            "tier0_grant",
            "has_user",
            "has_status_failure",
            "has_email_subject",
            "has_resource",
            "has_finding",
            "activity_id_99",
            "activity_id_unset",
            "severity_high",
            "severity_medium",
            "metadata_uid_present",
        )
    )
    return tuple(parts)


_NAME_INDEX: dict[str, int] = {n: i for i, n in enumerate(feature_names())}


def _feature_index(name: str) -> int:
    return _NAME_INDEX[name]


def _class_name(class_uid: int) -> str:
    """A textual class name for the one-hot priors."""
    from core.schema.ocsf import ClassUid

    try:
        return ClassUid(class_uid).name
    except ValueError:
        return ""


def _vendor_product(payload: Mapping[str, Any]) -> str:
    """``f"{vendor}:{product}"`` for the priors, or ``""`` if unknown."""
    vendor = str(payload.get("metadata_product_vendor_name") or "").strip()
    product = str(payload.get("metadata_product_name") or "").strip()
    if not vendor or not product:
        return ""
    return f"{vendor}:{product}"


def _metadata_label_present(payload: Mapping[str, Any], prefix: str) -> bool:
    """True if any label in ``metadata_labels`` starts with ``prefix``."""
    labels = payload.get("metadata_labels")
    if not isinstance(labels, list):
        return False
    return any(isinstance(label, str) and label.startswith(prefix) for label in labels)


def extract_features(payload: Mapping[str, Any]) -> tuple[int, ...]:
    """The model's input vector for one OCSF event.

    Returns a tuple of length ``len(feature_names())`` with integer values
    in ``{0, 1}``. The vector is small (≈ 35 features) and dense; a sparse
    encoding would gain nothing on a vector this size.
    """
    names = feature_names()
    vec = [0] * len(names)
    # Class prior.
    class_name = _class_name(int(payload.get("class_uid", 0)))
    if class_name in _ocsf_classes():
        vec[_feature_index(f"class:{class_name}")] = 1
    else:
        vec[_feature_index("class_is_unseen")] = 1
    # Vendor prior.
    vp = _vendor_product(payload)
    if vp and vp in _vendor_products():
        vec[_feature_index(f"vendor:{vp}")] = 1
    else:
        vec[_feature_index("vendor:unknown")] = 1
    # Direct booleans.
    vec[_feature_index("is_mfa")] = 1 if payload.get("actor_session_is_mfa") else 0
    vec[_feature_index("is_alert")] = 1 if payload.get("is_alert") else 0
    vec[_feature_index("actor_present")] = 1 if payload.get("actor") else 0
    vec[_feature_index("src_endpoint_present")] = 1 if payload.get("src_endpoint_ip") else 0
    vec[_feature_index("has_attack_label")] = (
        1 if _metadata_label_present(payload, "attack:") else 0
    )
    vec[_feature_index("public_principal_grant")] = (
        1 if _metadata_label_present(payload, "gcp:public-principal") else 0
    )
    vec[_feature_index("token_ip_mismatch")] = (
        1 if _metadata_label_present(payload, "token-ip-mismatch") else 0
    )
    vec[_feature_index("tier0_grant")] = (
        1 if _metadata_label_present(payload, "tier0-role") else 0
    )
    vec[_feature_index("has_user")] = 1 if payload.get("user") else 0
    status_id = payload.get("status_id")
    vec[_feature_index("has_status_failure")] = 1 if status_id == 2 else 0
    email = payload.get("email")
    vec[_feature_index("has_email_subject")] = (
        1 if isinstance(email, Mapping) and email.get("subject") else 0
    )
    vec[_feature_index("has_resource")] = 1 if payload.get("resources") else 0
    vec[_feature_index("has_finding")] = 1 if payload.get("finding_info") else 0
    vec[_feature_index("activity_id_99")] = 1 if payload.get("activity_id") == 99 else 0
    vec[_feature_index("activity_id_unset")] = 1 if payload.get("activity_id") is None else 0
    severity_id = payload.get("severity_id") or 0
    vec[_feature_index("severity_high")] = 1 if severity_id >= 4 else 0
    vec[_feature_index("severity_medium")] = 1 if severity_id == 3 else 0
    vec[_feature_index("metadata_uid_present")] = 1 if payload.get("metadata_uid") else 0
    return tuple(vec)


__all__ = ["extract_features", "feature_names"]
