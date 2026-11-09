"""Manifest definitions and c2pa settings."""

from __future__ import annotations

import copy
import json
from typing import TYPE_CHECKING, Optional, Sequence

if TYPE_CHECKING:
    from .ai_disclosure import AiDisclosure

CLAIM_GENERATOR_NAME = "SSL Provenance API"
CLAIM_GENERATOR_VERSION = "1.0.0"

#: Label assigned to the parent ingredient captured from a manifest-less asset,
#: and referenced by ``parameters.ingredientIds`` in :data:`MANIFEST_JSON`'s
#: ``c2pa.opened`` action. Keep the two in sync.
OPENED_INGREDIENT_ID = "original-asset"

#: Manifest definition used when the incoming asset does **not** carry a manifest.
#:
#: Instead of declaring a ``c2pa.created`` action, the incoming asset is captured
#: as a ``parentOf`` ingredient (added via ``Builder.add_ingredient_from_stream``,
#: which records the original asset's hash in the ingredient assertion) and a
#: ``c2pa.opened`` action references that ingredient.
#:
#: ``parameters.ingredientIds`` is a temporary linking field: c2pa matches each id
#: against the ingredient's ``label`` and rewrites it to the ingredient
#: assertion's hashed URI in ``parameters.ingredients`` at sign time.
MANIFEST_JSON: dict = {
    "claim_generator_info": [
        {"name": CLAIM_GENERATOR_NAME, "version": CLAIM_GENERATOR_VERSION}
    ],
    "assertions": [
        {
            "label": "c2pa.actions",
            "data": {
                "actions": [
                    {
                        "action": "c2pa.opened",
                        "softwareAgent": {
                            "name": CLAIM_GENERATOR_NAME,
                            "version": CLAIM_GENERATOR_VERSION,
                        },
                        "parameters": {"ingredientIds": [OPENED_INGREDIENT_ID]},
                    }
                ]
            },
            "created": True,
        }
    ],
}

#: Manifest definition used when the incoming asset already carries a manifest.
#:
#: No ``c2pa.created``/``c2pa.opened`` action is declared here: combined with the
#: ``EDIT`` builder intent, c2pa captures the source asset as a parent ingredient
#: (preserving its existing manifest store) and auto-adds a ``c2pa.opened``
#: action tied to that parent.
MANIFEST_JSON_EDIT: dict = {
    "claim_generator_info": [
        {"name": CLAIM_GENERATOR_NAME, "version": CLAIM_GENERATOR_VERSION}
    ],
}


def ai_generated_manifest(ai: "AiDisclosure") -> dict:
    """Manifest definition declaring the asset as AI-generated.

    A single ``c2pa.created`` action with ``digitalSourceType``
    ``trainedAlgorithmicMedia``, the AI tool as ``softwareAgent`` (distinct
    from the claim generator, this SDK) and ``description``, plus
    ``allActionsIncluded: true``. No ingredient goes with it: the asset is the
    AI output itself. Because a ``c2pa.created`` action is present, c2pa adds
    no created/opened action of its own. ``ai`` must have ``when`` resolved
    (:meth:`AiDisclosure.resolved`).
    """
    return {
        "claim_generator_info": [
            {"name": CLAIM_GENERATOR_NAME, "version": CLAIM_GENERATOR_VERSION}
        ],
        "assertions": [
            {
                "label": "c2pa.actions",
                "data": {"actions": [ai.to_action()], "allActionsIncluded": True},
                "created": True,
            }
        ],
    }


def parent_ingredient_json(title: str, format: str) -> dict:
    """JSON definition for the parent ingredient captured from a manifest-less
    asset. The asset bytes (and thus the ingredient's data hash) are supplied
    separately to ``Builder.add_ingredient_from_stream``.

    ``label`` links the ingredient to the ``c2pa.opened`` action's
    ``ingredientIds``.
    """
    return {
        "title": title,
        "format": format,
        "relationship": "parentOf",
        "label": OPENED_INGREDIENT_ID,
    }


def manifest_definition(base: dict, custom_assertions: Sequence[dict]) -> dict:
    """Append caller-supplied assertions to one of this module's manifest
    definitions, returning the definition handed to the c2pa ``Builder``.

    :data:`MANIFEST_JSON_EDIT` declares no ``assertions`` list, so one is created
    when needed. Custom assertions go last, after anything the base declares.
    """
    definition = copy.deepcopy(base)
    if not custom_assertions:
        return definition

    existing = definition.pop("assertions", None)
    assertions = existing if isinstance(existing, list) else []
    assertions.extend(copy.deepcopy(list(custom_assertions)))
    definition["assertions"] = assertions
    return definition


#: Extended key usage (EKU) OIDs accepted in addition to the standard C2PA
#: id-kp-documentSigning OID: MS document signing, Adobe signing, and
#: id-kp-timeStamping.
TRUST_CONFIG_EKUS = "1.3.6.1.4.1.311.10.3.12\n1.2.840.113583.1.1.5\n1.3.6.1.5.5.7.3.8"

#: Auto-generated assertions forced into the claim's ``created_assertions``
#: rather than ``gathered_assertions``. c2pa hardcodes the auto thumbnail and
#: auto actions assertions (and dynamic assertions such as ``cawg.identity``) as
#: gathered unless listed here. Labels are matched against the base label (the
#: ``.vN`` version and ``__N`` instance suffixes are stripped before comparing).
CREATED_ASSERTION_LABELS = (
    "c2pa.thumbnail.claim",
    "c2pa.actions",
    "c2pa.thumbnail.ingredient",
    "c2pa.ingredient",
    "cawg.identity",
)


def build_c2pa_settings(trust_anchors: Optional[str]) -> dict:
    """Build the c2pa settings applied to every signing operation.

    ``trust.trust_anchors``, when present, is the official C2PA trust-list PEM
    bundle supplied by the caller; it lets the edit path validate the
    certificate chains of a manifest already carried by the incoming asset.
    ``trust.trust_config`` admits MS document signing and Adobe signing EKUs.
    ``verify.verify_after_sign`` is disabled so the freshly signed chain is not
    re-checked.
    """
    trust: dict = {"trust_config": TRUST_CONFIG_EKUS}
    if trust_anchors is not None:
        trust["trust_anchors"] = trust_anchors
    return {
        "trust": trust,
        "verify": {"verify_after_sign": False},
        "builder": {"created_assertion_labels": list(CREATED_ASSERTION_LABELS)},
    }


def build_c2pa_settings_json(trust_anchors: Optional[str]) -> str:
    return json.dumps(build_c2pa_settings(trust_anchors))

