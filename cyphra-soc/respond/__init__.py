"""The respond subsystem — containment actions and playbooks.

The triage layer escalates to respond via :class:`PlaybookDispatcher`,
which pairs an incident's attack ids with the playbook that contains
the right containment sequence.

Two submodules:

* :mod:`respond.actions` — :class:`Action`, the smallest unit of
  containment. Disable user, isolate host, revoke token, quarantine
  email. Idempotent on ``target_key``.
* :mod:`respond.playbooks` — :class:`Playbook`, an ordered list of
  action steps with a failure policy. Three shipped playbooks:
  ``compromise_response``, ``credential_stuffing``, ``ransomware_response``.
"""

from respond.actions import (
    Action,
    ActionResult,
    ActionStatus,
    DisableUserAction,
    IsolateHostAction,
    QuarantineEmailAction,
    RevokeTokenAction,
    get_action,
    list_actions,
    register,
)
from respond.playbooks import (
    CompromiseResponsePlaybook,
    CredentialStuffingPlaybook,
    Playbook,
    PlaybookDispatcher,
    PlaybookResult,
    PlaybookStep,
    RansomwareResponsePlaybook,
    get_playbook,
    list_playbooks,
    register_playbook,
)

__all__ = [
    "Action",
    "ActionResult",
    "ActionStatus",
    "CompromiseResponsePlaybook",
    "CredentialStuffingPlaybook",
    "DisableUserAction",
    "IsolateHostAction",
    "Playbook",
    "PlaybookDispatcher",
    "PlaybookResult",
    "PlaybookStep",
    "QuarantineEmailAction",
    "RansomwareResponsePlaybook",
    "RevokeTokenAction",
    "get_action",
    "get_playbook",
    "list_actions",
    "list_playbooks",
    "register",
    "register_playbook",
]
