"""Declarative bugfinder v3 config: pydantic models, invariants and lookups."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = PACKAGE_DIR / "config.yaml"
DOCS_HOST = "docs.monad.xyz"
ROLE_NAMES = ("principal", "workerSmart", "workerCheap")


def _require_unique(items: list) -> list:
    seen: set = set()
    for item in items:
        if item in seen:
            raise ValueError(f"duplicate entry {item!r}")
        seen.add(item)
    return items


Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")]
NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Repository = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://\S+$")]
PositiveInt = Annotated[int, Field(gt=0)]
ProfileCount = PositiveInt | Literal["all"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
UniqueSlugs = Annotated[list[Slug], Field(min_length=1), AfterValidator(_require_unique)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Workflow(StrictModel):
    id: Literal["bugfinder-v3"]
    retries: Annotated[int, Field(ge=0)]  # per-agent-node retries (pipeline.agent_node)


class Scope(StrictModel):
    include: list[NonEmpty] = Field(default=["**/*"], min_length=1)
    exclude: list[NonEmpty] = Field(default_factory=list)


class Target(StrictModel):
    id: Slug
    repository: Repository
    repositoryUrl: HttpsUrl
    sourceRef: NonEmpty
    historyFile: NonEmpty | None = None
    scope: Scope = Field(default_factory=Scope)


class Provider(StrictModel):
    """Pi provider block; the keys of ``agentflow.specs.ProviderConfig``."""

    name: NonEmpty
    base_url: NonEmpty | None = None
    api_key_env: NonEmpty | None = None
    wire_api: NonEmpty | None = None


class Profile(StrictModel):
    """One harness + model + reasoning tuple; the sandbox follows each phase's ``tools``."""

    harness: Literal["codex", "claude", "pi"]
    model: NonEmpty
    reasoning: Literal["low", "medium", "high", "xhigh", "max", "ultra"]
    provider: Provider | None = None

    @model_validator(mode="after")
    def _provider_only_for_pi(self) -> Profile:
        if self.provider is not None and self.harness != "pi":
            raise ValueError("provider is only supported for the pi harness")
        return self


class PrincipalRole(StrictModel):
    defaultProfile: Slug
    allowedProfiles: UniqueSlugs

    @model_validator(mode="after")
    def _default_is_allowed(self) -> PrincipalRole:
        if self.defaultProfile not in self.allowedProfiles:
            raise ValueError(f"defaultProfile {self.defaultProfile!r} is not in allowedProfiles")
        return self


class WorkerRole(StrictModel):
    profiles: UniqueSlugs


class Roles(StrictModel):
    principal: PrincipalRole
    workerSmart: WorkerRole
    # Reserved for future high-volume phases; no v3 node uses it (Smithers parity).
    workerCheap: WorkerRole | None = None

    @model_validator(mode="after")
    def _workers_disjoint(self) -> Roles:
        if self.workerCheap is None:
            return self
        shared = sorted(set(self.workerSmart.profiles) & set(self.workerCheap.profiles))
        if shared:
            raise ValueError(f"workerSmart and workerCheap must be disjoint; shared: {shared}")
        return self


class Timeouts(StrictModel):
    rankMin: PositiveInt
    huntMin: PositiveInt
    contextWorkerMin: PositiveInt
    synthesisMin: PositiveInt
    goalPlanMin: PositiveInt
    dedupMin: PositiveInt
    gate1Min: PositiveInt
    gate2Min: PositiveInt
    gate3Min: PositiveInt
    reportMin: PositiveInt


class Pools(StrictModel):
    codex: PositiveInt
    claude: PositiveInt
    pi: PositiveInt


class BudgetProfile(StrictModel):
    fileRankThreshold: Annotated[int, Field(ge=1, le=5)]
    huntProfiles: ProfileCount
    replicasPerProfile: PositiveInt
    contextWorkerProfiles: ProfileCount
    maxRoamGoals: Annotated[int, Field(ge=0)]
    triageFindingCap: PositiveInt
    validityProfiles: ProfileCount
    maxItemsPerSlot: PositiveInt
    timeouts: Timeouts
    engineConcurrency: PositiveInt
    pools: Pools
    deadlineHours: PositiveInt | None


class ImpactPhase(StrictModel):
    profile: Slug = "claude-code-fable-5"


class Phases(StrictModel):
    triageImpact: ImpactPhase = Field(default_factory=ImpactPhase)


class GuidanceSource(StrictModel):
    id: Slug
    url: HttpsUrl

    @field_validator("url")
    @classmethod
    def _on_docs_host(cls, value: str) -> str:
        if urlsplit(value).hostname != DOCS_HOST:
            raise ValueError(f"documentation url must be on https://{DOCS_HOST}: {value}")
        return value


class GuidanceSources(StrictModel):
    officialDocumentation: list[GuidanceSource] = Field(min_length=1)


class BountyTerms(StrictModel):
    source: Literal["gist"]
    url: HttpsUrl
    revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    path: NonEmpty
    sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class KnownIssueSources(StrictModel):
    repositories: Annotated[list[Repository], Field(min_length=1), AfterValidator(_require_unique)]


class Routing(StrictModel):
    timeoutDisposition: Literal["INCONCLUSIVE"]
    conflictingEvidenceDisposition: Literal["INCONCLUSIVE"]


class TriagePolicy(StrictModel):
    guidanceSources: GuidanceSources
    bountyTerms: BountyTerms
    pocRequiredForSeverities: Annotated[list[Severity], Field(min_length=1), AfterValidator(_require_unique)]
    knownIssueSources: KnownIssueSources
    referenceClients: Annotated[
        list[Literal["geth", "nethermind"]], Field(min_length=1), AfterValidator(_require_unique)
    ]
    routing: Routing
    prohibitedActions: list[NonEmpty] = Field(min_length=1)


class V3Config(StrictModel):
    schemaVersion: Literal[1]
    workflow: Workflow
    budget: NonEmpty
    budgets: dict[NonEmpty, BudgetProfile] = Field(min_length=1)
    targets: list[Target] = Field(min_length=1)
    profiles: dict[Slug, Profile] = Field(min_length=1)
    roles: Roles
    phases: Phases = Field(default_factory=Phases)
    triagePolicy: TriagePolicy

    @model_validator(mode="after")
    def _invariants(self, info: ValidationInfo) -> V3Config:
        _check_targets(self)
        _check_profile_refs(self)
        _check_budget(self)
        _check_impact_independence(self)
        _check_budget_counts(self)
        _check_bounty_file(self, _base_dir(info))
        return self


def _base_dir(info: ValidationInfo) -> Path:
    context = info.context or {}
    return Path(context.get("base_dir", PACKAGE_DIR))


def _check_targets(config: V3Config) -> None:
    _require_unique([target.id for target in config.targets])
    covered = set(config.triagePolicy.knownIssueSources.repositories)
    for target in config.targets:
        if target.repository not in covered:
            raise ValueError(
                f"knownIssueSources.repositories must cover target repository {target.repository!r}"
            )


def _check_profile_refs(config: V3Config) -> None:
    roles = config.roles
    refs = {
        "roles.principal.defaultProfile": [roles.principal.defaultProfile],
        "roles.principal.allowedProfiles": roles.principal.allowedProfiles,
        "roles.workerSmart.profiles": roles.workerSmart.profiles,
        "roles.workerCheap.profiles": roles.workerCheap.profiles if roles.workerCheap else [],
        "phases.triageImpact.profile": [config.phases.triageImpact.profile],
    }
    for location, profile_ids in refs.items():
        for profile_id in profile_ids:
            if profile_id not in config.profiles:
                raise ValueError(f"{location} references unknown profile {profile_id!r}")


def _check_budget(config: V3Config) -> None:
    if config.budget not in config.budgets:
        raise ValueError(f"budget {config.budget!r} is not defined in budgets {sorted(config.budgets)}")


def _check_impact_independence(config: V3Config) -> None:
    impact_id = config.phases.triageImpact.profile
    if impact_id not in config.roles.principal.allowedProfiles:
        raise ValueError(f"phases.triageImpact.profile {impact_id!r} is not an allowed principal profile")
    impact_model = config.profiles[impact_id].model
    context_model = config.profiles[config.roles.principal.defaultProfile].model
    if impact_model == context_model:
        raise ValueError(f"triageImpact model {impact_model!r} must differ from the principal default model")
    validity = [profile_id for profile_id in config.roles.workerSmart.profiles if profile_id != impact_id]
    if not validity:
        raise ValueError("workerSmart needs a profile other than phases.triageImpact.profile for validity")
    clashes = [profile_id for profile_id in validity if config.profiles[profile_id].model == impact_model]
    if clashes:
        raise ValueError(f"validity profiles {clashes} share the triageImpact model {impact_model!r}")


def validity_profile_ids(config: V3Config) -> list[str]:
    """workerSmart profiles eligible for gate 2: everything but the gate 3 profile.

    ``_check_impact_independence`` guarantees no other workerSmart profile shares
    the impact model, so excluding the profile id is the whole rule.
    """

    impact_id = config.phases.triageImpact.profile
    return [profile_id for profile_id in config.roles.workerSmart.profiles if profile_id != impact_id]


def _check_budget_counts(config: V3Config) -> None:
    """A profile count above the pool it draws from would be truncated silently; reject it."""

    pools = {
        "huntProfiles": len(config.roles.workerSmart.profiles),
        "contextWorkerProfiles": len(config.roles.workerSmart.profiles),
        "validityProfiles": len(validity_profile_ids(config)),
    }
    for name, budget in config.budgets.items():
        for field, available in pools.items():
            count = getattr(budget, field)
            if count != "all" and count > available:
                raise ValueError(f"budgets.{name}.{field}={count} exceeds the {available} eligible workerSmart profiles")


def _check_bounty_file(config: V3Config, base_dir: Path) -> None:
    terms = config.triagePolicy.bountyTerms
    path = base_dir / terms.path
    if not path.is_file():
        raise ValueError(f"bountyTerms.path not found: {path}")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != terms.sha256:
        raise ValueError(f"bountyTerms.sha256 mismatch: file is {digest}, config says {terms.sha256}")


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def load_config(path: Path | None = None) -> V3Config:
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    data = yaml.load(config_path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    return V3Config.model_validate(data, context={"base_dir": config_path.parent})


def resolve_budget(config: V3Config, name: str | None = None) -> BudgetProfile:
    key = config.budget if name is None else name
    if key not in config.budgets:
        raise ValueError(f"unknown budget {key!r}; expected one of {sorted(config.budgets)}")
    return config.budgets[key]


def select_target(config: V3Config, target_id: str) -> Target:
    for target in config.targets:
        if target.id == target_id:
            return target
    raise ValueError(f"unknown target {target_id!r}; expected one of {[t.id for t in config.targets]}")


def profiles_for(
    config: V3Config,
    role: str,
    *,
    exclude: tuple[str, ...] = (),
    only: str | None = None,
) -> list[str]:
    """Profiles a role runs with, in config order.

    ``only`` pins a single profile (it must be allowed for the role); ``exclude``
    removes profile ids. Raises ValueError when nothing is left.
    """
    _check_role(role)
    if role == "principal":
        principal = config.roles.principal
        candidates = [principal.defaultProfile if only is None else only]
        allowed = principal.allowedProfiles
    else:
        worker = getattr(config.roles, role)
        if worker is None:
            raise ValueError(f"role {role} is not configured")
        allowed = worker.profiles
        candidates = list(allowed) if only is None else [only]
    if only is not None and only not in allowed:
        raise ValueError(f"profile {only!r} is not allowed for role {role}")
    selected = [profile_id for profile_id in candidates if profile_id not in exclude]
    if not selected:
        raise ValueError(f"no profiles left for role {role} after excluding {list(exclude)}")
    return selected


def replicas_for(config: V3Config, budget: BudgetProfile, role: str) -> int:
    """Principal is a singleton; worker roles use the budget's replicasPerProfile."""
    _check_role(role)
    return 1 if role == "principal" else budget.replicasPerProfile


def _check_role(role: str) -> None:
    if role not in ROLE_NAMES:
        raise ValueError(f"unknown role {role!r}; expected one of {ROLE_NAMES}")
