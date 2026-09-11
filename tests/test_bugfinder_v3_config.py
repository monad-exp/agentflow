from __future__ import annotations

import copy
import hashlib
import re
import shutil
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml
from pydantic import ValidationError

from examples.bugfinder.v3 import config as config_module, pipeline, prompts, run
from examples.bugfinder.v3.config import (
    DEFAULT_CONFIG_PATH,
    BudgetProfile,
    Phases,
    Profile,
    Provider,
    Roles,
    Target,
    V3Config,
    Workflow,
    load_config,
    profiles_for,
    replicas_for,
    resolve_budget,
    select_target,
    validity_profile_ids,
)

V3_DIR = Path(__file__).resolve().parents[1] / "examples" / "bugfinder" / "v3"
POLICY_SHA256 = "80e8caa5a8c2a0828299b8e9cc0b0a6720fccaa2b852412d606e5fc3c61e2b40"

TIMEOUT_FIELDS = (
    "rankMin",
    "huntMin",
    "contextWorkerMin",
    "synthesisMin",
    "goalPlanMin",
    "dedupMin",
    "gate1Min",
    "gate2Min",
    "gate3Min",
    "reportMin",
)


def budget_row(
    threshold: int,
    hunt: Any,
    replicas: int,
    context: Any,
    roam: int,
    cap: int,
    validity: Any,
    items: int,
    timeouts: str,
    engine: int,
    pools: str,
    deadline: int | None,
) -> dict[str, Any]:
    return {
        "fileRankThreshold": threshold,
        "huntProfiles": hunt,
        "replicasPerProfile": replicas,
        "contextWorkerProfiles": context,
        "maxRoamGoals": roam,
        "triageFindingCap": cap,
        "validityProfiles": validity,
        "maxItemsPerSlot": items,
        "timeouts": dict(zip(TIMEOUT_FIELDS, (int(v) for v in timeouts.split("/")))),
        "engineConcurrency": engine,
        "pools": dict(zip(("codex", "claude", "pi"), (int(v) for v in pools.split("/")))),
        "deadlineHours": deadline,
    }


BUDGET_TABLE = {
    "low": budget_row(5, 2, 1, 2, 0, 8, 2, 256, "30/30/30/20/20/30/15/30/60/20", 8, "4/2/2", 12),
    "medium": budget_row(4, 3, 1, 3, 1, 16, 3, 512, "30/45/45/30/30/45/20/45/120/30", 16, "8/4/4", 48),
    "high": budget_row(
        3, "all", 2, "all", 1, 32, "all", 2048, "30/55/45/30/30/45/20/45/180/30", 24, "12/8/12", None
    ),
}


@pytest.fixture(scope="module")
def raw() -> dict[str, Any]:
    return yaml.safe_load(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def config() -> V3Config:
    return load_config()


def set_path(data: dict[str, Any], dotted: str, value: Any) -> None:
    node: Any = data
    parts = dotted.split(".")
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value


def validate(raw: dict[str, Any], *mutations: Callable[[dict[str, Any]], None]) -> V3Config:
    data = copy.deepcopy(raw)
    for mutate in mutations:
        mutate(data)
    return V3Config.model_validate(data, context={"base_dir": V3_DIR})


def setter(dotted: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda data: set_path(data, dotted, value)


def test_shipped_config_matches_design(config: V3Config):
    assert config.schemaVersion == 1
    assert config.workflow.id == "bugfinder-v3"
    assert config.workflow.retries == 1
    assert config.budget == "medium"
    assert sorted(config.budgets) == ["high", "low", "medium"]

    assert [target.id for target in config.targets] == ["monad", "monad-bft"]
    monad, bft = config.targets
    assert monad.repository == "category-labs/monad"
    assert monad.repositoryUrl == "https://github.com/category-labs/monad"
    assert monad.sourceRef == "main"
    assert bft.sourceRef == "master"
    for target in config.targets:
        assert target.historyFile is None
        assert target.scope.include == ["**/*"]
        assert target.scope.exclude == ["**/*.md", "**/testdata/**", "**/*.lock"]

    assert {name: (p.harness, p.model, p.reasoning) for name, p in config.profiles.items()} == {
        "codex-gpt-5-6-sol": ("codex", "gpt-5.6-sol", "xhigh"),
        "claude-code-fable-5": ("claude", "claude-fable-5", "max"),
        "claude-code-opus-5": ("claude", "claude-opus-5", "max"),
        "pi-glm-5-3": ("pi", "openrouter/z-ai/glm-5.3", "max"),
        "codex-gpt-5-6-luna": ("codex", "gpt-5.6-luna", "medium"),
    }
    pi = config.profiles["pi-glm-5-3"].provider
    assert pi is not None
    assert (pi.name, pi.api_key_env, pi.wire_api) == ("openrouter", "OPENROUTER_API_KEY", "openai-completions")
    assert all(p.provider is None for name, p in config.profiles.items() if name != "pi-glm-5-3")
    assert set(Profile.model_fields) == {"harness", "model", "reasoning", "provider"}
    assert set(Provider.model_fields) == set(pipeline._PROVIDER_KEYS)

    assert config.roles.principal.defaultProfile == "codex-gpt-5-6-sol"
    assert config.roles.principal.allowedProfiles == [
        "codex-gpt-5-6-sol",
        "claude-code-fable-5",
        "claude-code-opus-5",
    ]
    assert config.roles.workerSmart.profiles == [
        "codex-gpt-5-6-sol",
        "claude-code-fable-5",
        "claude-code-opus-5",
        "pi-glm-5-3",
    ]
    assert config.roles.workerCheap is not None and config.roles.workerCheap.profiles == ["codex-gpt-5-6-luna"]
    assert config.phases.triageImpact.profile == "claude-code-fable-5"
    assert validity_profile_ids(config) == ["codex-gpt-5-6-sol", "claude-code-opus-5", "pi-glm-5-3"]

    policy = config.triagePolicy
    assert [doc.id for doc in policy.guidanceSources.officialDocumentation] == [
        "monad-documentation",
        "monad-ethereum-differences",
        "monad-protocol-changelog",
    ]
    assert policy.bountyTerms.source == "gist"
    assert policy.bountyTerms.url == "https://gist.github.com/aviggiano/bbae44300630a2cc9642a7a58ef28fd0"
    assert policy.bountyTerms.revision == "908010ff44cbb1c66a96f0215ddd4f926946421b"
    assert policy.bountyTerms.path == "policy/monad-bounty.md"
    assert policy.pocRequiredForSeverities == ["CRITICAL", "HIGH"]
    assert policy.knownIssueSources.repositories == ["category-labs/monad", "category-labs/monad-bft"]
    assert policy.referenceClients == ["geth", "nethermind"]
    assert policy.routing.timeoutDisposition == "INCONCLUSIVE"
    assert policy.routing.conflictingEvidenceDisposition == "INCONCLUSIVE"
    assert len(policy.prohibitedActions) == 6
    assert all(action.endswith(".") and action.count(". ") == 0 for action in policy.prohibitedActions)


@pytest.mark.parametrize("name", sorted(BUDGET_TABLE))
def test_budget_table(config: V3Config, name: str):
    assert config.budgets[name].model_dump() == BUDGET_TABLE[name]


def test_vendored_policy_hash(config: V3Config):
    path = V3_DIR / config.triagePolicy.bountyTerms.path
    assert hashlib.sha256(path.read_bytes()).hexdigest() == POLICY_SHA256
    assert config.triagePolicy.bountyTerms.sha256 == POLICY_SHA256


def test_resolve_budget(config: V3Config):
    assert resolve_budget(config) is config.budgets["medium"]
    assert resolve_budget(config, "high").deadlineHours is None
    assert isinstance(resolve_budget(config, "low"), BudgetProfile)
    with pytest.raises(ValueError, match="unknown budget 'turbo'"):
        resolve_budget(config, "turbo")


def test_select_target(config: V3Config):
    target = select_target(config, "monad-bft")
    assert isinstance(target, Target)
    assert target.repositoryUrl == "https://github.com/category-labs/monad-bft"
    with pytest.raises(ValueError, match="unknown target 'geth'"):
        select_target(config, "geth")


def test_profiles_for(config: V3Config):
    assert profiles_for(config, "principal") == ["codex-gpt-5-6-sol"]
    assert profiles_for(config, "principal", only="claude-code-fable-5") == ["claude-code-fable-5"]
    assert profiles_for(config, "workerSmart") == config.roles.workerSmart.profiles
    assert profiles_for(config, "workerSmart", exclude=("claude-code-fable-5",)) == [
        "codex-gpt-5-6-sol",
        "claude-code-opus-5",
        "pi-glm-5-3",
    ]
    assert profiles_for(config, "workerSmart", only="pi-glm-5-3") == ["pi-glm-5-3"]
    assert profiles_for(config, "workerCheap") == ["codex-gpt-5-6-luna"]
    with pytest.raises(ValueError, match="not allowed for role principal"):
        profiles_for(config, "principal", only="codex-gpt-5-6-luna")
    with pytest.raises(ValueError, match="not allowed for role workerCheap"):
        profiles_for(config, "workerCheap", only="pi-glm-5-3")
    with pytest.raises(ValueError, match="no profiles left for role workerCheap"):
        profiles_for(config, "workerCheap", exclude=("codex-gpt-5-6-luna",))
    with pytest.raises(ValueError, match="unknown role 'reviewer'"):
        profiles_for(config, "reviewer")


def test_replicas_for(config: V3Config):
    high = resolve_budget(config, "high")
    assert replicas_for(config, high, "principal") == 1
    assert replicas_for(config, high, "workerSmart") == 2
    assert replicas_for(config, high, "workerCheap") == 2
    assert replicas_for(config, resolve_budget(config, "low"), "workerSmart") == 1
    with pytest.raises(ValueError, match="unknown role"):
        replicas_for(config, high, "reviewer")


def test_load_config_from_relocated_copy(tmp_path: Path):
    shutil.copy(DEFAULT_CONFIG_PATH, tmp_path / "config.yaml")
    shutil.copytree(V3_DIR / "policy", tmp_path / "policy")
    assert load_config(tmp_path / "config.yaml").budget == "medium"
    (tmp_path / "policy" / "monad-bounty.md").write_text("tampered", encoding="utf-8")
    with pytest.raises(ValidationError, match="bountyTerms.sha256 mismatch"):
        load_config(tmp_path / "config.yaml")


def test_load_config_rejects_duplicate_keys(tmp_path: Path):
    path = tmp_path / "config.yaml"
    path.write_text("schemaVersion: 1\nbudget: low\nbudget: high\n", encoding="utf-8")
    with pytest.raises(yaml.YAMLError, match="duplicate key 'budget'"):
        load_config(path)


VALID_MUTATIONS: dict[str, tuple[Callable[[dict[str, Any]], None], Callable[[V3Config], Any]]] = {
    "principal default switched to another allowed profile": (
        setter("roles.principal.defaultProfile", "claude-code-opus-5"),
        lambda config: config.roles.principal.defaultProfile == "claude-code-opus-5",
    ),
    "budget default low": (setter("budget", "low"), lambda config: resolve_budget(config).triageFindingCap == 8),
    "threshold lower bound": (
        setter("budgets.low.fileRankThreshold", 1),
        lambda config: config.budgets["low"].fileRankThreshold == 1,
    ),
    "threshold upper bound": (
        setter("budgets.low.fileRankThreshold", 5),
        lambda config: config.budgets["low"].fileRankThreshold == 5,
    ),
    "huntProfiles all": (setter("budgets.low.huntProfiles", "all"), lambda config: config.budgets["low"].huntProfiles == "all"),
    "huntProfiles at the pool size": (
        setter("budgets.low.huntProfiles", 4),
        lambda config: config.budgets["low"].huntProfiles == 4,
    ),
    "contextWorkerProfiles one": (
        setter("budgets.low.contextWorkerProfiles", 1),
        lambda config: config.budgets["low"].contextWorkerProfiles == 1,
    ),
    "validityProfiles all": (
        setter("budgets.low.validityProfiles", "all"),
        lambda config: config.budgets["low"].validityProfiles == "all",
    ),
    "validityProfiles at the eligible pool size": (
        setter("budgets.low.validityProfiles", 3),
        lambda config: config.budgets["low"].validityProfiles == 3,
    ),
    "impact profile with an independent model": (
        setter("phases.triageImpact.profile", "claude-code-opus-5"),
        lambda config: validity_profile_ids(config) == ["codex-gpt-5-6-sol", "claude-code-fable-5", "pi-glm-5-3"],
    ),
    "extra docs url on the docs host": (
        setter("triagePolicy.guidanceSources.officialDocumentation.0.url", "https://docs.monad.xyz/node-ops"),
        lambda config: config.triagePolicy.guidanceSources.officialDocumentation[0].url == "https://docs.monad.xyz/node-ops",
    ),
    "extra known-issue repository": (
        setter(
            "triagePolicy.knownIssueSources.repositories",
            ["category-labs/monad", "category-labs/monad-bft", "monad-crypto/monad-solonet"],
        ),
        lambda config: config.triagePolicy.knownIssueSources.repositories[-1] == "monad-crypto/monad-solonet",
    ),
    "renamed target id": (setter("targets.1.id", "monad-bft-master"), lambda config: select_target(config, "monad-bft-master").repository == "category-labs/monad-bft"),
    "history file": (
        setter("targets.0.historyFile", "file:///srv/history/monad.txt"),
        lambda config: config.targets[0].historyFile == "file:///srv/history/monad.txt",
    ),
    "no deadline": (setter("budgets.low.deadlineHours", None), lambda config: config.budgets["low"].deadlineHours is None),
    "workerCheap omitted": (lambda data: data["roles"].pop("workerCheap"), lambda config: config.roles.workerCheap is None),
}


@pytest.mark.parametrize("mutate,check", VALID_MUTATIONS.values(), ids=list(VALID_MUTATIONS))
def test_valid_mutations_are_accepted(raw: dict[str, Any], mutate: Callable[[dict[str, Any]], None], check: Callable[[V3Config], Any]):
    config = validate(raw, mutate)
    assert isinstance(config, V3Config)
    assert check(config)


def test_unconfigured_worker_cheap_role_is_rejected_by_profiles_for(raw: dict[str, Any]):
    config = validate(raw, lambda data: data["roles"].pop("workerCheap"))
    with pytest.raises(ValueError, match="role workerCheap is not configured"):
        profiles_for(config, "workerCheap")


INVALID_MUTATIONS = {
    "unknown worker profile": (setter("roles.workerCheap.profiles", ["ghost"]), "unknown profile 'ghost'"),
    "unknown principal default": (setter("roles.principal.defaultProfile", "ghost"), "not in allowedProfiles"),
    "unknown impact profile": (
        setter("phases.triageImpact.profile", "ghost"),
        "phases.triageImpact.profile references unknown profile 'ghost'",
    ),
    "principal default not allowed": (
        setter("roles.principal.defaultProfile", "codex-gpt-5-6-luna"),
        "defaultProfile 'codex-gpt-5-6-luna' is not in allowedProfiles",
    ),
    "duplicate allowed profile": (
        setter("roles.principal.allowedProfiles", ["codex-gpt-5-6-sol", "codex-gpt-5-6-sol"]),
        "duplicate entry 'codex-gpt-5-6-sol'",
    ),
    "worker roles overlap": (
        setter("roles.workerCheap.profiles", ["codex-gpt-5-6-luna", "pi-glm-5-3"]),
        "workerSmart and workerCheap must be disjoint",
    ),
    "budget default missing": (setter("budget", "turbo"), "budget 'turbo' is not defined in budgets"),
    "threshold below 1": (setter("budgets.low.fileRankThreshold", 0), "greater than or equal to 1"),
    "threshold above 5": (setter("budgets.low.fileRankThreshold", 6), "less than or equal to 5"),
    "huntProfiles zero": (setter("budgets.low.huntProfiles", 0), "greater than 0"),
    "huntProfiles above the pool": (
        setter("budgets.low.huntProfiles", 5),
        r"budgets.low.huntProfiles=5 exceeds the 4 eligible workerSmart profiles",
    ),
    "contextWorkerProfiles negative": (setter("budgets.low.contextWorkerProfiles", -1), "greater than 0"),
    "contextWorkerProfiles above the pool": (
        setter("budgets.medium.contextWorkerProfiles", 99),
        r"budgets.medium.contextWorkerProfiles=99 exceeds the 4 eligible",
    ),
    "validityProfiles word": (setter("budgets.low.validityProfiles", "some"), "'all'"),
    "validityProfiles above the impact-independent pool": (
        setter("budgets.high.validityProfiles", 4),
        r"budgets.high.validityProfiles=4 exceeds the 3 eligible workerSmart profiles",
    ),
    "profile sandbox knob": (
        setter("profiles.codex-gpt-5-6-sol.sandbox", "workspace-write"),
        "Extra inputs are not permitted",
    ),
    "pi model hint": (
        setter("profiles.pi-glm-5-3.provider.model_context_window", 200000),
        "Extra inputs are not permitted",
    ),
    "replicas zero": (setter("budgets.high.replicasPerProfile", 0), "greater than 0"),
    "roam negative": (setter("budgets.high.maxRoamGoals", -1), "greater than or equal to 0"),
    "deadline zero": (setter("budgets.low.deadlineHours", 0), "greater than 0"),
    "timeout zero": (setter("budgets.low.timeouts.gate3Min", 0), "greater than 0"),
    "pool zero": (setter("budgets.low.pools.pi", 0), "greater than 0"),
    "impact model equals context model": (
        setter("phases.triageImpact.profile", "codex-gpt-5-6-sol"),
        "must differ from the principal default model",
    ),
    "impact profile not principal-allowed": (
        setter("phases.triageImpact.profile", "pi-glm-5-3"),
        "is not an allowed principal profile",
    ),
    "no validity profile left": (
        setter("roles.workerSmart.profiles", ["claude-code-fable-5"]),
        "needs a profile other than phases.triageImpact.profile",
    ),
    "bounty sha mismatch": (setter("triagePolicy.bountyTerms.sha256", "0" * 64), "bountyTerms.sha256 mismatch"),
    "bounty sha malformed": (setter("triagePolicy.bountyTerms.sha256", "abc"), "String should match pattern"),
    "bounty file missing": (
        setter("triagePolicy.bountyTerms.path", "policy/missing.md"),
        "bountyTerms.path not found",
    ),
    "bounty source not gist": (setter("triagePolicy.bountyTerms.source", "github"), "'gist'"),
    "bounty revision short": (
        setter("triagePolicy.bountyTerms.revision", "908010f"),
        "String should match pattern",
    ),
    "docs url http": (
        setter("triagePolicy.guidanceSources.officialDocumentation.0.url", "http://docs.monad.xyz/"),
        "String should match pattern",
    ),
    "docs url other host": (
        setter("triagePolicy.guidanceSources.officialDocumentation.0.url", "https://example.com/docs"),
        "must be on https://docs.monad.xyz",
    ),
    "target repository uncovered": (
        setter("triagePolicy.knownIssueSources.repositories", ["category-labs/monad"]),
        "must cover target repository 'category-labs/monad-bft'",
    ),
    "duplicate target id": (setter("targets.1.id", "monad"), "duplicate entry 'monad'"),
    "target id not a slug": (setter("targets.1.id", "Monad_BFT"), "String should match pattern"),
    "target url http": (
        setter("targets.0.repositoryUrl", "http://github.com/category-labs/monad"),
        "match pattern",
    ),
    "unknown harness": (setter("profiles.codex-gpt-5-6-sol.harness", "opencode"), "'codex', 'claude' or 'pi'"),
    "unknown reasoning": (setter("profiles.codex-gpt-5-6-sol.reasoning", "turbo"), "reasoning"),
    "provider on codex": (
        setter("profiles.codex-gpt-5-6-sol.provider", {"name": "openai"}),
        "provider is only supported for the pi harness",
    ),
    "bad poc severity": (setter("triagePolicy.pocRequiredForSeverities", ["SEVERE"]), "pocRequiredForSeverities"),
    "bad reference client": (setter("triagePolicy.referenceClients", ["besu"]), "'geth' or 'nethermind'"),
    "routing not inconclusive": (setter("triagePolicy.routing.timeoutDisposition", "REJECTED"), "'INCONCLUSIVE'"),
    "schema version": (setter("schemaVersion", 2), "schemaVersion"),
    "extra top-level key": (setter("evidenceEnvironment", "solonet"), "Extra inputs are not permitted"),
    "extra budget key": (setter("budgets.low.heartbeatMin", 10), "Extra inputs are not permitted"),
    "empty include": (setter("targets.0.scope.include", []), "at least 1 item"),
}


@pytest.mark.parametrize("mutate,match", INVALID_MUTATIONS.values(), ids=list(INVALID_MUTATIONS))
def test_invalid_mutations_are_rejected(raw: dict[str, Any], mutate: Callable[[dict[str, Any]], None], match: str):
    with pytest.raises(ValidationError, match=match):
        validate(raw, mutate)


def test_new_profile_can_be_referenced(raw: dict[str, Any]):
    def add_profile(data: dict[str, Any]) -> None:
        data["profiles"]["codex-gpt-5-6-mini"] = {
            "harness": "codex",
            "model": "gpt-5.6-mini",
            "reasoning": "low",
        }
        data["roles"]["workerCheap"]["profiles"].append("codex-gpt-5-6-mini")

    config = validate(raw, add_profile)
    assert profiles_for(config, "workerCheap") == ["codex-gpt-5-6-luna", "codex-gpt-5-6-mini"]


def test_validity_profile_sharing_impact_model_is_rejected(raw: dict[str, Any]):
    def add_twin(data: dict[str, Any]) -> None:
        data["profiles"]["claude-code-fable-5-b"] = dict(data["profiles"]["claude-code-fable-5"])
        data["roles"]["workerSmart"]["profiles"].append("claude-code-fable-5-b")

    match = r"validity profiles \['claude-code-fable-5-b'\] share the triageImpact model"
    with pytest.raises(ValidationError, match=match):
        validate(raw, add_twin)


def test_phases_default_to_fable_reviewer(raw: dict[str, Any]):
    config = validate(raw, lambda data: data.pop("phases"))
    assert config.phases.triageImpact.profile == "claude-code-fable-5"


def test_scope_defaults(raw: dict[str, Any]):
    config = validate(raw, lambda data: data["targets"][0].pop("scope"))
    assert config.targets[0].scope.include == ["**/*"]
    assert config.targets[0].scope.exclude == []


# Fields no builder or validator reads; each is documented as reserved or identity-only in config.yaml/DESIGN.md.
RESERVED_FIELDS = {
    (Roles, "workerCheap"),  # reserved for future high-volume phases (Smithers parity)
    (V3Config, "schemaVersion"),  # Literal[1]: validated, never read
    (Workflow, "id"),  # Literal["bugfinder-v3"]: validated, never read
}


def test_every_config_field_is_consumed_or_reserved():
    """`config.yaml` knobs either drive the graph (or an invariant) or are marked reserved; nothing is silently ignored."""

    consumers = "\n".join(Path(module.__file__).read_text(encoding="utf-8") for module in (pipeline, prompts, run))
    # The config module's functions (after the model definitions) are consumers too; the models themselves are not.
    consumers += Path(config_module.__file__).read_text(encoding="utf-8").split("def _check_targets", 1)[1]
    for model in (V3Config, Workflow, Target, Profile, Provider, Roles, BudgetProfile, Phases):
        for name in model.model_fields:
            if (model, name) in RESERVED_FIELDS:
                continue
            # Attribute access (`budget.huntProfiles`) or a key literal (`_PROVIDER_KEYS`, `getattr(timeouts, "huntMin")`).
            assert re.search(rf"""(\.|["']){re.escape(name)}\b""", consumers), f"{model.__name__}.{name} is neither consumed nor reserved"
    for model, name in RESERVED_FIELDS:
        assert name in model.model_fields
