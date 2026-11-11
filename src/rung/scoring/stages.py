"""The four rungs of the ladder, described for humans (CLI ``rung stages``, API, dashboard).

The wording follows the stage table in ``docs/architecture.md``, which operationalises the
start-up progression model of Klotins et al. (IEEE TSE 47(3), 2021).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from rung.models import STAGE_ORDER, Stage


class StageInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage: Stage
    title: str
    summary: str
    expectations: list[str]


STAGE_INFO: tuple[StageInfo, ...] = (
    StageInfo(
        stage=Stage.inception,
        title="Inception",
        summary=(
            "From idea to first release. The team is tiny and speed matters more than "
            "process, so only the basics that are cheap now and painful to retrofit are "
            "expected."
        ),
        expectations=[
            "Real version control use",
            "A README",
            "A .gitignore",
            "A dependency manifest",
            "No committed secrets",
        ],
    ),
    StageInfo(
        stage=Stage.stabilization,
        title="Stabilization",
        summary=(
            "The product is released and has to become dependable for its first "
            "customers: changes must be verifiable and builds repeatable."
        ),
        expectations=[
            "Automated tests",
            "CI on every push and pull request",
            "A reproducible build (Dockerfile, lockfile)",
            "A LICENSE",
            "Setup documentation",
            "Readable commit messages",
        ],
    ),
    StageInfo(
        stage=Stage.growth,
        title="Growth",
        summary=(
            "The team and the customer base are scaling, so the process has to scale "
            "with them: work is reviewed, automated and shared across contributors."
        ),
        expectations=[
            "A pull-request / merge workflow",
            "Several contributors",
            "CI that runs tests and lint",
            "Hardened containers",
            "A CONTRIBUTING guide",
            "A changelog or roadmap",
            "CODEOWNERS",
            "Dependency-update automation",
            "Release tags",
        ],
    ),
    StageInfo(
        stage=Stage.maturity,
        title="Maturity",
        summary=(
            "An established product. The focus moves to optimising and governing: "
            "supply-chain hygiene, documented architecture and a sustainable team."
        ),
        expectations=[
            "A SECURITY.md policy",
            "SHA-pinned CI actions",
            "Least-privilege CI tokens",
            "Container healthchecks",
            "Architecture docs or ADRs",
            "A sustained release cadence",
            "Low bus-factor risk",
        ],
    ),
)

if tuple(info.stage for info in STAGE_INFO) != STAGE_ORDER:  # pragma: no cover
    raise RuntimeError("STAGE_INFO must list every stage in ladder order")
