"""五个阶段：recon / locate / verify / exploit / report。"""
from . import recon, locate, verify, exploit, report  # noqa: F401

STAGE_MODULES = {
    "recon": recon.ReconStage,
    "locate": locate.LocateStage,
    "verify": verify.VerifyStage,
    "exploit": exploit.ExploitStage,
    "report": report.ReportStage,
}
