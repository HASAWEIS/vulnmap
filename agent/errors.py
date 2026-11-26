"""错误码与异常。"""
from __future__ import annotations


class VmError(Exception):
    code = "E_UNKNOWN"

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.message = message
        self.retryable = retryable


class EnvError(VmError):
    code = "E_ENV"


class BuildError(VmError):
    code = "E_BUILD"


class ArgError(VmError):
    code = "E_ARG"


class ReachError(VmError):
    code = "E_REACH"


class FormatError(VmError):
    code = "E_FORMAT"


class NoGain(VmError):
    code = "E_NOGAIN"


class BudgetExhausted(VmError):
    code = "E_BUDGET"


class ContractViolation(VmError):
    code = "E_CONTRACT"
