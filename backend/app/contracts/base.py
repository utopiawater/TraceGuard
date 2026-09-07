from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    @field_validator("*", mode="after")
    @classmethod
    def require_aware_datetimes(cls, value: Any) -> Any:
        if isinstance(value, datetime) and value.tzinfo is None:
            raise ValueError("datetime values must include an explicit timezone")
        return value

