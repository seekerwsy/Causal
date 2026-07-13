from typing import Any, ClassVar, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationError
from pydantic_core import PydanticCustomError


SCHEMA_VERSION = "1.0"


_SafeValidationModel = TypeVar(
    "_SafeValidationModel",
    bound="SafeValidationMixin",
)


def _sanitized_validation_error(
    model_name: str,
    message: str,
    *,
    input_type: Literal["python", "json"] = "python",
) -> ValidationError:
    return ValidationError.from_exception_data(
        model_name,
        [
            {
                "type": PydanticCustomError("safe_validation", message),
                "loc": (),
                "input": None,
            }
        ],
        input_type=input_type,
        hide_input=True,
    )


def model_shape_is_intact(value: BaseModel) -> bool:
    """Reject undeclared or missing state introduced by unsafe Pydantic APIs."""

    try:
        declared_fields = set(type(value).model_fields)
        if set(vars(value)) != declared_fields:
            return False
        if value.__pydantic_extra__:
            return False
        return all(
            not isinstance(nested, BaseModel) or model_shape_is_intact(nested)
            for nested in vars(value).values()
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


class SafeValidationMixin:
    _safe_validation_message: ClassVar[str]

    @classmethod
    def _safe_error(
        cls,
        input_type: Literal["python", "json"] = "python",
    ) -> ValidationError:
        return _sanitized_validation_error(
            cls.__name__,
            cls._safe_validation_message,
            input_type=input_type,
        )

    def __init__(self, /, **data: Any) -> None:
        try:
            super().__init__(**data)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        else:
            return
        data.clear()
        try:
            vars(self).clear()
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        raise type(self)._safe_error()

    def __setattr__(self, name: str, value: object) -> None:
        model_type = type(self)
        try:
            super().__setattr__(name, value)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        else:
            return
        self = None
        name = ""
        value = None
        raise model_type._safe_error()

    @classmethod
    def model_validate(
        cls: type[_SafeValidationModel],
        obj: object,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            if isinstance(obj, BaseModel) and not model_shape_is_intact(obj):
                raise ValueError("unsafe model state")
            return super().model_validate(obj, **kwargs)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        obj = None
        kwargs.clear()
        raise cls._safe_error()

    @classmethod
    def model_validate_json(
        cls: type[_SafeValidationModel],
        json_data: str | bytes | bytearray,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            return super().model_validate_json(json_data, **kwargs)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        json_data = b""
        kwargs.clear()
        raise cls._safe_error("json")

    @classmethod
    def model_validate_strings(
        cls: type[_SafeValidationModel],
        obj: object,
        **kwargs: Any,
    ) -> _SafeValidationModel:
        try:
            kwargs["strict"] = True
            return cls.model_validate(obj, **kwargs)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            pass
        obj = None
        kwargs.clear()
        raise cls._safe_error()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VersionedModel(StrictModel):
    schema_version: Literal["1.0"]
