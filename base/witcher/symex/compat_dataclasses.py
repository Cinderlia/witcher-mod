import copy


_MISSING = object()


class _Field:
    __slots__ = ("default", "default_factory")

    def __init__(self, default=_MISSING, default_factory=_MISSING):
        self.default = default
        self.default_factory = default_factory


def field(*, default=_MISSING, default_factory=_MISSING):
    return _Field(default=default, default_factory=default_factory)


def dataclass(_cls=None, *, frozen=False):
    def wrap(cls):
        ann = getattr(cls, "__annotations__", {}) or {}
        names = list(ann.keys())
        fields_map = {}
        defaults = {}
        factories = {}
        for name in names:
            v = getattr(cls, name, _MISSING)
            if isinstance(v, _Field):
                fields_map[name] = v
                if v.default is not _MISSING:
                    defaults[name] = v.default
                if v.default_factory is not _MISSING:
                    factories[name] = v.default_factory
            else:
                if v is not _MISSING:
                    defaults[name] = v
        setattr(cls, "__dataclass_fields__", tuple(names))
        setattr(cls, "__dataclass_frozen__", bool(frozen))

        def __init__(self, *args, **kwargs):
            if len(args) > len(names):
                raise TypeError("too many positional arguments")
            for i, v in enumerate(args):
                kwargs[names[i]] = v
            for name in names:
                if name in kwargs:
                    val = kwargs[name]
                elif name in factories:
                    val = factories[name]()
                elif name in defaults:
                    dv = defaults[name]
                    val = copy.copy(dv)
                else:
                    raise TypeError("missing required argument: " + name)
                object.__setattr__(self, name, val) if frozen else setattr(self, name, val)
            if frozen:
                object.__setattr__(self, "_dataclass_inited", True)

        def __repr__(self):
            parts = []
            for name in names:
                parts.append(name + "=" + repr(getattr(self, name)))
            return cls.__name__ + "(" + ", ".join(parts) + ")"

        def __eq__(self, other):
            if other is self:
                return True
            if other.__class__ is not cls:
                return False
            return all(getattr(self, n) == getattr(other, n) for n in names)

        if frozen:
            def __setattr__(self, k, v):
                if getattr(self, "_dataclass_inited", False) and k in names:
                    raise AttributeError("cannot assign to field '" + str(k) + "'")
                object.__setattr__(self, k, v)
            cls.__setattr__ = __setattr__

        cls.__init__ = __init__
        cls.__repr__ = __repr__
        cls.__eq__ = __eq__
        return cls

    if _cls is None:
        return wrap
    return wrap(_cls)


def asdict(obj):
    if hasattr(obj, "__dataclass_fields__"):
        out = {}
        for name in getattr(obj, "__dataclass_fields__", ()):
            out[name] = asdict(getattr(obj, name))
        return out
    if isinstance(obj, dict):
        return {asdict(k): asdict(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        t = [asdict(x) for x in obj]
        return t if isinstance(obj, list) else tuple(t)
    return obj


def replace(obj, **changes):
    if not hasattr(obj, "__dataclass_fields__"):
        raise TypeError("replace() expects a dataclass-like instance")
    data = {name: getattr(obj, name) for name in getattr(obj, "__dataclass_fields__", ())}
    data.update(changes)
    return obj.__class__(**data)

