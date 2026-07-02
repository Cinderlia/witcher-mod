DELETE_KEY_SENTINEL = "__WC_DELETE_KEY_9F3A5C17__"


def is_delete_sentinel(value) -> bool:
    return isinstance(value, str) and value.strip() == DELETE_KEY_SENTINEL
