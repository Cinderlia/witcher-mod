from typing import List


def llm_item_variants(it: dict) -> List[dict]:
    from .llm_var_split import llm_item_variants_by_rules

    return llm_item_variants_by_rules(it)

