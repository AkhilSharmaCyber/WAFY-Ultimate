"""Auto-generates short rules from attack payloads for fast future matching."""

auto_rules: list = []
MAX_RULES = 200


def generate_rule(payload: str) -> None:
    if len(payload) > 20:
        rule = payload[:20].strip()
        if rule and rule not in auto_rules:
            auto_rules.append(rule)
            if len(auto_rules) > MAX_RULES:
                auto_rules.pop(0)


def match_auto_rule(payload: str) -> bool:
    return any(rule in payload for rule in auto_rules if rule)
