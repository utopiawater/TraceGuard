from typing import Dict, Iterable, List

from .base import Detector


class RuleRegistry:
    def __init__(self, rules: Iterable[Detector] = ()) -> None:
        self._rules: Dict[str, Detector] = {}
        for rule in rules:
            self.register(rule)

    def register(self, rule: Detector) -> None:
        if rule.rule_id in self._rules:
            raise ValueError("duplicate rule_id: %s" % rule.rule_id)
        self._rules[rule.rule_id] = rule

    def all(self) -> List[Detector]:
        return list(self._rules.values())

