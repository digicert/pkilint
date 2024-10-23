from typing import List, Sequence, Tuple, NamedTuple

from pkilint.validation import (
    ValidationResult,
    ValidationFinding,
    ValidationFindingDescription,
)


class FindingDescriptionFilter:
    def __init__(self):
        pass

    def filter(
        self,
        result: ValidationResult,
        finding_description: ValidationFindingDescription,
    ) -> bool:
        pass


class ResultWithExcludedFindingDescriptions(NamedTuple):
    result: ValidationResult
    filter_and_finding_descriptions: List[
        Tuple[FindingDescriptionFilter, ValidationFindingDescription]
    ]


class ValidationFindingFilter(FindingDescriptionFilter):
    def __init__(self, validation_finding: ValidationFinding):
        self._validation_finding = validation_finding

        super().__init__()

    def filter(
        self,
        result: ValidationResult,
        finding_description: ValidationFindingDescription,
    ) -> bool:
        return self._validation_finding != finding_description.finding


def filter_results(
    filters: List[FindingDescriptionFilter], results: Sequence[ValidationResult]
) -> Tuple[List[ValidationResult], List[ResultWithExcludedFindingDescriptions]]:
    filtered_results = []
    results_with_exclusions = []

    for result in results:
        included_finding_descriptions = []
        filtered_finding_descriptions = []

        for finding_description in result.finding_descriptions:
            excluding_filter = next(
                (f for f in filters if not f.filter(result, finding_description)), None
            )

            if excluding_filter is None:
                included_finding_descriptions.append(finding_description)
            else:
                filtered_finding_descriptions.append(
                    (
                        excluding_filter,
                        finding_description,
                    )
                )

        if any(filtered_finding_descriptions):
            results_with_exclusions.append(
                ResultWithExcludedFindingDescriptions(
                    ValidationResult(
                        result.validator,
                        result.node,
                        [fafd[1] for fafd in filtered_finding_descriptions],
                    ),
                    filtered_finding_descriptions,
                )
            )

            filtered_results.append(
                ValidationResult(
                    result.validator, result.node, included_finding_descriptions
                )
            )
        else:
            filtered_results.append(result)

    return filtered_results, results_with_exclusions
