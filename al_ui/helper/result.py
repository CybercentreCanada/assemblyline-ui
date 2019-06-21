from assemblyline.common.classification import InvalidClassification

from al_ui.config import CLASSIFICATION
from assemblyline.common.dict_utils import flatten


def filter_sections(sections, user_classification, min_classification):
    # TODO: Depth analysis should be done before returning sections

    max_classification = min_classification
    temp_sections = [s for s in sections if CLASSIFICATION.is_accessible(user_classification, s['classification'])]
    final_sections = []
    for section in temp_sections:
        try:
            section['classification'] = CLASSIFICATION.max_classification(section['classification'], min_classification)
            max_classification = CLASSIFICATION.max_classification(section['classification'], max_classification)
        except InvalidClassification:
            continue

        section['tags'] = [
            {'type': k,
             'value': t,
             'short_type': k.rsplit(".", 1)[-1]}
            for k, v in flatten(section['tags']).items()
            if v is not None
            for t in v
        ]

        final_sections.append(section)
    return max_classification, final_sections


# noinspection PyBroadException
def format_result(user_classification, r, min_classification):
    if not CLASSIFICATION.is_accessible(user_classification, min_classification):
        return None

    # Drop sections user does not have access and set others to at least min classification
    max_classification, r['result']['sections'] = filter_sections(r['result']['sections'],
                                                                  user_classification, min_classification)

    # Set result classification to at least min but no more then viewable result classification
    r['classification'] = CLASSIFICATION.max_classification(max_classification, min_classification)

    if len(r['result']['sections']) == 0:
        r['result']['score'] = 0
        r['response']['extracted'] = []

    return r
