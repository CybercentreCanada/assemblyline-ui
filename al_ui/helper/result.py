import collections
import json

from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification

from al_ui.config import CLASSIFICATION


def recurse_tag_classification_test(data, user_classification, max_classification, min_classification):
    out = {}
    for tag_type, tags in data.items():
        if tags is None:
            continue

        if isinstance(tags, collections.abc.Mapping):
            res, max_classification = recurse_tag_classification_test(tags, user_classification,
                                                                      max_classification, min_classification)
            if res:
                out[tag_type] = res
        else:
            for t in tags:
                if CLASSIFICATION.is_accessible(user_classification, t['classification']):
                    if tag_type not in out:
                        out[tag_type] = []
                    try:
                        t['classification'] = CLASSIFICATION.max_classification(t['classification'], min_classification)
                        max_classification = CLASSIFICATION.max_classification(t['classification'], max_classification)
                    except InvalidClassification:
                        continue
                    out[tag_type].append(t)

    return out, max_classification


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

        # Drop tags user does not have access and set others to at least min classification
        section['tags'], max_classification = recurse_tag_classification_test(section['tags'], user_classification,
                                                                              max_classification, min_classification)

        final_sections.append(section)
    return max_classification, final_sections


# noinspection PyBroadException
def format_result(user_classification, r, min_classification):
    if not CLASSIFICATION.is_accessible(user_classification, min_classification):
        return None

    # Drop sections user does not have access and set others to at least min classification
    max_classification, r['result']['sections'] = filter_sections(r['result']['sections'], user_classification,
                                                                  min_classification)

    # Set result classification to at least min but no more then viewable result classification
    r['classification'] = CLASSIFICATION.max_classification(max_classification, min_classification)

    if len(r['result']['sections']) == 0:
        r['result']['score'] = 0
        r['response']['extracted'] = []

    return r
