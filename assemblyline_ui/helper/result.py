import json

from assemblyline_ui.config import CLASSIFICATION, HEURISTICS
from assemblyline.common.attack_map import attack_map
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.tagging import tag_dict_to_list


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

        if section['body_format'] == "JSON" and isinstance(section['body'], str):
            try:
                section['body'] = json.loads(section['body'])
            except ValueError:
                pass

        section['tags'] = tag_dict_to_list(section['tags'])
        if section.get('heuristic', False):
            section['heuristic']['name'] = HEURISTICS.get(section['heuristic']['heur_id'], {}).get('name', "UNKNOWN")
            if section['heuristic'].get('attack_id', False):
                attack_id = section['heuristic']['attack_id']
                if attack_id in attack_map:
                    section['heuristic']['attack_pattern'] = attack_map[attack_id]['name']
                else:
                    section['heuristic']['attack_id'] = None

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
