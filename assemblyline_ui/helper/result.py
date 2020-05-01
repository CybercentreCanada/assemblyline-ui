import json

from assemblyline_ui.config import CLASSIFICATION, LOGGER
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.tagging import tag_dict_to_list


class InvalidSectionList(Exception):
    pass


def build_heirarchy_rec(sections, current_id=0, current_lvl=0, parent=None):
    if parent is None:
        parent = {"id": None, "children": []}

    while True:
        try:
            sec = sections[current_id]
        except IndexError:
            break
        temp = {"id": current_id, "children": []}
        if sec['depth'] == current_lvl:
            prev = temp
            parent['children'].append(temp)
            current_id += 1
        elif sec['depth'] > current_lvl:
            try:
                # noinspection PyUnboundLocalVariable
                _, current_id = build_heirarchy_rec(sections, current_id, current_lvl + 1, prev)
            except UnboundLocalError:
                raise InvalidSectionList("Section list is invalid. Cannot build a tree from it...")
        else:
            break

    return parent, current_id


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

        if section['body_format'] in ["GRAPH_DATA", "URL", "JSON", "KEY_VALUE"] and isinstance(section['body'], str):
            try:
                section['body'] = json.loads(section['body'])
            except ValueError:
                pass

        section['tags'] = tag_dict_to_list(section['tags'])

        final_sections.append(section)

    return max_classification, final_sections


# noinspection PyBroadException
def format_result(user_classification, r, min_classification, build_hierarchy=False):
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
        r['response']['supplementary'] = []

    if build_hierarchy:
        try:
            section_hierarchy, _ = build_heirarchy_rec(r['result']['sections'])
            r['section_hierarchy'] = section_hierarchy['children']
        except InvalidSectionList:
            LOGGER.warning(f"Could not generate section hierarchy for {r['response']['service_name']} "
                           f"service. Will use old display method.")

    return r
