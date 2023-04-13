import json
from assemblyline.common.dict_utils import flatten

from assemblyline_ui.config import CLASSIFICATION, LOGGER
from assemblyline.common.classification import InvalidClassification
from assemblyline.common.tagging import tag_dict_to_list


JSON_SECTIONS = ["GRAPH_DATA", "URL", "JSON", "KEY_VALUE", "PROCESS_TREE",
                 "TABLE", "IMAGE", "MULTI", "ORDERED_KEY_VALUE", "TIMELINE"]


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


def cleanup_heuristic_sections(heuristic_sections, ):
    cleaned_sections = {}
    for heur_id, sections in heuristic_sections.items():
        cleaned_sections[heur_id] = [fix_section_data(sec) for sec in sections]
    return cleaned_sections


def fix_section_data(section):
    if section['body_format'] in JSON_SECTIONS and isinstance(section['body'], str):
        # Loading JSON formatted sections
        try:
            section['body'] = json.loads(section['body'])
        except ValueError:
            pass

    # Changing tags to a list
    section['tags'] = tag_dict_to_list(flatten(section['tags']), False)
    section['tags'] += tag_dict_to_list(section.pop('safelisted_tags', {}), True)
    return section


def filter_sections(sections, user_classification, min_classification):
    max_classification = min_classification

    # Filtering section you do not have access to
    temp_sections = [s for s in sections if CLASSIFICATION.is_accessible(user_classification, s['classification'])]
    final_sections = []
    for section in temp_sections:
        try:
            # Recalculation max classification using the currently accessible sections
            section['classification'] = CLASSIFICATION.max_classification(section['classification'], min_classification)
            max_classification = CLASSIFICATION.max_classification(section['classification'], max_classification)
        except InvalidClassification:
            continue

        final_sections.append(fix_section_data(section))

    # Telling the user a section was hidden
    if len(sections) != len(final_sections):
        hidden_section = dict(
            body="One of the sections produced by the service has been removed because you do not have enough "
                 "priviledges to see its results. \n\nContact system administrators for more information.",
            title_text="WARNING: Service sections have been sanitized",
            depth=0,
            classification=CLASSIFICATION.UNRESTRICTED,
            tags=[],
            heuristic=None,
            body_format="TEXT"
        )
        final_sections.insert(0, hidden_section)

    return max_classification, final_sections


# noinspection PyBroadException
def format_result(user_classification, r, min_classification, build_hierarchy=False):
    if not CLASSIFICATION.is_accessible(user_classification, min_classification):
        return None

    # Drop sections user does not have access and set others to at least min classification
    max_classification, r['result']['sections'] = filter_sections(r['result']['sections'], user_classification,
                                                                  min_classification)

    # Drop supplementary and extracted files that the user does not have access to
    for ftype in ['supplementary', 'extracted']:
        r['response'][ftype] = [x for x in r['response'][ftype]
                                if CLASSIFICATION.is_accessible(user_classification, x['classification'])]

    # Set result classification to at least min but no more then viewable result classification
    r['classification'] = CLASSIFICATION.max_classification(max_classification, min_classification)

    if build_hierarchy:
        try:
            section_hierarchy, _ = build_heirarchy_rec(r['result']['sections'])
            r['section_hierarchy'] = section_hierarchy['children']
        except InvalidSectionList:
            LOGGER.warning(f"Could not generate section hierarchy for {r['response']['service_name']} "
                           f"service. Will use old display method.")

    return r
