
import json

from assemblyline.common import forge
from assemblyline.common.classification import InvalidClassification

from al_ui.config import CLASSIFICATION


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

        final_sections.append(section)
    return max_classification, final_sections


# noinspection PyBroadException
def format_result(user_classification, r, min_classification):
    if not CLASSIFICATION.is_accessible(user_classification, min_classification):
        return None

    # TODO: is that necessary? Can this be done transparently at the datastore layer?

    try:
        title = r['result']['sections'][0]['title_text']
        if title.startswith('Result exceeded max size.'):
            sha256 = r['response']['supplementary'][-1][1]
            with forge.get_filestore() as transport:
                oversized = json.loads(transport.get(sha256))
            oversized['oversized'] = True
            r = format_result(user_classification, oversized, min_classification)
        
    except Exception:
        pass

    # Drop sections user does not have access and set others to at least min classification
    max_classification, r['result']['sections'] = filter_sections(r['result']['sections'], user_classification,
                                                                  min_classification)

    # Drop tags user does not have access and set others to at least min classification
    temp_tags = [t for t in r['result']['tags']
                 if CLASSIFICATION.is_accessible(user_classification, t['classification'])]
    tags = []
    for tag in temp_tags:
        try:
            tag['classification'] = CLASSIFICATION.max_classification(tag['classification'], min_classification)
            max_classification = CLASSIFICATION.max_classification(tag['classification'], max_classification)
        except InvalidClassification:
            continue
        tags.append(tag)
    r['result']['tags'] = tags

    # Set result classification to at least min but no more then viewable result classification
    r['classification'] = CLASSIFICATION.max_classification(max_classification, min_classification)
    parts = CLASSIFICATION.get_access_control_parts(r['classification'])
    r.update(parts)

    if len(r['result']['sections']) == 0 and len(r['result']['tags']) == 0:
        r['result']['score'] = 0
        r['response']['extracted'] = []

    return r
