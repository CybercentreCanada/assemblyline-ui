import concurrent.futures
import json

import elasticapm
from assemblyline.common import forge
from assemblyline.common.dict_utils import flatten
from assemblyline.common.tagging import tag_dict_to_ai_list
from assemblyline.datastore.collection import Index, log
from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline.datastore.helper import JSON_SECTIONS, AssemblylineDatastore
from assemblyline.datastore.store import ESStore


class UIDatastore(AssemblylineDatastore):
    def __init__(self, config = None):
        if not config:
            config = forge.get_config()
        self.config = config

        super().__init__(ESStore(hosts=config.datastore.hosts,
                                 archive_alernate_dtl=config.core.archiver.alternate_dtl))

    @elasticapm.capture_span(span_type='datastore')
    def get_multiple_results(self, keys, cl_engine=forge.get_classification(), as_obj=False, index_type=None):
        results = {k: self.create_empty_result_from_key(k, cl_engine, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        try:
            results.update(self.result.multiget(keys, as_dictionary=True, as_obj=as_obj, index_type=index_type))
        except MultiKeyError as e:
            log.warning(f"Trying to get multiple results but some are missing: {str(e.keys)}")
            results.update(e.partial_output)
        return results

    @elasticapm.capture_span(span_type='datastore')
    def get_single_result(self, key, cl_engine=forge.get_classification(), as_obj=False, index_type=None):
        if key.endswith(".e"):
            data = self.create_empty_result_from_key(key, cl_engine, as_obj=as_obj)
        else:
            data = self.result.get(key, as_obj=as_obj, index_type=index_type)

        return data

    @elasticapm.capture_span(span_type='datastore')
    def list_file_parents(self, sha256, access_control=None, index_type=None):
        query = f"response.extracted.sha256:{sha256}"
        processed_sha256 = []
        output = []

        response = self.result.search(query, fl='id', sort="created desc",
                                      access_control=access_control, as_obj=False, index_type=index_type)
        for p in response['items']:
            key = p['id']
            sha256 = key[:64]
            if sha256 not in processed_sha256:
                output.append(key)
                processed_sha256.append(sha256)

            if len(processed_sha256) >= 10:
                break

        return output


    @elasticapm.capture_span(span_type='datastore')
    def list_file_childrens(self, sha256, access_control=None, index_type=None):
        query = f'sha256:{sha256} AND response.extracted.sha256:*'
        service_resp = self.result.grouped_search("response.service_name", query=query, fl='*',
                                                  sort="created desc", access_control=access_control,
                                                  as_obj=False, index_type=index_type)

        output = []
        processed_sha256 = []
        for r in service_resp['items']:
            for extracted in r['items'][0]['response']['extracted']:
                if extracted['sha256'] not in processed_sha256:
                    processed_sha256.append(extracted['sha256'])
                    output.append({
                        'name': extracted['name'],
                        'sha256': extracted['sha256']
                    })
        return output

    @elasticapm.capture_span(span_type='datastore')
    def get_file_submission_meta(self, sha256, fields, access_control=None, index_type=None):
        query = f"files.sha256:{sha256} OR results:{sha256}.*"
        with concurrent.futures.ThreadPoolExecutor(len(fields)) as executor:
            res = {field: executor.submit(self.submission.facet,
                                          field,
                                          query=query,
                                          access_control=access_control,
                                          index_type=index_type)
                   for field in fields}

        return {k.split(".")[-1]: v.result() for k, v in res.items()}


    @elasticapm.capture_span(span_type='datastore')
    def list_file_active_keys(self, sha256, access_control=None, min_score=None, index_type=None):
        query = f"sha256:{sha256}"
        if min_score:
            query += f" AND result.score:>={min_score}"

        item_list = list(self.result.stream_search(query, fl="id,created,response.service_name,result.score",
                                                          access_control=access_control, as_obj=False,
                                                          index_type=index_type))

        item_list.sort(key=lambda k: k["created"], reverse=True)

        active_found = set()
        active_keys = []
        alternates = []
        for item in item_list:
            if item['response']['service_name'] not in active_found:
                active_keys.append(item['id'])
                active_found.add(item['response']['service_name'])
            else:
                alternates.append(item)

        return active_keys, alternates

    @elasticapm.capture_span(span_type='datastore')
    def get_ai_formatted_file_results_data(self, sha256, user_classification=None, user_access_control=None,
                                           cl_engine=forge.get_classification(),
                                           index_type=None):
        # Get the submission data
        file_obj = self.file.get(sha256, index_type=index_type)
        if not file_obj or (user_classification and not cl_engine.is_accessible(
                user_c12n=user_classification, c12n=file_obj.classification.value)):
            return None

        # Check for the max service score
        items = self.result.search(f"sha256:{sha256}", fl="result.score", access_control=user_access_control,
                                   as_obj=False, rows=1, sort="result.score desc", index_type=index_type)['items']
        if items:
            max_score = items[0]['result']['score']
        else:
            max_score = 0

        # Auto adjust min_score
        if max_score < 0:
            min_score = -1000000
        else:
            min_score = 300

        # Get the list of active result keys
        active_keys, _ = self.list_file_active_keys(
            sha256, user_access_control, min_score=min_score, index_type=index_type)

        # Parse results
        results = [
            self._fix_section_data(r.as_primitives(strip_non_ai_fields=True, strip_null=True), min_score)
            for r in self.result.multiget(active_keys, as_dictionary=False,
                                          error_on_missing=False, index_type=index_type)
            if min_score <= r.result.score and (not user_classification or cl_engine.is_accessible(
                user_c12n=user_classification, c12n=r.classification.value))]

        # Create output
        output = file_obj.as_primitives(strip_non_ai_fields=True, strip_null=True)
        output['verdict'] = self._get_verdict_from_score(max_score)
        output['results'] = results
        return output

    @elasticapm.capture_span(span_type='datastore')
    def get_ai_formatted_submission_data(self, sid, user_classification=None,
                                         cl_engine=forge.get_classification(),
                                         index_type=None):
        # Get the submission data
        submission = self.submission.get(sid, index_type=index_type)
        if not submission or (user_classification and not cl_engine.is_accessible(
                user_c12n=user_classification, c12n=submission.classification.value)):
            return None

        # Auto adjust min_score
        if submission.max_score < 0:
            min_score = -1000000
        else:
            min_score = 300

        # Check where the submission is from to determine the appropriate index type to fetch related results
        if not submission.get('from_archive', False):
            index_type = Index.HOT
        else:
            index_type = Index.ARCHIVE

        # Parse results
        results = [
            self._fix_section_data(r.as_primitives(strip_non_ai_fields=True, strip_null=True), min_score)
            for r in self.result.multiget(
                submission.results, as_dictionary=False, error_on_missing=False, index_type=index_type)
            if min_score <= r.result.score and (not user_classification or cl_engine.is_accessible(
                user_c12n=user_classification, c12n=r.classification.value))]

        # Create output
        output = submission.as_primitives(strip_non_ai_fields=True, strip_null=True)
        output['verdict'] = self._get_verdict_from_score(output.pop('max_score', 0))
        output['results'] = results
        return output

    @elasticapm.capture_span(span_type='datastore')
    def _fix_section_data(self, result, min_score):
        new_sections = []
        for section in result['result'].get('sections', []):
            # Skip section with a small score
            if section.get('heuristic', {}).get('score', -1) < min_score:
                continue

            # Rewrite heuristic score as a verdict
            if 'heuristic' in section:
                heur_score = section['heuristic'].pop('score', 0)
                section['heuristic']['verdict'] = self._get_verdict_from_score(heur_score)

            # Loading JSON formatted sections
            body_format = section['body_format']
            section_body = section.get('body')
            if body_format in JSON_SECTIONS and isinstance(section_body, str):
                try:
                    section['body'] = json.loads(section_body)
                except ValueError:
                    pass

            # Changing tags to a list
            section['tags'] = tag_dict_to_ai_list(flatten(section.get('tags', {})))
            if not section['tags']:
                section.pop('tags')

            # Add the section to the new section array
            new_sections.append(section)

        # Update result sections
        result['result']['sections'] = new_sections

        # Rewrite score as verdict
        result_score = result['result'].pop('score', 0)
        result['result']['verdict'] = self._get_verdict_from_score(result_score)

        return result

    def _get_verdict_from_score(self, score):
        if score >= self.config.submission.verdicts.malicious:
            return "malicious"
        elif score >= self.config.submission.verdicts.highly_suspicious:
            return "highly suspicious"
        elif score >= self.config.submission.verdicts.suspicious:
            return "suspicious"
        elif score >= self.config.submission.verdicts.info:
            return "informative"
        else:
            return "safe"
