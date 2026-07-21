#
import concurrent.futures

import elasticapm
from assemblyline.common import forge
from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.datastore.store import ESStore


class UIDatastore(AssemblylineDatastore):
    def __init__(self, config = None):
        if not config:
            config = forge.get_config()

        super().__init__(ESStore(hosts=config.datastore.hosts,
                                 archive_alternate_dtl=config.core.archiver.alternate_dtl))

    @elasticapm.capture_span(span_type='datastore')
    def get_multiple_results(self, keys, cl_engine=forge.get_classification(), as_obj=False, index_type=None):
        results = {k: self.create_empty_result_from_key(k, cl_engine, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        try:
            results.update(self.result.multiget(keys, as_dictionary=True, as_obj=as_obj, index_type=index_type))
        except MultiKeyError as e:
            self.ds.log.warning(f"Trying to get multiple results but some are missing: {str(e.keys)}")
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
        query = f'id:{sha256}* AND response.extracted.sha256:*'
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
        query = f"files.sha256:{sha256} OR results:{sha256}*"
        with concurrent.futures.ThreadPoolExecutor(len(fields)) as executor:
            res = {field: executor.submit(self.submission.facet,
                                          field,
                                          query=query,
                                          access_control=access_control,
                                          index_type=index_type)
                   for field in fields}

        return {k.split(".")[-1]: v.result() for k, v in res.items()}
