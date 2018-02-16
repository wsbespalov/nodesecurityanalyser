import sys
import json
import requests


class NodesecurityAnalizer(object):
    """Analizer for nodesecurity project
    """

    advisories_url = "https://api.nodesecurity.io/advisories"

    @staticmethod
    def is_downloadable_as_file(api_data):
        # type: (dict) -> bool
        """
        Check if file is downloadable from URL.
        """
        url = api_data['url']
        h = requests.head(url, allow_redirects=True)
        header = h.headers
        content_type = header.get('content-type')
        api_data['content_type'] = content_type
        content_length = header.get('content-length', None)
        api_data['content_length'] = content_length
        if content_length is not None:
            print('Content length is {0}'.format(content_length))
        if 'text' in content_type.lower():
            return False
        if 'html' in content_type.lower():
            return False
        return True

    @staticmethod
    def download_file(api_data):
        # type: (dict) -> bool
        """
        Download file from server,
        """
        url = api_data['url']
        local_file_name = url.split('/')[-1] + '.json'
        try:
            upload_result = requests.get(url, allow_redirects=True)
            with open(local_file_name, 'wb') as f:
                for chunk in upload_result.iter_content(chunk_size=1024):
                    f.write(chunk)
            api_data['local_file_name'] = local_file_name
            return True
        except Exception as common_exception:
            print('Get an exception {0}'.format(common_exception))
            api_data['local_file_name'] = None
            return False

    def get_nodesecurity_advisories_json_from_server(self, api_data):
        # type: (dict) -> bool
        """
        Upload json from nodesecurity.io
        """
        api_data['url'] = self.advisories_url
        if self.is_downloadable_as_file(api_data):
            result = self.download_file(api_data)
            local_file = api_data['local_file_name']
            if result:
                if local_file is not None:
                    with open(local_file, 'r') as fp:
                        try:
                            content = json.load(fp)
                            api_data['source'] = content
                            return True
                        except Exception as common_exception:
                            print('JSON parsing exception: {0}'.format(common_exception))
                            api_data['source'] = None
                            return False
        api_data['source'] = None
        return False

    def restructure_data(self, api_data):
        template = {
            "id":None,
            "references":[],
            "vulnerable_configuration":[],
            "vulnerable_configuration_cpe_2_2":[],
            "Published":None,
            "Modified":None,
            "cvss":None,
            "access":{
                "vector":None,
                "complexity":None,
                "authentication":None
            },
            "impact":{
                "confidentiality":None,
                "integrity":None,
                "availability":None
            },
            "cvss-time":None,
            "cwe":None,
            "summary":None
        }
        pass


def main(config):
    # type: (dict) -> None
    """
    Program entry point.
    """
    na = NodesecurityAnalizer()
    data = dict()
    if na.get_nodesecurity_advisories_json_from_server(data):
        print('Download success')

        print('Complete success')
        return 0
    print('Nothing to analyse')
    return 1

if __name__ == "__main__":
    sys.exit(main({}))
