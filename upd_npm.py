import os
import json
import requests
import datetime

from mongo import bulk_update
from mongo import get_last_modified
from mongo import set_collection_update


from messages import Messages

MONGO_COLLECTION_NPM = 'npm'

advisories_url = "https://api.nodesecurity.io/advisories"

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

def get_nodesecurity_advisories_json_from_server(api_data):
    # type: (dict) -> bool
    """
    Upload json from nodesecurity.io
    """
    api_data['url'] = advisories_url
    if is_downloadable_as_file(api_data):
        result = download_file(api_data)
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
                    finally:
                        pass
                if os.path.isfile(local_file):
                    os.remove(local_file)
    api_data['source'] = None
    return False

def update_npm_database(args=None):
    data = {}
    data['source'] = None
    if get_nodesecurity_advisories_json_from_server(data):
        vulners = []
        if data['source'] is not None:
            if 'results' in data['source']:
                vulners = data['source']['results']
        last_modified = datetime.datetime.now().isoformat()
        bulk_update(MONGO_COLLECTION_NPM, vulners)
        set_collection_update(MONGO_COLLECTION_NPM, last_modified)


if __name__ == '__main__':
    update_npm_database()