import datetime
from collections import defaultdict
from functools import cmp_to_key
import json
import os
import re
import statistics

from dotenv import load_dotenv
import requests
from rich import box
from rich.console import Console
from rich.table import Table

load_dotenv()

token = os.environ['GITHUB_TOKEN']
circleci_token = os.environ['CIRCLECI_TOKEN']
org_name = os.environ['GITHUB_ORG']
team_slug = os.environ['GITHUB_TEAM_SLUG']

def submit(query, variables):
    response = requests.post('https://api.github.com/graphql', headers={
            'authorization': 'bearer ' + token,
        },
        data=json.dumps({'query': query, 'variables': variables}),
    )
    if response.status_code != 200 or 'errors' in json.loads(response.content):
        raise Exception(response.text)
    return json.loads(response.text)

def all_pages(query, variables):
    def _merge(dict_1, dict_2):
        # Recursive, but we don't expect crazy heavy nesting level

        list_keys = [key for key in dict_2.keys() if isinstance(dict_2[key], list)]
        merged_lists = {
            key: dict_1.get(key, []) + dict_2[key]
            for key in list_keys
        }

        dict_keys = [key for key in dict_2.keys() if isinstance(dict_2[key], dict)]
        merged_dicts = {
            key: _merge(dict_1.get(key, {}), dict_2[key])
            for key in dict_keys
        }

        return {
            **dict_1,
            **dict_2,
            **merged_lists,
            **merged_dicts,
        }

    def find_matching(struct, key):
        if isinstance(struct, dict):
            for k, v in struct.items():
                if k == key:
                    yield v
                else:
                    yield from find_matching(v, key)

        if isinstance(struct, list):
            for v in struct:
                yield from find_matching(v, key)

    results_all = {}
    page_info ={
        'hasNextPage': True,
        'endCursor': None,
    }

    while page_info['hasNextPage']:
        results_this_page = submit(query, {
            **variables,
            f'after': page_info['endCursor'],
        })
        page_info = list(find_matching(results_this_page, 'pageInfo'))[-1]
        results_all = _merge(results_all, results_this_page)

    return results_all


repos = \
    all_pages('''
        query($org_name: String!, $after: String) {
            organization(login:$org_name) {
                repositories(first: 100, after: $after) {
                    nodes {
                        name
                    }
                    pageInfo {
                      hasNextPage
                      endCursor
                    }
                }
            }
        }
    ''', {'org_name': org_name}
    )['data']['organization']['repositories']['nodes'] if not team_slug else \
    [
        edge['node']
        for edge in all_pages('''
            query($org_name: String!, $team_slug: String!, $after: String) {
                organization(login:$org_name) {
                    team(slug: $team_slug) {
                        repositories(first: 100, after: $after) {
                            edges {
                                node {
                                    name
                                }
                                permission
                            }
                            pageInfo {
                                hasNextPage
                                endCursor
                            }
                        }
                    }
                }
            }
        ''', {'org_name': org_name, 'team_slug': team_slug})['data']['organization']['team']['repositories']['edges']
        if edge['permission'] == 'ADMIN'
    ]

def circleci(method, url):
    has_next_page = True
    items = []
    page_token = None
    while has_next_page:
        response = requests.request(method, url, params={'page-token': page_token} if token else {}, headers={
            'circle-token': circleci_token
        })
        try:
            response.raise_for_status()
        except:
            items += [{'name': 'UNKNOWN - API ERROR'}]
            has_next_page = False
        else:
            response_json = response.json()
            items += response_json.get('items', [])
            page_token = response_json.get('next_page_token')
            has_next_page = page_token is not None

    return items

repos_with_env_vars = [
    (repo, circleci('GET', f'https://circleci.com/api/v2/project/gh/{org_name}/{repo["name"]}/envvar'))
    for repo in repos
]
repos_with_at_least_one_env_var = [
    (repo, env_vars)
    for repo, env_vars in repos_with_env_vars
    if env_vars
]

table = Table(box=box.ASCII, header_style='not bold')
table.add_column("Repository")
table.add_column("Variable")

for repo, env_vars in repos_with_at_least_one_env_var:
    for env_var in env_vars:
        table.add_row(
            f'[link=https://github.com/{org_name}/{repo["name"]}]{repo["name"]}[/link]',
            f'[link=https://app.circleci.com/settings/project/github/{org_name}/{repo["name"]}/environment-variables]{env_var["name"]}[/link]',
            style='bold bright_white',
        )

console = Console()
console.print(table)
